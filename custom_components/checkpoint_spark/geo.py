"""Offline IP → country lookup for the threat map.

Uses the free "DB-IP Lite Country" database (https://db-ip.com, CC BY 4.0 –
"IP Geolocation by DB-IP"). The CSV is downloaded once a month in the
background and looked up locally – no IP address is ever sent anywhere.
"""

from __future__ import annotations

from array import array
from bisect import bisect_right
from datetime import timedelta
import gzip
import io
import ipaddress
import logging
import os
import socket
import time

from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.util import dt as dt_util

_LOGGER = logging.getLogger(__name__)

URL = "https://download.db-ip.com/free/dbip-country-lite-{month}.csv.gz"
FILE = "checkpoint_spark_dbip_country.csv.gz"
MAX_AGE = timedelta(days=32)
MAX_DOWNLOAD = 64 * 1024 * 1024
ATTRIBUTION = "IP Geolocation by DB-IP (db-ip.com, CC BY 4.0)"


class GeoIP:
    """IPv4 ranges in sorted arrays; lookup by binary search."""

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass
        self.path = hass.config.path(".storage", FILE)
        self._starts = array("I")
        self._ends = array("I")
        self._idx = array("B")          # index into self._codes (compact: 1 byte per range)
        self._codes: list[str] = []
        self.loaded_from: str | None = None
        self._cache: dict[str, str | None] = {}

    @property
    def ready(self) -> bool:
        return bool(self._starts)

    def lookup(self, ip: str | None) -> str | None:
        """Country code (e.g. "AT") or None for private/unknown addresses (cached per IP)."""
        if not ip or not self._starts:
            return None
        if ip in self._cache:
            return self._cache[ip]
        if len(self._cache) > 50_000:
            self._cache.clear()
        cc = self._cache[ip] = self._lookup(ip)
        return cc

    def _lookup(self, ip: str) -> str | None:
        try:
            addr = ipaddress.IPv4Address(str(ip).strip())
        except ValueError:
            return None
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return None
        n = int(addr)
        i = bisect_right(self._starts, n) - 1
        if i >= 0 and n <= self._ends[i]:
            cc = self._codes[self._idx[i]]
            return cc if cc != "ZZ" else None
        return None

    def async_start(self) -> None:
        """Load / download in the background (parsing takes a few seconds – never blocks setup)."""
        self.hass.async_create_background_task(self.async_setup(), "checkpoint_spark geoip")

    async def async_setup(self) -> None:
        """Load the cached file; download when it is missing, unreadable or older than a month."""
        exists = await self.hass.async_add_executor_job(os.path.exists, self.path)
        if exists:
            await self.hass.async_add_executor_job(self._load)
        age = (
            time.time() - (await self.hass.async_add_executor_job(os.path.getmtime, self.path))
            if exists else None
        )
        if age is None or age > MAX_AGE.total_seconds() or not self.ready:
            await self._async_download()

    async def _async_download(self) -> None:
        session = async_get_clientsession(self.hass)
        now = dt_util.now()
        months = [now.strftime("%Y-%m"), (now.replace(day=1) - timedelta(days=1)).strftime("%Y-%m")]
        for month in months:
            url = URL.format(month=month)
            try:
                async with session.get(url, timeout=300) as resp:
                    if resp.status != 200:
                        continue
                    # read the whole body (content.read(n) only returns what is buffered), bounded
                    chunks, size = [], 0
                    async for chunk in resp.content.iter_chunked(65536):
                        size += len(chunk)
                        if size > MAX_DOWNLOAD:
                            break
                        chunks.append(chunk)
                data = b"".join(chunks)
                if size > MAX_DOWNLOAD or data[:2] != b"\x1f\x8b":
                    _LOGGER.warning("GeoIP download from %s rejected (size/format)", url)
                    continue
                if not await self.hass.async_add_executor_job(self._valid, data):
                    _LOGGER.warning("GeoIP download from %s incomplete – not used", url)
                    continue
                await self.hass.async_add_executor_job(self._store, data)
                await self.hass.async_add_executor_job(self._load)
                _LOGGER.info("GeoIP database %s loaded (%d IPv4 ranges)", month, len(self._starts))
                return
            except Exception as err:  # noqa: BLE001 – network problems must not break the integration
                _LOGGER.debug("GeoIP download %s failed: %s", url, err)
        _LOGGER.warning("GeoIP database could not be downloaded; the threat map shows no countries")

    @staticmethod
    def _valid(data: bytes) -> bool:
        """Complete gzip with plausible content (catches truncated downloads)."""
        lines = 0
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:  # streamed – no full copy in memory
                for _ in f:
                    lines += 1
        except (OSError, EOFError):
            return False
        return lines > 100_000

    def _store(self, data: bytes) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, self.path)

    def _load(self) -> None:
        starts, ends, idx = array("I"), array("I"), array("B")
        codes: list[str] = []
        pos: dict[str, int] = {}
        to_int = lambda ip: int.from_bytes(socket.inet_aton(ip), "big")  # noqa: E731
        try:
            with gzip.open(self.path, "rt", encoding="ascii", errors="replace") as f:
                for line in f:
                    a, b, cc = line.rstrip("\n").split(",")[:3]
                    if ":" in a:  # IPv6 – not used (the gateway reports IPv4)
                        continue
                    try:
                        sa, sb = to_int(a), to_int(b)
                    except OSError:
                        continue
                    cc = cc.strip()[:2].upper()
                    if cc not in pos:
                        if len(codes) >= 255:
                            continue
                        pos[cc] = len(codes)
                        codes.append(cc)
                    starts.append(sa)
                    ends.append(sb)
                    idx.append(pos[cc])
        except (OSError, EOFError, ValueError) as err:
            _LOGGER.warning("GeoIP database unreadable: %s", err)
            return
        self._starts, self._ends, self._idx, self._codes = starts, ends, idx, codes
        self._cache = {}
        self.loaded_from = self.path
