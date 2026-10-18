"""Optional syslog receiver (UDP) for the gateway's security logs.

Two ways to feed it:
- directly: the gateway sends syslog to Home Assistant
- via a log server (Synology Log Center, rsyslog, syslog-ng, …) that forwards
  to Home Assistant – add its IP as an additional sender

Hardening (see SECURITY.md): sender allow-list, size and rate limits, bounded
buffers, control characters stripped, values length-limited, no raw messages
persisted, forwarding only of accepted messages and never to ourselves.
"""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime
import logging
import re
import socket
import time
from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .const import DOMAIN, EVENT_THREAT
from .log_analysis import LogAnalyzer

_LOGGER = logging.getLogger(__name__)

BUFFER_SIZE = 200
# per product (Firewall, Anti-Virus, IPS, …) so rare security events are not
# pushed out by frequent firewall drops
PRODUCT_BUFFER_SIZE = 50
MAX_DATAGRAM = 8192          # bytes; longer datagrams are cut before parsing
MAX_PRODUCTS = 50            # distinct ProductName buffers
RATE_LIMIT = 500             # accepted messages per second (token bucket)
MAX_FIELD_LEN = 500
STORE_VERSION = 1
STORE_DELAY = 30             # s, batch writes of detections

# <PRI>, optional RFC 5424 version, then the rest
_PRI = re.compile(r"^<(\d{1,3})>(\d\s)?")
# key="value" or key=value (Check Point log export style); also key:"value"
# a value may be cut off (the gateway truncates long lines) -> unterminated quote at the end
_KV = re.compile(r'([A-Za-z_][\w.-]*)(?:\s*=\s*("(?:[^"\\]|\\.)*(?:"|$)|[^\s;,\]]+)|:("(?:[^"\\]|\\.)*(?:"|$)))')
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def parse_message(raw: str) -> dict[str, Any]:
    """Best-effort split of a syslog line: priority, header and key/value fields."""
    raw = _CTRL.sub(" ", raw[:MAX_DATAGRAM])
    msg: dict[str, Any] = {"raw": raw.strip()}
    if m := _PRI.match(raw):
        pri = int(m.group(1))
        msg["facility"], msg["severity"] = pri >> 3, pri & 7
        raw = raw[m.end():]
    fields: dict[str, str] = {}
    for key, val, quoted in _KV.findall(raw):
        val = val or quoted
        if val.startswith('"'):
            val = val[1:-1] if val.endswith('"') and len(val) > 1 else val[1:]
            val = val.replace('\\"', '"')
        fields[key[:64]] = val[:MAX_FIELD_LEN]
    if fields:
        msg["fields"] = fields
        # header = text before the first key/value pair
        first = _KV.search(raw)
        msg["header"] = (raw[: first.start()] if first else raw).strip()[:200]
    else:
        msg["header"] = raw.strip()[:200]
    return msg


def parse_target(value: str) -> tuple[str, int] | None:
    """'host:port' or 'host' (port 514) -> (host, port); None if invalid/empty."""
    value = (value or "").strip()
    if not value:
        return None
    host, sep, port = value.rpartition(":")
    if not sep:
        host, port = value, "514"
    try:
        port_num = int(port)
    except ValueError:
        return None
    if not host or not 1 <= port_num <= 65535:
        return None
    return host, port_num


def split_hosts(value: str) -> set[str]:
    return {h.strip() for h in str(value or "").replace(";", ",").split(",") if h.strip()}


def _is_local_address(ip: str) -> bool:
    """True if ip belongs to this host (binding to it only works for local addresses)."""
    if ip.startswith("127."):
        return True
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((ip, 0))
    except OSError:
        return False
    finally:
        sock.close()
    return True


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: SyslogReceiver) -> None:
        self._receiver = receiver

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._receiver.handle(data, addr[0])

    def error_received(self, exc: Exception) -> None:
        _LOGGER.debug("Syslog socket error: %s", exc)


class SyslogReceiver:
    """UDP listener; accepts datagrams from the gateway and configured relays only."""

    def __init__(
        self,
        hass: HomeAssistant,
        gateway_host: str,
        port: int,
        entry_id: str = "",
        ignore_sources: set[str] | None = None,
        senders: set[str] | None = None,
        forward: str = "",
        retention_days: int = 90,
    ) -> None:
        self.hass = hass
        self.entry_id = entry_id
        self.analyzer = LogAnalyzer(ignore_sources, retention_days=retention_days)
        self.port = port
        self._hosts = {gateway_host, *(senders or ())}
        self._allowed: set[str] = set()
        self._forward_cfg = parse_target(forward)
        self.forward_addr: tuple[str, int] | None = None
        self._transport: asyncio.DatagramTransport | None = None
        self._fwd_transport: asyncio.DatagramTransport | None = None
        self.messages: deque[dict[str, Any]] = deque(maxlen=BUFFER_SIZE)
        self.by_product: dict[str, deque[dict[str, Any]]] = {}
        self.product_counts: dict[str, int] = {}
        self.received = 0
        self.dropped = 0          # not from an allowed sender
        self.rate_limited = 0
        self.forwarded = 0
        self.last_received: datetime | None = None
        self._listeners: list[Any] = []
        self._tokens = float(RATE_LIMIT)
        self._last_refill = time.monotonic()
        self._store: Store[dict[str, Any]] = Store(
            hass, STORE_VERSION, f"{DOMAIN}.{entry_id}.detections"
        )

    @property
    def allowed(self) -> list[str]:
        return sorted(self._allowed)

    async def _resolve(self, host: str) -> set[str]:
        try:
            infos = await self.hass.loop.getaddrinfo(host, None, family=socket.AF_INET)
            return {info[4][0] for info in infos}
        except OSError:
            _LOGGER.warning("Syslog host %s could not be resolved", host)
            return set()

    async def async_start(self) -> None:
        for host in self._hosts:
            self._allowed |= await self._resolve(host)
        if stored := await self._store.async_load():
            self.analyzer.load(stored, dt_util.utcnow())
        self._transport, _ = await self.hass.loop.create_datagram_endpoint(
            lambda: _Protocol(self), local_addr=("0.0.0.0", self.port)
        )
        if self._forward_cfg:
            await self._setup_forward(*self._forward_cfg)
        _LOGGER.info(
            "Syslog receiver on UDP %s, accepting %s%s",
            self.port,
            self.allowed,
            f", forwarding to {self.forward_addr[0]}:{self.forward_addr[1]}"
            if self.forward_addr
            else "",
        )

    async def _setup_forward(self, host: str, port: int) -> None:
        ips = await self._resolve(host)
        if not ips:
            _LOGGER.error("Syslog forward target %s not resolvable – forwarding off", host)
            return
        if port == self.port and any(_is_local_address(ip) for ip in ips):
            _LOGGER.error("Syslog forward target is this receiver – forwarding off (loop)")
            return
        if ips & self._allowed and port == self.port:
            _LOGGER.error("Syslog forward target is an allowed sender on the same port – forwarding off (loop)")
            return
        self.forward_addr = (sorted(ips)[0], port)
        self._fwd_transport, _ = await self.hass.loop.create_datagram_endpoint(
            asyncio.DatagramProtocol, family=socket.AF_INET
        )

    @callback
    def async_stop(self) -> None:
        for transport in (self._transport, self._fwd_transport):
            if transport:
                transport.close()
        self._transport = self._fwd_transport = None
        if self.analyzer.dirty:
            self._store.async_delay_save(self._data_to_save, 0)

    def _data_to_save(self) -> dict[str, Any]:
        self.analyzer.dirty = False
        return self.analyzer.dump()

    @callback
    def async_add_listener(self, update: Any) -> Any:
        self._listeners.append(update)

        def remove() -> None:
            self._listeners.remove(update)

        return remove

    def _allow_rate(self) -> bool:
        now = time.monotonic()
        self._tokens = min(float(RATE_LIMIT), self._tokens + (now - self._last_refill) * RATE_LIMIT)
        self._last_refill = now
        if self._tokens < 1:
            return False
        self._tokens -= 1
        return True

    def handle(self, data: bytes, source: str) -> None:
        if source not in self._allowed:
            self.dropped += 1
            _LOGGER.debug("Syslog datagram from %s dropped (not an allowed sender)", source)
            self._notify()
            return
        if not self._allow_rate():
            self.rate_limited += 1
            return
        data = data[:MAX_DATAGRAM]
        if self._fwd_transport and self.forward_addr:
            try:
                self._fwd_transport.sendto(data, self.forward_addr)
                self.forwarded += 1
            except OSError as err:
                _LOGGER.debug("Syslog forward failed: %s", err)
        msg = parse_message(data.decode("utf-8", errors="replace"))
        now = dt_util.utcnow()
        msg["received"] = now.isoformat()
        msg["sender"] = source
        self.messages.append(msg)
        product = (msg.get("fields") or {}).get("ProductName") or "unknown"
        if product in self.by_product or len(self.by_product) < MAX_PRODUCTS:
            self.by_product.setdefault(product, deque(maxlen=PRODUCT_BUFFER_SIZE)).append(msg)
            self.product_counts[product] = self.product_counts.get(product, 0) + 1
        self.received += 1
        self.last_received = now
        for event in self.analyzer.add(msg, now):
            event["entry_id"] = self.entry_id
            _LOGGER.info("Syslog threat event: %s", event)
            self.hass.bus.async_fire(EVENT_THREAT, event)
        if self.analyzer.dirty:
            self._store.async_delay_save(self._data_to_save, STORE_DELAY)
        self._notify()

    def _notify(self) -> None:
        for update in list(self._listeners):
            update()
