"""Optional syslog receiver (UDP) for the gateway's security logs.

Preparation stage: messages from the gateway IP are split into key/value
pairs and kept in memory (ring buffer) so the log format can be analysed.
Nothing is written to disk.
"""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime
import logging
import re
import socket
from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.util import dt as dt_util

_LOGGER = logging.getLogger(__name__)

BUFFER_SIZE = 200

# <PRI>, optional RFC 5424 version, then the rest
_PRI = re.compile(r"^<(\d{1,3})>(\d\s)?")
# key="value" or key=value (Check Point log export style); also key:"value"
_KV = re.compile(r'([A-Za-z_][\w.-]*)(?:\s*=\s*("(?:[^"\\]|\\.)*"|[^\s;,\]]+)|:("(?:[^"\\]|\\.)*"))')


def parse_message(raw: str) -> dict[str, Any]:
    """Best-effort split of a syslog line: priority, header and key/value fields."""
    msg: dict[str, Any] = {"raw": raw.strip()}
    if m := _PRI.match(raw):
        pri = int(m.group(1))
        msg["facility"], msg["severity"] = pri >> 3, pri & 7
        raw = raw[m.end():]
    fields = {}
    for key, val, quoted in _KV.findall(raw):
        val = val or quoted
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1].replace('\\"', '"')
        fields[key] = val
    if fields:
        msg["fields"] = fields
        # header = text before the first key/value pair
        first = _KV.search(raw)
        msg["header"] = raw[: first.start()].strip() if first else raw.strip()
    else:
        msg["header"] = raw.strip()
    return msg


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: SyslogReceiver) -> None:
        self._receiver = receiver

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._receiver.handle(data, addr[0])


class SyslogReceiver:
    """UDP listener; accepts datagrams from the gateway address only."""

    def __init__(self, hass: HomeAssistant, gateway_host: str, port: int) -> None:
        self.hass = hass
        self.port = port
        self._gateway_host = gateway_host
        self._allowed: set[str] = set()
        self._transport: asyncio.DatagramTransport | None = None
        self.messages: deque[dict[str, Any]] = deque(maxlen=BUFFER_SIZE)
        self.received = 0
        self.dropped = 0
        self.last_received: datetime | None = None
        self._listeners: list[Any] = []

    async def async_start(self) -> None:
        try:
            infos = await self.hass.loop.getaddrinfo(self._gateway_host, None, family=socket.AF_INET)
            self._allowed = {info[4][0] for info in infos}
        except OSError:
            self._allowed = {self._gateway_host}
        self._transport, _ = await self.hass.loop.create_datagram_endpoint(
            lambda: _Protocol(self), local_addr=("0.0.0.0", self.port)
        )
        _LOGGER.info("Syslog receiver listening on UDP %s (accepting %s)", self.port, self._allowed)

    @callback
    def async_stop(self) -> None:
        if self._transport:
            self._transport.close()
            self._transport = None

    @callback
    def async_add_listener(self, update: Any) -> Any:
        self._listeners.append(update)

        def remove() -> None:
            self._listeners.remove(update)

        return remove

    def handle(self, data: bytes, source: str) -> None:
        if source not in self._allowed:
            self.dropped += 1
            _LOGGER.debug("Syslog datagram from %s dropped (not the gateway)", source)
            self._notify()
            return
        text = data.decode("utf-8", errors="replace")
        msg = parse_message(text)
        msg["received"] = dt_util.utcnow().isoformat()
        self.messages.append(msg)
        self.received += 1
        self.last_received = dt_util.utcnow()
        self._notify()

    def _notify(self) -> None:
        for update in list(self._listeners):
            update()
