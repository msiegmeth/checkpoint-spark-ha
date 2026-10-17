"""Diagnostics for Check Point Quantum Spark."""

from __future__ import annotations

import json
import re
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from .const import CONF_REDACT_DIAGNOSTICS
from .coordinator import SparkConfigEntry

TO_REDACT = {CONF_USERNAME, CONF_PASSWORD, "user", "password", "sid", "serial_number", "ipv4_address"}
# additionally removed with the "redact network data" option
NETWORK_KEYS = {"macAddress", "gatewayName", "host", "url", "configuration_url"}

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")


def _anonymise(data: Any) -> Any:
    """Replace IPv4/MAC addresses consistently (same address -> same placeholder)."""
    ips: dict[str, str] = {}

    def ip(m: re.Match[str]) -> str:
        return ips.setdefault(m.group(), f"192.0.2.{len(ips) + 1}")

    text = json.dumps(data, ensure_ascii=False)
    text = _MAC.sub("00:00:5E:00:53:00", _IPV4.sub(ip, text))
    return json.loads(text)


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: SparkConfigEntry
) -> dict[str, Any]:
    data = entry.runtime_data.data
    redact = set(TO_REDACT)
    network = entry.options.get(CONF_REDACT_DIAGNOSTICS, False)
    if network:
        redact |= NETWORK_KEYS
    result = {
        "entry": {
            "data": async_redact_data(dict(entry.data), redact),
            "options": dict(entry.options),
        },
        "login_info": async_redact_data(data.login_info, redact),
        "fetched": {k: v.isoformat() for k, v in data.fetched.items()},
        "system": async_redact_data(data.system, redact),
        "reports": async_redact_data(data.reports, redact),
    }
    if (rx := entry.runtime_data.syslog) is not None:
        result["syslog"] = {
            "port": rx.port,
            "received": rx.received,
            "dropped": rx.dropped,
            "products": dict(rx.product_counts),
            "messages": list(rx.messages)[-20:],
            "by_product": {p: list(m)[-10:] for p, m in rx.by_product.items()},
        }
    return _anonymise(result) if network else result
