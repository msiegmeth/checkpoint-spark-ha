"""Diagnostics for Check Point Quantum Spark."""

from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from .coordinator import SparkConfigEntry

TO_REDACT = {CONF_USERNAME, CONF_PASSWORD, "user", "password", "sid"}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: SparkConfigEntry
) -> dict[str, Any]:
    data = entry.runtime_data.data
    return {
        "entry": {
            "data": async_redact_data(dict(entry.data), TO_REDACT),
            "options": dict(entry.options),
        },
        "login_info": async_redact_data(data.login_info, TO_REDACT),
        "fetched": {k: v.isoformat() for k, v in data.fetched.items()},
        "reports": async_redact_data(data.reports, TO_REDACT),
    }
