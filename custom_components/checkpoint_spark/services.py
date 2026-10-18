"""Actions (services) for Check Point Quantum Spark."""

from __future__ import annotations

import voluptuous as vol

from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import (
    HomeAssistant,
    ServiceCall,
    ServiceResponse,
    SupportsResponse,
    callback,
)
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv
from homeassistant.util import dt as dt_util

from .api import SparkError
from .const import DOMAIN, REPORT_TYPES
from .coordinator import SparkConfigEntry, SparkCoordinator

ATTR_CONFIG_ENTRY = "config_entry_id"
ATTR_REPORT_TYPE = "report_type"
ATTR_COMMAND = "command"

_ENTRY = {vol.Optional(ATTR_CONFIG_ENTRY): cv.string}


def _coordinator(hass: HomeAssistant, call: ServiceCall) -> SparkCoordinator:
    entries: list[SparkConfigEntry] = [
        e
        for e in hass.config_entries.async_entries(DOMAIN)
        if e.state is ConfigEntryState.LOADED
    ]
    if entry_id := call.data.get(ATTR_CONFIG_ENTRY):
        entries = [e for e in entries if e.entry_id == entry_id]
    if len(entries) != 1:
        raise ServiceValidationError(
            translation_domain=DOMAIN, translation_key="entry_not_found"
        )
    return entries[0].runtime_data


@callback
def async_setup_services(hass: HomeAssistant) -> None:
    async def refresh(call: ServiceCall) -> None:
        await _coordinator(hass, call).async_refresh_all()

    async def get_report(call: ServiceCall) -> ServiceResponse:
        coordinator = _coordinator(hass, call)
        report_type = call.data[ATTR_REPORT_TYPE]
        report = coordinator.data.reports.get(report_type) if coordinator.data else None
        if report is None:
            raise ServiceValidationError(
                translation_domain=DOMAIN,
                translation_key="report_not_loaded",
                translation_placeholders={"report_type": report_type},
            )
        fetched = coordinator.data.fetched.get(report_type)
        return {
            "report_type": report_type,
            "fetched": fetched.isoformat() if fetched else None,
            "report": report,
        }

    async def show_command(call: ServiceCall) -> ServiceResponse:
        coordinator = _coordinator(hass, call)
        command = call.data[ATTR_COMMAND].strip()
        if not command.lower().startswith("show "):
            raise ServiceValidationError(
                translation_domain=DOMAIN, translation_key="only_show"
            )
        data = coordinator.config_entry.data
        api = coordinator.api()
        try:
            await api.login(data[CONF_USERNAME], data[CONF_PASSWORD])
            output = await api.run_show_command(command)
        except SparkError as err:
            raise HomeAssistantError(f"{command}: {err}") from err
        finally:
            await api.logout()
        return {"command": command, "output": output}

    async def syslog_messages(call: ServiceCall) -> ServiceResponse:
        coordinator = _coordinator(hass, call)
        rx = coordinator.syslog
        if rx is None:
            raise ServiceValidationError(
                translation_domain=DOMAIN, translation_key="syslog_disabled"
            )
        limit = call.data["limit"]
        product = call.data.get("product")
        source = rx.by_product.get(product, []) if product else rx.messages
        return {
            "received": rx.received,
            "dropped": rx.dropped,
            "products": dict(rx.product_counts),
            "messages": list(reversed(source))[:limit],
        }

    async def detections(call: ServiceCall) -> ServiceResponse:
        coordinator = _coordinator(hass, call)
        rx = coordinator.syslog
        if rx is None:
            raise ServiceValidationError(
                translation_domain=DOMAIN, translation_key="syslog_disabled"
            )
        items = rx.analyzer.history_since(dt_util.utcnow(), call.data["days"], call.data.get("kind"))
        return {"count": len(items), "detections": list(reversed(items))}

    hass.services.async_register(
        DOMAIN,
        "detections",
        detections,
        schema=vol.Schema({**_ENTRY, vol.Optional("days", default=7): vol.All(int, vol.Range(1, 365)),
                           vol.Optional("kind"): vol.In(["ips_attack", "malware_detected"])}),
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(DOMAIN, "refresh", refresh, schema=vol.Schema(_ENTRY))
    hass.services.async_register(
        DOMAIN,
        "syslog_messages",
        syslog_messages,
        schema=vol.Schema({**_ENTRY, vol.Optional("limit", default=50): vol.All(int, vol.Range(1, 200)),
            vol.Optional("product"): cv.string}),
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        "get_report",
        get_report,
        schema=vol.Schema({**_ENTRY, vol.Required(ATTR_REPORT_TYPE): vol.In(REPORT_TYPES)}),
        supports_response=SupportsResponse.ONLY,
    )
    hass.services.async_register(
        DOMAIN,
        "show_command",
        show_command,
        schema=vol.Schema({**_ENTRY, vol.Required(ATTR_COMMAND): cv.string}),
        supports_response=SupportsResponse.ONLY,
    )
