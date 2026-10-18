"""Config flow for Check Point Quantum Spark."""

from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import (
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlowWithReload,
)
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import selector
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import SparkApi, SparkAuthError, SparkError
from .const import (
    CONF_MONITORED_BLADES,
    CONF_REDACT_DIAGNOSTICS,
    CONF_SYSLOG_ENABLED,
    CONF_SYSLOG_IGNORE,
    CONF_SYSLOG_PORT,
    DEFAULT_SYSLOG_PORT,
    CONF_REPORT_TYPES,
    CONF_SCAN_INTERVAL_MIN,
    DEFAULT_PORT,
    DEFAULT_REPORT_TYPES,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
    MAX_SCAN_INTERVAL_MIN,
    MIN_SCAN_INTERVAL_MIN,
    REPORT_TYPES,
)
from .coordinator import SparkConfigEntry, report_interval
from .report import blades_of

_LOGGER = logging.getLogger(__name__)


async def _test_login(hass: HomeAssistant, data: Mapping[str, Any]) -> str | None:
    """Return an error key or None if login works."""
    verify = data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)
    api = SparkApi(
        async_get_clientsession(hass, verify_ssl=verify),
        data[CONF_HOST],
        data[CONF_PORT],
        verify,
    )
    try:
        await api.login(data[CONF_USERNAME], data[CONF_PASSWORD])
    except SparkAuthError:
        return "invalid_auth"
    except SparkError as err:
        _LOGGER.debug("Connection test failed: %s", err)
        return "cannot_connect"
    except Exception:
        _LOGGER.exception("Unexpected error during login test")
        return "unknown"
    finally:
        await api.logout()
    return None


def _user_schema(defaults: Mapping[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_HOST, default=defaults.get(CONF_HOST, "")): str,
            vol.Required(CONF_PORT, default=defaults.get(CONF_PORT, DEFAULT_PORT)): vol.All(
                vol.Coerce(int), vol.Range(min=1, max=65535)
            ),
            vol.Required(CONF_USERNAME, default=defaults.get(CONF_USERNAME, "")): str,
            vol.Required(CONF_PASSWORD): selector.TextSelector(
                selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
            ),
            vol.Required(
                CONF_VERIFY_SSL,
                default=defaults.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
            ): bool,
        }
    )


class SparkConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle a config flow."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            user_input[CONF_HOST] = user_input[CONF_HOST].strip()
            await self.async_set_unique_id(
                f"{user_input[CONF_HOST]}:{user_input[CONF_PORT]}"
            )
            self._abort_if_unique_id_configured()
            if not (error := await _test_login(self.hass, user_input)):
                return self.async_create_entry(
                    title=f"Quantum Spark ({user_input[CONF_HOST]})",
                    data=user_input,
                    options={CONF_REPORT_TYPES: DEFAULT_REPORT_TYPES},
                )
            errors["base"] = error
        return self.async_show_form(
            step_id="user",
            data_schema=_user_schema(user_input or {}),
            errors=errors,
        )

    async def async_step_reauth(
        self, entry_data: Mapping[str, Any]
    ) -> ConfigFlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            data = {**entry.data, **user_input}
            if not (error := await _test_login(self.hass, data)):
                return self.async_update_reload_and_abort(entry, data=data)
            errors["base"] = error
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_USERNAME, default=entry.data.get(CONF_USERNAME, "")
                    ): str,
                    vol.Required(CONF_PASSWORD): selector.TextSelector(
                        selector.TextSelectorConfig(
                            type=selector.TextSelectorType.PASSWORD
                        )
                    ),
                }
            ),
            description_placeholders={"host": entry.data[CONF_HOST]},
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: SparkConfigEntry) -> SparkOptionsFlow:
        return SparkOptionsFlow()


class SparkOptionsFlow(OptionsFlowWithReload):
    """Report types, polling interval per type, monitored blades; changes reload the entry."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            if not user_input.get(CONF_REPORT_TYPES):
                errors[CONF_REPORT_TYPES] = "no_report_type"
            else:
                for rt in REPORT_TYPES:
                    key = f"{CONF_SCAN_INTERVAL_MIN}_{rt}"
                    if key in user_input:
                        user_input[key] = int(user_input[key])
                return self.async_create_entry(data=user_input)

        options = dict(self.config_entry.options)
        fields: dict[Any, Any] = {
            vol.Required(
                CONF_REPORT_TYPES,
                default=options.get(CONF_REPORT_TYPES, DEFAULT_REPORT_TYPES),
            ): selector.SelectSelector(
                selector.SelectSelectorConfig(
                    options=REPORT_TYPES,
                    multiple=True,
                    mode=selector.SelectSelectorMode.LIST,
                    translation_key="report_type",
                )
            ),
        }
        for rt in REPORT_TYPES:
            fields[
                vol.Required(
                    f"{CONF_SCAN_INTERVAL_MIN}_{rt}", default=report_interval(options, rt)
                )
            ] = selector.NumberSelector(
                selector.NumberSelectorConfig(
                    min=MIN_SCAN_INTERVAL_MIN,
                    max=MAX_SCAN_INTERVAL_MIN,
                    step=1,
                    mode=selector.NumberSelectorMode.BOX,
                    unit_of_measurement="min",
                )
            )
        monitored = list(options.get(CONF_MONITORED_BLADES, []))
        known = set(monitored)
        coordinator = getattr(self.config_entry, "runtime_data", None)
        if coordinator and coordinator.data:
            for report in coordinator.data.reports.values():
                if isinstance(report, dict):
                    known |= set(blades_of(report))
                    break
        if known:
            fields[vol.Optional(CONF_MONITORED_BLADES, default=monitored)] = (
                selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=sorted(known),
                        multiple=True,
                        mode=selector.SelectSelectorMode.LIST,
                        translation_key="blade",
                    )
                )
            )
        fields[
            vol.Optional(
                CONF_REDACT_DIAGNOSTICS,
                default=options.get(CONF_REDACT_DIAGNOSTICS, False),
            )
        ] = bool
        fields[
            vol.Optional(CONF_SYSLOG_ENABLED, default=options.get(CONF_SYSLOG_ENABLED, False))
        ] = bool
        fields[
            vol.Optional(CONF_SYSLOG_PORT, default=options.get(CONF_SYSLOG_PORT, DEFAULT_SYSLOG_PORT))
        ] = vol.All(vol.Coerce(int), vol.Range(min=1024, max=65535))
        fields[
            vol.Optional(CONF_SYSLOG_IGNORE, default=options.get(CONF_SYSLOG_IGNORE, ""))
        ] = str
        return self.async_show_form(
            step_id="init", data_schema=vol.Schema(fields), errors=errors
        )
