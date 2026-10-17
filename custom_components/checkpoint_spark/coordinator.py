"""Data update coordinator for Check Point Quantum Spark."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
)
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .api import SparkApi, SparkAuthError, SparkError
from .const import (
    CONF_REPORT_TYPES,
    CONF_SCAN_INTERVAL_MIN,
    DEFAULT_REPORT_TYPES,
    DEFAULT_SCAN_INTERVAL_MIN,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

type SparkConfigEntry = ConfigEntry[SparkCoordinator]


@dataclass
class SparkData:
    """Decoded reports per type plus the time each one was fetched."""

    reports: dict[str, Any] = field(default_factory=dict)
    fetched: dict[str, datetime] = field(default_factory=dict)
    login_info: dict[str, Any] = field(default_factory=dict)


class SparkCoordinator(DataUpdateCoordinator[SparkData]):
    """Fetch all selected reports in one short session per update."""

    config_entry: SparkConfigEntry

    def __init__(self, hass: HomeAssistant, entry: SparkConfigEntry) -> None:
        minutes = entry.options.get(CONF_SCAN_INTERVAL_MIN, DEFAULT_SCAN_INTERVAL_MIN)
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=timedelta(minutes=minutes),
        )
        self.report_types: list[str] = list(
            entry.options.get(CONF_REPORT_TYPES, DEFAULT_REPORT_TYPES)
        )

    def _api(self) -> SparkApi:
        data = self.config_entry.data
        verify = data.get(CONF_VERIFY_SSL, False)
        return SparkApi(
            async_get_clientsession(self.hass, verify_ssl=verify),
            data[CONF_HOST],
            data[CONF_PORT],
            verify,
        )

    async def _async_update_data(self) -> SparkData:
        data = self.config_entry.data
        api = self._api()
        previous = self.data or SparkData()
        result = SparkData(
            reports=dict(previous.reports), fetched=dict(previous.fetched)
        )
        errors: list[str] = []
        try:
            result.login_info = await api.login(data[CONF_USERNAME], data[CONF_PASSWORD])
            for report_type in self.report_types:
                try:
                    result.reports[report_type] = await api.generate_report(report_type)
                    result.fetched[report_type] = dt_util.utcnow()
                except SparkAuthError:
                    raise
                except SparkError as err:
                    _LOGGER.warning("Report %s failed: %s", report_type, err)
                    errors.append(f"{report_type}: {err}")
        except SparkAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except SparkError as err:
            raise UpdateFailed(str(err)) from err
        finally:
            await api.logout()

        if errors and len(errors) == len(self.report_types):
            raise UpdateFailed("; ".join(errors))
        # Drop report types that were deselected in the options.
        for stale in set(result.reports) - set(self.report_types):
            result.reports.pop(stale, None)
            result.fetched.pop(stale, None)
        return result
