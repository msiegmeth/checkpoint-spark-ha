"""Check Point Quantum Spark security reports."""

from __future__ import annotations

from homeassistant.const import Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

import logging

from homeassistant.const import CONF_HOST

from .const import (
    CONF_SYSLOG_ENABLED,
    CONF_SYSLOG_IGNORE,
    CONF_SYSLOG_FORWARD,
    CONF_SYSLOG_PORT,
    CONF_SYSLOG_RETENTION,
    CONF_SYSLOG_SENDERS,
    DEFAULT_SYSLOG_PORT,
    DEFAULT_SYSLOG_RETENTION,
    DOMAIN,
)
from .coordinator import SparkConfigEntry, SparkCoordinator
from .services import async_setup_services
from .syslog import SyslogReceiver, split_hosts

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.BINARY_SENSOR, Platform.SENSOR]

CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    async_setup_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: SparkConfigEntry) -> bool:
    coordinator = SparkCoordinator(hass, entry)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    if entry.options.get(CONF_SYSLOG_ENABLED):
        opts = entry.options
        receiver = SyslogReceiver(
            hass,
            entry.data[CONF_HOST],
            opts.get(CONF_SYSLOG_PORT, DEFAULT_SYSLOG_PORT),
            entry.entry_id,
            ignore_sources=split_hosts(opts.get(CONF_SYSLOG_IGNORE, "")),
            senders=split_hosts(opts.get(CONF_SYSLOG_SENDERS, "")),
            forward=opts.get(CONF_SYSLOG_FORWARD, ""),
            retention_days=int(opts.get(CONF_SYSLOG_RETENTION, DEFAULT_SYSLOG_RETENTION)),
        )
        try:
            await receiver.async_start()
        except OSError as err:
            _LOGGER.error("Syslog receiver could not start on port %s: %s", receiver.port, err)
        else:
            coordinator.syslog = receiver
            entry.async_on_unload(receiver.async_stop)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: SparkConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
