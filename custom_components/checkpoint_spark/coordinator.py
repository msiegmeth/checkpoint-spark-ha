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
    CONF_MONITORED_BLADES,
    CONF_REPORT_TYPES,
    CONF_SCAN_INTERVAL_MIN,
    DEFAULT_INTERVALS,
    DEFAULT_REPORT_TYPES,
    DEFAULT_SCAN_INTERVAL_MIN,
    DOMAIN,
    EVENT_DEDUP_HOURS,
    EVENT_REPORT_ORDER,
    EVENT_THREAT,
)
from .report import _chart, _summary, blades_of

_LOGGER = logging.getLogger(__name__)

type SparkConfigEntry = ConfigEntry[SparkCoordinator]

# A report counts as due slightly before its interval ends (poll jitter).
_DUE_TOLERANCE = timedelta(seconds=60)


@dataclass
class SparkData:
    """Decoded reports per type plus the time each one was fetched."""

    reports: dict[str, Any] = field(default_factory=dict)
    fetched: dict[str, datetime] = field(default_factory=dict)
    login_info: dict[str, Any] = field(default_factory=dict)


def report_interval(options: dict[str, Any], report_type: str) -> int:
    """Polling interval in minutes for one report type (falls back to the old global option)."""
    key = f"{CONF_SCAN_INTERVAL_MIN}_{report_type}"
    if key in options:
        return int(options[key])
    if CONF_SCAN_INTERVAL_MIN in options:  # options from v0.1.x
        return max(int(options[CONF_SCAN_INTERVAL_MIN]), DEFAULT_INTERVALS[report_type])
    return DEFAULT_INTERVALS.get(report_type, DEFAULT_SCAN_INTERVAL_MIN)


class SparkCoordinator(DataUpdateCoordinator[SparkData]):
    """Fetch the due reports in one short session per update."""

    config_entry: SparkConfigEntry

    def __init__(self, hass: HomeAssistant, entry: SparkConfigEntry) -> None:
        self.report_types: list[str] = list(
            entry.options.get(CONF_REPORT_TYPES, DEFAULT_REPORT_TYPES)
        )
        self.intervals = {
            rt: timedelta(minutes=report_interval(dict(entry.options), rt))
            for rt in self.report_types
        }
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=min(self.intervals.values(), default=timedelta(minutes=15)),
        )
        # threat events: last time each (kind, name) was seen
        self._seen: dict[tuple[str, str], datetime] = {}

    def _api(self) -> SparkApi:
        data = self.config_entry.data
        verify = data.get(CONF_VERIFY_SSL, False)
        return SparkApi(
            async_get_clientsession(self.hass, verify_ssl=verify),
            data[CONF_HOST],
            data[CONF_PORT],
            verify,
        )

    def _due(self, previous: SparkData, now: datetime) -> list[str]:
        return [
            rt
            for rt in self.report_types
            if rt not in previous.fetched
            or now - previous.fetched[rt] >= self.intervals[rt] - _DUE_TOLERANCE
        ]

    async def _async_update_data(self) -> SparkData:
        data = self.config_entry.data
        previous = self.data or SparkData()
        now = dt_util.utcnow()
        due = self._due(previous, now)
        result = SparkData(
            reports={k: v for k, v in previous.reports.items() if k in self.report_types},
            fetched={k: v for k, v in previous.fetched.items() if k in self.report_types},
            login_info=previous.login_info,
        )
        if not due:
            return result

        api = self._api()
        errors: list[str] = []
        try:
            result.login_info = await api.login(data[CONF_USERNAME], data[CONF_PASSWORD])
            for report_type in due:
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

        if errors and len(errors) == len(due) and not result.reports:
            raise UpdateFailed("; ".join(errors))

        self._fire_threat_events(previous, result, now)
        self._init_monitored_blades(result)
        return result

    # ------------------------------------------------------------ events --
    def _event_report_type(self, fetched_now: SparkData, previous: SparkData) -> str | None:
        """Most current selected report type that was refreshed in this update."""
        for rt in EVENT_REPORT_ORDER:
            if rt in self.report_types:
                if fetched_now.fetched.get(rt) != previous.fetched.get(rt):
                    return rt
                return None  # the preferred type was not refreshed this time
        return None

    def _fire_threat_events(self, previous: SparkData, result: SparkData, now: datetime) -> None:
        rt = self._event_report_type(result, previous)
        if rt is None:
            return
        new, old = result.reports.get(rt), previous.reports.get(rt)
        if not isinstance(new, dict):
            return
        baseline = not isinstance(old, dict)
        old = old if isinstance(old, dict) else {}
        events: list[dict[str, Any]] = []

        def listed(kind: str, chart: str, value_field: str, only=None) -> None:
            before = {i.get("name") for i in _chart(old, chart)}
            for item in _chart(new, chart):
                name = item.get("name")
                if not name or (only and not only(item)):
                    continue
                key = (kind, str(name))
                recently = self._seen.get(key)
                self._seen[key] = now
                if baseline or name in before:
                    continue
                if recently and now - recently < timedelta(hours=EVENT_DEDUP_HOURS):
                    continue
                events.append(
                    {
                        "kind": kind,
                        "name": name,
                        "value": item.get(value_field),
                        **{k: item[k] for k in ("severity", "cve") if item.get(k)},
                    }
                )

        listed("malware", "topMalwaresChart", "incidents")
        listed("host", "topInfectedHostsChart", "count")
        listed(
            "critical_protection",
            "topProtectionsBySessionsChart",
            "sessions",
            only=lambda i: str(i.get("severity")) == "4",
        )
        for kind, header in (
            ("infected_hosts", "TOTAL_INFECTED_HOSTS"),
            ("infected_servers", "TOTAL_INFECTED_SERVERS"),
            ("critically_infected_hosts", "TOTAL_CRITICAL_INFECTED_HOSTS"),
        ):
            before, after = _summary(old, header), _summary(new, header)
            if not baseline and after and after > (before or 0):
                events.append({"kind": kind, "name": header, "value": after, "previous": before})

        for event in events:
            event.update(entry_id=self.config_entry.entry_id, report_type=rt)
            _LOGGER.info("Threat event: %s", event)
            self.hass.bus.async_fire(EVENT_THREAT, event)

        # forget entries not seen for a long time
        cutoff = now - timedelta(hours=EVENT_DEDUP_HOURS * 2)
        self._seen = {k: t for k, t in self._seen.items() if t >= cutoff}

    # ------------------------------------------------------------ blades --
    def _init_monitored_blades(self, result: SparkData) -> None:
        """First run: monitor the blades that are enabled right now."""
        if CONF_MONITORED_BLADES in self.config_entry.options:
            return
        report = next((r for r in result.reports.values() if isinstance(r, dict)), {})
        blades = blades_of(report)
        if not blades:
            return
        self.hass.config_entries.async_update_entry(
            self.config_entry,
            options={
                **self.config_entry.options,
                CONF_MONITORED_BLADES: sorted(b for b, on in blades.items() if on),
            },
        )
