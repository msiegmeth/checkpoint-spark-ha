"""Sensors for Check Point Quantum Spark security reports."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import EntityCategory, UnitOfInformation
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC, DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from .const import DOMAIN
from .coordinator import SparkConfigEntry, SparkCoordinator
from .report import _chart, _has_summary, _history, _int, _summary, blades_of

PARALLEL_UPDATES = 0

# Attributes holding lists; kept out of the recorder.
LIST_ATTRIBUTES = frozenset(
    {
        "top_apps_by_bandwidth",
        "top_sites_by_bandwidth",
        "top_categories_by_bandwidth",
        "top_users_by_bandwidth",
        "bandwidth_history",
        "top_apps_by_sessions",
        "top_sites_by_sessions",
        "top_categories_by_sessions",
        "top_users_by_sessions",
        "top_high_risk_apps",
        "top_high_risk_users",
        "top_protections",
        "top_malwares",
        "top_infected_hosts",
        "infected_hosts",
        "possibly_infected_hosts",
        "blades",
    }
)

def _charts(**keys: str) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def build(report: dict[str, Any]) -> dict[str, Any]:
        return {attr: _chart(report, key) for attr, key in keys.items()}

    return build


@dataclass(frozen=True, kw_only=True)
class SparkSummaryDescription(SensorEntityDescription):
    """A value from the report summary, plus optional list attributes."""

    header: str
    attrs_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = field(default=None)
    # Only enabled by default when this software blade is active on the gateway.
    blade: str | None = None


def _bytes(key: str, header: str, icon: str, attrs_fn=None) -> SparkSummaryDescription:
    return SparkSummaryDescription(
        key=key,
        header=header,
        icon=icon,
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfInformation.BYTES,
        suggested_unit_of_measurement=UnitOfInformation.GIGABYTES,
        suggested_display_precision=2,
        attrs_fn=attrs_fn,
    )


def _count(key: str, header: str, icon: str, attrs_fn=None, blade=None) -> SparkSummaryDescription:
    return SparkSummaryDescription(
        key=key,
        header=header,
        icon=icon,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
        attrs_fn=attrs_fn,
        blade=blade,
    )


def _traffic_attrs(report: dict[str, Any]) -> dict[str, Any]:
    attrs = _charts(
        top_apps_by_bandwidth="topAppsByBandwidthChart",
        top_sites_by_bandwidth="topSitesByBandwidthChart",
        top_categories_by_bandwidth="topCategoriesByBandwidthChart",
        top_users_by_bandwidth="topUsersByBandwidthChart",
    )(report)
    attrs["bandwidth_history"] = _history(report)
    return attrs


def _infected_attrs(report: dict[str, Any]) -> dict[str, Any]:
    return _charts(
        top_infected_hosts="topInfectedHostsChart",
        infected_hosts="infectedHostsChart",
        possibly_infected_hosts="possiblyInfectedHostsChart",
    )(report)


SUMMARY_SENSORS: tuple[SparkSummaryDescription, ...] = (
    _bytes("traffic", "TOTAL_BYTES", "mdi:swap-vertical-bold", _traffic_attrs),
    _bytes("download", "TOTAL_DOWN_BYTES", "mdi:download"),
    _bytes("upload", "TOTAL_UP_BYTES", "mdi:upload"),
    _count(
        "sessions",
        "TOTAL_APPS",
        "mdi:lan-connect",
        _charts(
            top_apps_by_sessions="topAppsBySessionsChart",
            top_sites_by_sessions="topSitesBySessionsChart",
            top_categories_by_sessions="topCategoriesBySessionsChart",
            top_users_by_sessions="topUsersBySessionsChart",
        ),
    ),
    _count(
        "high_risk_sessions",
        "TOTAL_HIGH_RISK_APPS",
        "mdi:alert-octagon",
        _charts(
            top_high_risk_apps="topHighRiskAppsBySessionsChart",
            top_high_risk_users="topHighRiskUsersBySessionsChart",
        ),
    ),
    _count(
        "ips_events",
        "TOTAL_PROTECTIONS",
        "mdi:shield-alert",
        _charts(top_protections="topProtectionsBySessionsChart"),
    ),
    _count(
        "virus_incidents",
        "TOTAL_AV_MALWARES",
        "mdi:virus",
        _charts(top_malwares="topMalwaresChart"),
    ),
    _count("bot_incidents", "TOTAL_AB_MALWARES", "mdi:robot-angry"),
    _count("emulation_malware", "TOTAL_TE_MALWARES", "mdi:flask", blade="threat_emulation"),
    _count("emulated_files", "TOTAL_TE_FILES_SCANNED_CLOUD", "mdi:file-search", blade="threat_emulation"),
    _count("infected_hosts", "TOTAL_INFECTED_HOSTS", "mdi:laptop-off", _infected_attrs),
    _count("new_infected_hosts", "TOTAL_NEWLY_INFECTED_HOSTS", "mdi:laptop-off"),
    _count(
        "critical_infected_hosts", "TOTAL_CRITICAL_INFECTED_HOSTS", "mdi:laptop-off"
    ),
    _count("infected_servers", "TOTAL_INFECTED_SERVERS", "mdi:server-off"),
)


class SparkEntity(CoordinatorEntity[SparkCoordinator]):
    """Common base: one device per gateway."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: SparkCoordinator, key: str) -> None:
        super().__init__(coordinator)
        entry = coordinator.config_entry
        self._attr_unique_id = f"{entry.unique_id}_{key}"
        info = _report_info(coordinator)
        mac = info.get("macAddress")
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.unique_id)},
            connections={(CONNECTION_NETWORK_MAC, mac.lower())} if mac else set(),
            manufacturer="Check Point",
            model="Quantum Spark",
            name="Quantum Spark",
            sw_version=info.get("firmwareVersion"),
            configuration_url=f"https://{entry.data['host']}",
        )


def _first_report(coordinator: SparkCoordinator) -> dict[str, Any]:
    for report in (coordinator.data.reports if coordinator.data else {}).values():
        if isinstance(report, dict):
            return report
    return {}


def _blades(coordinator: SparkCoordinator) -> dict[str, bool]:
    return blades_of(_first_report(coordinator))


def _report_info(coordinator: SparkCoordinator) -> dict[str, Any]:
    info = _first_report(coordinator).get("reportInfo")
    return info if isinstance(info, dict) else {}


class SparkReportEntity(SparkEntity):
    """Entity bound to one report type."""

    def __init__(self, coordinator: SparkCoordinator, report_type: str, key: str) -> None:
        super().__init__(coordinator, f"{report_type}_{key}")
        self._report_type = report_type
        self._attr_translation_key = f"{report_type}_{key}"

    @property
    def _report(self) -> dict[str, Any] | None:
        report = self.coordinator.data.reports.get(self._report_type)
        return report if isinstance(report, dict) else None

    @property
    def available(self) -> bool:
        return super().available and self._report is not None


class SparkSummarySensor(SparkReportEntity, SensorEntity):
    """Key figure from a report summary."""

    entity_description: SparkSummaryDescription
    _unrecorded_attributes = LIST_ATTRIBUTES

    def __init__(
        self,
        coordinator: SparkCoordinator,
        report_type: str,
        description: SparkSummaryDescription,
        blades: dict[str, bool],
    ) -> None:
        super().__init__(coordinator, report_type, description.key)
        self.entity_description = description
        if description.blade:
            self._attr_entity_registry_enabled_default = blades.get(description.blade, True)

    @property
    def native_value(self) -> int | None:
        return _summary(self._report or {}, self.entity_description.header)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if not self.entity_description.attrs_fn or not self._report:
            return None
        return self.entity_description.attrs_fn(self._report)


class SparkReportTimestampSensor(SparkReportEntity, SensorEntity):
    """When the report of this type was generated on the gateway."""

    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: SparkCoordinator, report_type: str) -> None:
        super().__init__(coordinator, report_type, "report_time")

    @property
    def native_value(self) -> datetime | None:
        info = (self._report or {}).get("reportInfo") or {}
        if (ts := _int(info.get("timeStamp"))) is not None:
            return dt_util.utc_from_timestamp(ts)
        return self.coordinator.data.fetched.get(self._report_type)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        status = (self._report or {}).get("reportStatus") or {}
        attrs: dict[str, Any] = {}
        if (start := _int(status.get("startDate"))) is not None:
            attrs["period_start"] = dt_util.utc_from_timestamp(start).isoformat()
        if status.get("status"):
            attrs["status"] = str(status["status"]).removeprefix("REPORT_STATUS.").lower()
        if fetched := self.coordinator.data.fetched.get(self._report_type):
            attrs["fetched"] = fetched.isoformat()
        return attrs


class SparkBladesSensor(SparkEntity, SensorEntity):
    """Number of enabled software blades; per-blade state as attribute."""

    _attr_translation_key = "active_blades"
    _attr_icon = "mdi:shield-check"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _unrecorded_attributes = LIST_ATTRIBUTES

    def __init__(self, coordinator: SparkCoordinator) -> None:
        super().__init__(coordinator, "active_blades")

    def _blades(self) -> dict[str, bool]:
        return _blades(self.coordinator)

    @property
    def native_value(self) -> int | None:
        blades = self._blades()
        return sum(blades.values()) if blades else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"blades": self._blades()}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SparkConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    entities: list[SensorEntity] = [SparkBladesSensor(coordinator)]
    blades = _blades(coordinator)
    for report_type in coordinator.report_types:
        entities.append(SparkReportTimestampSensor(coordinator, report_type))
        report = coordinator.data.reports.get(report_type) or {}
        # Only create what this report type (and firmware) actually delivers.
        entities.extend(
            SparkSummarySensor(coordinator, report_type, description, blades)
            for description in SUMMARY_SENSORS
            if _has_summary(report, description.header)
        )
    async_add_entities(entities)
