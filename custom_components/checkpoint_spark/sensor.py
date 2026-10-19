"""Sensors for Check Point Quantum Spark security reports."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
import time
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    PERCENTAGE,
    EntityCategory,
    UnitOfDataRate,
    UnitOfInformation,
    UnitOfTemperature,
    UnitOfTime,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er
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
            serial_number=(coordinator.data.system.get("serial_number") if coordinator.data else None),
            hw_version=(coordinator.data.system.get("hw_version") if coordinator.data else None),
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


@dataclass(frozen=True, kw_only=True)
class SparkSystemDescription(SensorEntityDescription):
    """A value parsed from a read-only clish show command."""

    value_fn: Callable[[dict[str, Any]], Any]
    attrs_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None
    exists_fn: Callable[[dict[str, Any]], bool] = lambda s: True


def _primary_internet(system: dict[str, Any]) -> dict[str, Any]:
    conns = system.get("internet") or []
    return conns[0] if conns else {}


def _connected_since(system: dict[str, Any]) -> datetime | None:
    secs = _primary_internet(system).get("connected_seconds")
    fetched = system.get("_fetched")
    if secs is None or not fetched or not _primary_internet(system).get("active"):
        return None
    # round to the minute so the state does not change on every poll
    since = fetched - timedelta(seconds=secs)
    return since.replace(second=0, microsecond=0)


def _expiry(system: dict[str, Any]) -> datetime | None:
    value = system.get("next_contract_expiry")
    if not value:
        return None
    return dt_util.start_of_local_day(date.fromisoformat(value))


SYSTEM_SENSORS: tuple[SparkSystemDescription, ...] = (
    SparkSystemDescription(
        key="cpu_temperature",
        device_class=SensorDeviceClass.TEMPERATURE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        suggested_display_precision=0,
        value_fn=lambda s: s.get("cpu_temperature"),
        attrs_fn=lambda s: {"internal": s.get("cpu_temperature_internal")},
        exists_fn=lambda s: "cpu_temperature" in s,
    ),
    SparkSystemDescription(
        key="ddr_temperature",
        device_class=SensorDeviceClass.TEMPERATURE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        suggested_display_precision=0,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.get("ddr_temperature"),
        exists_fn=lambda s: "ddr_temperature" in s,
    ),
    SparkSystemDescription(
        key="memory_used",
        icon="mdi:memory",
        device_class=SensorDeviceClass.DATA_SIZE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfInformation.MEGABYTES,
        suggested_display_precision=0,
        value_fn=lambda s: s.get("memory_used_mb"),
        exists_fn=lambda s: "memory_used_mb" in s,
    ),
    SparkSystemDescription(
        key="emmc_wear",
        icon="mdi:harddisk",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.get("emmc_wear"),
        exists_fn=lambda s: "emmc_wear" in s,
    ),
    SparkSystemDescription(
        key="firmware",
        icon="mdi:package-variant-closed",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: s.get("firmware"),
        attrs_fn=lambda s: {
            "version": s.get("firmware_version"),
            "build": s.get("firmware_build"),
            "model": s.get("model"),
            "hw_version": s.get("hw_version"),
            "auto_upgrade": s.get("firmware_auto_upgrade"),
        },
        exists_fn=lambda s: "firmware" in s,
    ),
    SparkSystemDescription(
        key="internet_connected_since",
        icon="mdi:web-clock",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=_connected_since,
        attrs_fn=lambda s: {
            k: _primary_internet(s).get(k) for k in ("name", "type", "interface", "link_status")
        },
        exists_fn=lambda s: bool(s.get("internet")),
    ),
    SparkSystemDescription(
        key="public_ipv4",
        icon="mdi:ip-network",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda s: _primary_internet(s).get("ipv4_address"),
        exists_fn=lambda s: bool(s.get("internet")),
    ),
    SparkSystemDescription(
        key="vpn_tunnels_up",
        icon="mdi:vpn",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda s: sum(t.get("state") == "up" for t in s.get("vpn_tunnels") or []),
        attrs_fn=lambda s: {"tunnels": s.get("vpn_tunnels") or []},
        exists_fn=lambda s: "vpn_tunnels" in s,
    ),
    SparkSystemDescription(
        key="next_contract_expiry",
        icon="mdi:license",
        device_class=SensorDeviceClass.TIMESTAMP,
        value_fn=_expiry,
        attrs_fn=lambda s: {
            "contracts": s.get("contracts") or [],
            "expired_contracts": s.get("expired_contracts") or [],
        },
        exists_fn=lambda s: "contracts" in s,
    ),
)


class SparkSystemSensor(SparkEntity, SensorEntity):
    """Value from a read-only clish show command."""

    entity_description: SparkSystemDescription
    _unrecorded_attributes = frozenset({"contracts", "tunnels", "expired_contracts"})

    def __init__(self, coordinator: SparkCoordinator, description: SparkSystemDescription) -> None:
        super().__init__(coordinator, description.key)
        self.entity_description = description
        self._attr_translation_key = description.key

    def _system(self) -> dict[str, Any]:
        system = dict(self.coordinator.data.system)
        system["_fetched"] = self.coordinator.data.system_fetched.get("show internet-connections")
        return system

    @property
    def native_value(self) -> Any:
        return self.entity_description.value_fn(self._system())

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        if not self.entity_description.attrs_fn:
            return None
        return self.entity_description.attrs_fn(self._system())


class SparkSyslogSensor(SparkEntity, SensorEntity):
    """Syslog messages received from the gateway since start (preparation stage)."""

    _attr_translation_key = "syslog_messages"
    _attr_icon = "mdi:math-log"
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: SparkCoordinator) -> None:
        super().__init__(coordinator, "syslog_messages")
        self._pending = None

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(self.coordinator.syslog.async_add_listener(self._message))

    def _message(self) -> None:
        # many messages per second are possible: write the state at most every 5 s
        if self._pending is None:
            self._pending = self.hass.loop.call_later(5, self._write)

    def _write(self) -> None:
        self._pending = None
        self.async_write_ha_state()

    @property
    def native_value(self) -> int:
        return self.coordinator.syslog.received

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        rx = self.coordinator.syslog
        return {
            "port": rx.port,
            "dropped": rx.dropped,
            "rate_limited": rx.rate_limited,
            "forwarded": rx.forwarded,
            "forward_to": f"{rx.forward_addr[0]}:{rx.forward_addr[1]}" if rx.forward_addr else None,
            "allowed_senders": rx.allowed,
            "events_suppressed": rx.analyzer.events_suppressed,
            "products": dict(rx.product_counts),
            "last_received": rx.last_received.isoformat() if rx.last_received else None,
        }


class SparkLogSensor(SparkEntity, SensorEntity):
    """Value derived from the syslog stream (rolling windows)."""

    _attr_state_class = SensorStateClass.MEASUREMENT
    _unrecorded_attributes = frozenset({"recent", "recent_malware", "top_sources", "top_services", "history", "daily"})

    def __init__(self, coordinator: SparkCoordinator, key: str, icon: str) -> None:
        super().__init__(coordinator, key)
        self._attr_translation_key = key
        self._attr_icon = icon
        self._pending = None

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(self.coordinator.syslog.async_add_listener(self._message))

    def _message(self) -> None:
        if self._pending is None:
            self._pending = self.hass.loop.call_later(10, self._write)

    def _write(self) -> None:
        self._pending = None
        self.async_write_ha_state()

    @property
    def _a(self):
        return self.coordinator.syslog.analyzer

    @property
    def native_value(self) -> int | None:
        now = dt_util.utcnow()
        match self._attr_translation_key:
            case "ips_events_1h":
                return self._a.ips_count(now)
            case "firewall_drops_1h":
                return self._a.drop_count(now)
            case "scanned_hosts":
                return self._a.anti_malware.get("scan_hosts_day")
            case "detected_threats":
                return self._a.anti_malware.get("unique_detected_day")
            case "detections_30d":
                return len(self._a.history_since(now, 30))
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        now = dt_util.utcnow()
        am = self._a.anti_malware
        match self._attr_translation_key:
            case "ips_events_1h":
                return {"last_24h": self._a.ips_count(now, 24), "ignored": self._a.ignored,
                        **{f"last_hour_{d}": self._a.ips_count(now, 1, d) for d in ("inbound", "internal", "outbound")},
                        **{f"last_24h_{d}": self._a.ips_count(now, 24, d) for d in ("inbound", "internal", "outbound")},
                        "recent": list(reversed(self._a.recent_ips))}
            case "firewall_drops_1h":
                return {"last_24h": self._a.drop_count(now, 24),
                        "top_sources": self._a.drop_top(1), "top_services": self._a.drop_top(2)}
            case "scanned_hosts":
                return {"hour": am.get("scan_hosts_hour"), "week": am.get("scan_hosts_week")}
            case "detected_threats":
                return {"hour": am.get("unique_detected_hour"), "week": am.get("unique_detected_week"),
                        "recent_malware": list(reversed(self._a.recent_malware))}
            case "detections_30d":
                return {"last_24h": len(self._a.history_since(now, 1)), "last_7d": len(self._a.history_since(now, 7)),
                        "ips_by_direction": {f"{d}d": self._a.direction_counts(now, d) for d in (1, 7, 30)},
                        "daily": self._a.daily_counts(now, 30),
                        # newest first, bounded so the state stays small for the frontend
                        "history": list(reversed(self._a.history_since(now, 30)))[:100]}
        return {}


# --------------------------------------------------------------- telemetry values --
def _tm_cpu(st) -> tuple[float | None, dict]:
    idle = {lab.get("cpu"): v for lab, v in st.values("system_cpu_utilization") if lab.get("state") == "idle"}
    if not idle:
        return None, {}
    cores = {f"core_{k}": round(100 - v, 1) for k, v in sorted(idle.items())}
    return round(sum(cores.values()) / len(cores), 1), cores


def _tm_memory(st) -> tuple[float | None, dict]:
    used = next((v for lab, v in st.values("system_memory_usage") if lab.get("state") == "used"), None)
    limit = next((v for _, v in st.values("system_memory_limit")), None)
    if used is None or not limit:
        return None, {}
    return round(100 * used / limit, 1), {"used_mb": round(used / 1e6), "total_mb": round(limit / 1e6)}


def _tm_interfaces(st) -> dict[str, dict[str, float]]:
    out: dict[str, dict[str, float]] = {}
    for key, metric in (("rx_mbit", "system_network_interface_rx_throughput_bs"),
                        ("tx_mbit", "system_network_interface_tx_throughput_bs")):
        for lab, v in st.values(metric):
            name = lab.get("if_name") or lab.get("name")
            if name and name not in ("lo", "TOTAL"):
                out.setdefault(name, {})[key] = round(v / 1e6, 2)
    return out


def _tm_wan(st, key: str) -> float | None:
    ifs = _tm_interfaces(st)
    for name in ("ppp0", "WAN"):
        if name in ifs and key in ifs[name]:
            return ifs[name][key]
    return None


def _tm_sdwan(st, metric: str) -> tuple[float | None, dict]:
    vals = st.values(metric)
    if not vals:
        return None, {}
    per_isp: dict[str, float] = {}
    for lab, v in vals:
        per_isp.setdefault(lab.get("isp_name", "?"), v)
    first = next(iter(per_isp.values()))
    return first, {"per_isp": per_isp}


def _tm_sum(st, metric: str, label: str) -> tuple[float | None, dict]:
    vals = st.values(metric)
    if not vals:
        return None, {}
    return sum(v for _, v in vals), {lab.get(label, "?"): v for lab, v in vals}


def _tm_drops(st) -> tuple[float | None, dict]:
    """Dropped packets since boot (sum of all reasons) + per reason; rate as attribute."""
    vals = st.values("system_traffic_dropped")
    if not vals:
        return None, {}
    by_reason: dict[str, int] = {}
    for lab, v in vals:
        reason = lab.get("type") or lab.get("component") or "?"
        by_reason[reason] = by_reason.get(reason, 0) + int(v)
    rate = sum(v for _, v in st.values("system_traffic_dropped_rate"))
    return sum(by_reason.values()), {
        "by_reason": dict(sorted(by_reason.items(), key=lambda x: -x[1])),
        "rate_per_s": rate,
    }


def _tm_boot(st):
    up = next((v for _, v in st.values("system_uptime")), None)
    if up is None or st.last_received is None:
        return None, {}
    boot = (st.last_received - timedelta(seconds=up)).replace(second=0, microsecond=0)
    # keep the previous value unless it really changed (reboot) – avoids ±1 min flapping
    prev = getattr(st, "boot_cache", None)
    if prev is None or abs((boot - prev).total_seconds()) > 180:
        st.boot_cache = prev = boot
    return prev, {}


@dataclass(frozen=True, kw_only=True)
class SparkTelemetryDescription(SensorEntityDescription):
    """Value derived from the gateway's OpenTelemetry metrics."""

    value_fn: Callable[[Any], tuple[Any, dict]]


TELEMETRY_SENSORS: tuple[SparkTelemetryDescription, ...] = (
    SparkTelemetryDescription(key="cpu_load", icon="mdi:cpu-64-bit", native_unit_of_measurement=PERCENTAGE,
                              state_class=SensorStateClass.MEASUREMENT, suggested_display_precision=0, value_fn=_tm_cpu),
    SparkTelemetryDescription(key="memory_load", icon="mdi:memory", native_unit_of_measurement=PERCENTAGE,
                              state_class=SensorStateClass.MEASUREMENT, suggested_display_precision=0, value_fn=_tm_memory),
    SparkTelemetryDescription(key="boot_time", icon="mdi:restart", device_class=SensorDeviceClass.TIMESTAMP,
                              entity_category=EntityCategory.DIAGNOSTIC, value_fn=_tm_boot),
    SparkTelemetryDescription(key="connections", icon="mdi:connection", state_class=SensorStateClass.MEASUREMENT,
                              value_fn=lambda st: _tm_sum(st, "system_network_connections", "component")),
    SparkTelemetryDescription(key="connection_rate", icon="mdi:speedometer", native_unit_of_measurement="1/s",
                              state_class=SensorStateClass.MEASUREMENT,
                              value_fn=lambda st: _tm_sum(st, "system_network_connections_rate", "component")),
    SparkTelemetryDescription(key="drops", icon="mdi:wall-fire", state_class=SensorStateClass.TOTAL_INCREASING,
                              value_fn=lambda st: _tm_drops(st)),
    SparkTelemetryDescription(key="wan_download", icon="mdi:download-network", device_class=SensorDeviceClass.DATA_RATE,
                              native_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND, state_class=SensorStateClass.MEASUREMENT,
                              suggested_display_precision=1,
                              value_fn=lambda st: (_tm_wan(st, "rx_mbit"), {"interfaces": _tm_interfaces(st)})),
    SparkTelemetryDescription(key="wan_upload", icon="mdi:upload-network", device_class=SensorDeviceClass.DATA_RATE,
                              native_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND, state_class=SensorStateClass.MEASUREMENT,
                              suggested_display_precision=1, value_fn=lambda st: (_tm_wan(st, "tx_mbit"), {})),
    SparkTelemetryDescription(key="wan_latency", icon="mdi:timer-outline", device_class=SensorDeviceClass.DURATION,
                              native_unit_of_measurement=UnitOfTime.MILLISECONDS, state_class=SensorStateClass.MEASUREMENT,
                              value_fn=lambda st: _tm_sdwan(st, "sdwan_modules_latency")),
    SparkTelemetryDescription(key="wan_jitter", icon="mdi:sine-wave", device_class=SensorDeviceClass.DURATION,
                              native_unit_of_measurement=UnitOfTime.MILLISECONDS, state_class=SensorStateClass.MEASUREMENT,
                              value_fn=lambda st: _tm_sdwan(st, "sdwan_modules_jitter")),
    SparkTelemetryDescription(key="wan_packet_loss", icon="mdi:package-variant-remove", native_unit_of_measurement=PERCENTAGE,
                              state_class=SensorStateClass.MEASUREMENT,
                              value_fn=lambda st: _tm_sdwan(st, "sdwan_modules_packetloss")),
)


class SparkTelemetryValueSensor(SparkEntity, SensorEntity):
    """Sensor fed by the OpenTelemetry receiver."""

    entity_description: SparkTelemetryDescription
    _unrecorded_attributes = frozenset({"interfaces", "per_isp", "by_reason"})

    def __init__(self, coordinator: SparkCoordinator, description: SparkTelemetryDescription) -> None:
        super().__init__(coordinator, description.key)
        self.entity_description = description
        self._attr_translation_key = description.key
        self._pending = None

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        store = self.coordinator.telemetry
        store.listeners.append(self._message)
        self.async_on_remove(lambda: store.listeners.remove(self._message))

    def _message(self) -> None:
        if self._pending is None:
            self._pending = self.hass.loop.call_later(10, self._write)

    def _write(self) -> None:
        self._pending = None
        self.async_write_ha_state()

    @property
    def native_value(self) -> Any:
        return self.entity_description.value_fn(self.coordinator.telemetry)[0]

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        return self.entity_description.value_fn(self.coordinator.telemetry)[1] or None


class SparkTelemetrySensor(SparkEntity, SensorEntity):
    """Time series received via OpenTelemetry (collection stage)."""

    _attr_translation_key = "telemetry_series"
    _attr_icon = "mdi:chart-timeline-variant"
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _unrecorded_attributes = frozenset({"metrics"})

    def __init__(self, coordinator: SparkCoordinator) -> None:
        super().__init__(coordinator, "telemetry_series")
        self._pending = None

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        store = self.coordinator.telemetry
        store.listeners.append(self._message)
        self.async_on_remove(lambda: store.listeners.remove(self._message))

    def _message(self) -> None:
        if self._pending is None:
            self._pending = self.hass.loop.call_later(10, self._write)

    def _write(self) -> None:
        self._pending = None
        self.async_write_ha_state()

    @property
    def native_value(self) -> int:
        return len(self.coordinator.telemetry.series)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        st = self.coordinator.telemetry
        names = st.metric_names()
        return {
            "requests": st.requests,
            "rejected": st.rejected,
            "dropped_series": st.dropped_series,
            "last_error": st.last_error,
            "last_received": st.last_received.isoformat() if st.last_received else None,
            "metrics": dict(list(names.items())[:150]),
        }


class SparkThreatMapSensor(SparkEntity, SensorEntity):
    """Countries attacking (inbound, 24 h) and receiving traffic (outbound) – data for the card's map."""

    _attr_translation_key = "threat_map"
    _attr_icon = "mdi:earth"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _unrecorded_attributes = frozenset({"inbound", "inbound_ips", "outbound_syslog", "outbound_report", "ticker", "attribution"})

    def __init__(self, coordinator: SparkCoordinator) -> None:
        super().__init__(coordinator, "threat_map")
        self._pending = None
        self._cache: tuple[float, dict[str, Any]] | None = None

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(self.coordinator.syslog.async_add_listener(self._message))

    def _message(self) -> None:
        if self._pending is None:
            self._pending = self.hass.loop.call_later(30, self._write)

    def _write(self) -> None:
        self._pending = None
        self.async_write_ha_state()

    def _data(self) -> dict[str, Any]:
        """Computed at most every 20 s (state and attributes share one result)."""
        mono = time.monotonic()
        if self._cache and mono - self._cache[0] < 20:
            return self._cache[1]
        data = self._compute()
        self._cache = (mono, data)
        return data

    def _compute(self) -> dict[str, Any]:
        geo, a = self.coordinator.geo, self.coordinator.syslog.analyzer
        if geo is None or not geo.ready:
            return {}
        now = dt_util.utcnow()
        inbound: dict[str, dict[str, int]] = {}
        ticker: list[dict[str, Any]] = []
        for t, src, svc in a.drops:  # 24 h window
            cc = geo.lookup(src)
            if cc:
                inbound.setdefault(cc, {"drops": 0, "ips": 0, "critical": 0})["drops"] += 1
        for t, src, svc in list(a.drops)[-12:]:
            if (cc := geo.lookup(src)):
                ticker.append({"time": t.isoformat(), "cc": cc, "type": "drop", "name": svc or "", "src": src})
        ips_by_period: dict[str, dict[str, int]] = {}
        for days in (1, 7, 30):
            counts: dict[str, int] = {}
            for item in a.history_since(now, days, "ips_attack"):
                if item.get("direction") == "inbound" and (cc := geo.lookup(item.get("src"))):
                    counts[cc] = counts.get(cc, 0) + 1
                    if days == 1:
                        e = inbound.setdefault(cc, {"drops": 0, "ips": 0, "critical": 0})
                        e["ips"] += 1
                        e["critical"] += item.get("severity") == "critical"
            ips_by_period[f"{days}d"] = counts
        for item in list(a.history_since(now, 1, "ips_attack"))[-8:]:
            if item.get("direction") == "inbound" and (cc := geo.lookup(item.get("src"))):
                ticker.append({"time": item["time"], "cc": cc, "type": "ips", "name": item.get("name"),
                               "severity": item.get("severity"), "src": item.get("src")})
        ticker.sort(key=lambda x: x["time"], reverse=True)
        out_sys: dict[str, dict[str, Any]] = {}
        for t, dst, nbytes, name in a.outbound:
            if (cc := geo.lookup(dst)):
                e = out_sys.setdefault(cc, {"bytes": 0, "count": 0, "names": {}})
                e["bytes"] += nbytes
                e["count"] += 1
                e["names"][name] = e["names"].get(name, 0) + nbytes
        for e in out_sys.values():
            e["names"] = [n for n, _ in sorted(e["names"].items(), key=lambda x: -x[1])[:5]]
        out_rep: dict[str, dict[str, dict[str, Any]]] = {}
        for period, report in self.coordinator.data.reports.items():
            per: dict[str, dict[str, Any]] = {}
            for item in _chart(report if isinstance(report, dict) else {}, "topSitesByBandwidthChart"):
                ip = (self.coordinator.site_ips.get(str(item.get("name") or "").lower()) or (None,))[0]
                if (cc := geo.lookup(ip)):
                    e = per.setdefault(cc, {"bytes": 0, "sites": []})
                    e["bytes"] += item.get("bytes") or 0
                    e["sites"].append(item.get("name"))
            out_rep[period] = per
        return {"inbound": inbound, "inbound_ips": ips_by_period, "outbound_syslog": out_sys,
                "outbound_report": out_rep, "ticker": ticker[:20]}

    @property
    def native_value(self) -> int | None:
        data = self._data()
        return len(data["inbound"]) if data else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {**self._data(), "attribution": "IP Geolocation by DB-IP (CC BY 4.0); map: Natural Earth"}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SparkConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    registry = er.async_get(hass)
    entities: list[SensorEntity] = [SparkBladesSensor(coordinator)]
    blades = _blades(coordinator)
    for report_type in coordinator.report_types:
        entities.append(SparkReportTimestampSensor(coordinator, report_type))
        report = coordinator.data.reports.get(report_type) or {}
        # Create what this report type (and firmware) delivers – and keep sensors that were created
        # before: some values (e.g. IPS in the hourly report) only appear now and then.
        entities.extend(
            SparkSummarySensor(coordinator, report_type, description, blades)
            for description in SUMMARY_SENSORS
            if _has_summary(report, description.header)
            or registry.async_get_entity_id(
                "sensor", DOMAIN, f"{entry.unique_id}_{report_type}_{description.key}"
            )
        )
    system = coordinator.data.system
    entities.extend(
        SparkSystemSensor(coordinator, d) for d in SYSTEM_SENSORS if d.exists_fn(system)
    )
    if coordinator.telemetry is not None:
        entities.append(SparkTelemetrySensor(coordinator))
        entities.extend(SparkTelemetryValueSensor(coordinator, d) for d in TELEMETRY_SENSORS)
    if coordinator.syslog:
        entities.append(SparkSyslogSensor(coordinator))
        if coordinator.geo is not None:
            entities.append(SparkThreatMapSensor(coordinator))
        entities += [
            SparkLogSensor(coordinator, "ips_events_1h", "mdi:shield-alert"),
            SparkLogSensor(coordinator, "firewall_drops_1h", "mdi:wall-fire"),
            SparkLogSensor(coordinator, "scanned_hosts", "mdi:radar"),
            SparkLogSensor(coordinator, "detected_threats", "mdi:biohazard"),
            SparkLogSensor(coordinator, "detections_30d", "mdi:shield-search"),
        ]
    async_add_entities(entities)
