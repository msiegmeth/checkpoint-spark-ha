"""Binary sensors for Check Point Quantum Spark."""

from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .const import CONF_MONITORED_BLADES, EVENT_REPORT_ORDER
from .coordinator import SparkConfigEntry
from .report import _summary
from .sensor import SparkEntity, _blades

PARALLEL_UPDATES = 0

_INFECTION_HEADERS = {
    "infected_hosts": "TOTAL_INFECTED_HOSTS",
    "infected_servers": "TOTAL_INFECTED_SERVERS",
    "critically_infected_hosts": "TOTAL_CRITICAL_INFECTED_HOSTS",
}


class SparkThreatActiveSensor(SparkEntity, BinarySensorEntity):
    """On while the most current report shows infected hosts or servers."""

    _attr_translation_key = "threat_active"
    _attr_device_class = BinarySensorDeviceClass.PROBLEM

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator, "threat_active")

    def _report(self) -> tuple[str | None, dict[str, Any]]:
        reports = self.coordinator.data.reports
        for rt in EVENT_REPORT_ORDER:
            if isinstance(reports.get(rt), dict):
                return rt, reports[rt]
        return None, {}

    def _counts(self) -> dict[str, int | None]:
        _, report = self._report()
        return {k: _summary(report, h) for k, h in _INFECTION_HEADERS.items()}

    @property
    def is_on(self) -> bool | None:
        counts = [v for v in self._counts().values() if v is not None]
        return any(v > 0 for v in counts) if counts else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        rt, _ = self._report()
        return {"report_type": rt, **self._counts()}


class SparkBladeFailureSensor(SparkEntity, BinarySensorEntity):
    """On when a monitored software blade is not enabled."""

    _attr_translation_key = "blade_failure"
    _attr_device_class = BinarySensorDeviceClass.PROBLEM

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator, "blade_failure")

    def _monitored(self) -> list[str]:
        return list(self.coordinator.config_entry.options.get(CONF_MONITORED_BLADES, []))

    def _missing(self) -> list[str] | None:
        blades = _blades(self.coordinator)
        if not blades:
            return None
        return [b for b in self._monitored() if not blades.get(b, False)]

    @property
    def is_on(self) -> bool | None:
        missing = self._missing()
        return None if missing is None else bool(missing)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"monitored": self._monitored(), "disabled": self._missing() or []}


class SparkInternetSensor(SparkEntity, BinarySensorEntity):
    """Primary internet connection active (from 'show internet-connections')."""

    _attr_translation_key = "internet"
    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator, "internet")

    def _conn(self) -> dict[str, Any]:
        conns = self.coordinator.data.system.get("internet") or []
        return conns[0] if conns else {}

    @property
    def is_on(self) -> bool | None:
        return self._conn().get("active")

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {k: self._conn().get(k) for k in ("name", "type", "interface", "link_status")}


class SparkHardwareProblemSensor(SparkEntity, BinarySensorEntity):
    """On when a voltage, temperature or eMMC check in 'show diag' is not OK."""

    _attr_translation_key = "hardware_problem"
    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator, "hardware_problem")

    @property
    def is_on(self) -> bool | None:
        ok = self.coordinator.data.system.get("hardware_ok")
        return None if ok is None else not ok

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {"problems": self.coordinator.data.system.get("hardware_problems") or []}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SparkConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    entities: list[BinarySensorEntity] = [
        SparkThreatActiveSensor(coordinator),
        SparkBladeFailureSensor(coordinator),
    ]
    system = coordinator.data.system
    if system.get("internet"):
        entities.append(SparkInternetSensor(coordinator))
    if "hardware_ok" in system:
        entities.append(SparkHardwareProblemSensor(coordinator))
    async_add_entities(entities)
