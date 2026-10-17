"""Sensors for Check Point Quantum Spark security reports."""

from __future__ import annotations

from datetime import datetime

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import SparkConfigEntry, SparkCoordinator

PARALLEL_UPDATES = 0


class SparkEntity(CoordinatorEntity[SparkCoordinator]):
    """Common base: one device per gateway."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: SparkCoordinator, key: str) -> None:
        super().__init__(coordinator)
        entry = coordinator.config_entry
        self._attr_unique_id = f"{entry.unique_id}_{key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, entry.unique_id)},
            manufacturer="Check Point",
            model="Quantum Spark",
            name="Quantum Spark",
            configuration_url=f"https://{entry.data['host']}:{entry.data['port']}",
        )


class SparkReportTimestampSensor(SparkEntity, SensorEntity):
    """When a report type was fetched last."""

    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, coordinator: SparkCoordinator, report_type: str) -> None:
        super().__init__(coordinator, f"{report_type}_report_time")
        self._report_type = report_type
        self._attr_translation_key = f"{report_type}_report_time"

    @property
    def native_value(self) -> datetime | None:
        return self.coordinator.data.fetched.get(self._report_type)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: SparkConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    async_add_entities(
        SparkReportTimestampSensor(coordinator, rt) for rt in coordinator.report_types
    )
