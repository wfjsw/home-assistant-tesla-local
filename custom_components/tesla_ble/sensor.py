"""Sensor platform for Tesla BLE."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
import logging
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
    EntityCategory,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from homeassistant.util import dt as dt_util

from .const import DOMAIN, VehicleLockState, VehicleSleepStatus
from .coordinator import TeslaBLECoordinator
from .protocol import VehicleState

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, kw_only=True)
class TeslaBLESensorEntityDescription(SensorEntityDescription):
    """Describes Tesla BLE sensor entity."""

    value_fn: Callable[[VehicleState], Any]


@dataclass(frozen=True, kw_only=True)
class TeslaBLEDiagnosticSensorEntityDescription(SensorEntityDescription):
    """Describes Tesla BLE diagnostic sensor entity."""

    value_fn: Callable[[TeslaBLECoordinator], Any]


SENSORS: tuple[TeslaBLESensorEntityDescription, ...] = (
    TeslaBLESensorEntityDescription(
        key="lock_state",
        name="Lock State",
        icon="mdi:car-door-lock",
        value_fn=lambda state: VehicleLockState(state.lock_state).name.lower().replace(
            "_", " "
        ).title(),
    ),
    TeslaBLESensorEntityDescription(
        key="sleep_status",
        name="Sleep Status",
        icon="mdi:sleep",
        value_fn=lambda state: VehicleSleepStatus(state.sleep_status)
        .name.lower()
        .replace("_", " ")
        .title(),
    ),
    TeslaBLESensorEntityDescription(
        key="last_update",
        name="Last Update",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda state: dt_util.utc_from_timestamp(state.last_update)
        if state.last_update > 0
        else None,
    ),
)


DIAGNOSTIC_SENSORS: tuple[TeslaBLEDiagnosticSensorEntityDescription, ...] = (
    TeslaBLEDiagnosticSensorEntityDescription(
        key="rssi",
        name="Signal Strength",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
        state_class=SensorStateClass.MEASUREMENT,
        entity_category=EntityCategory.DIAGNOSTIC,
        icon="mdi:bluetooth",
        value_fn=lambda coord: coord.rssi,
    ),
    TeslaBLEDiagnosticSensorEntityDescription(
        key="ble_address",
        name="BLE Address",
        icon="mdi:bluetooth",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda coord: coord.ble_address,
    ),
    TeslaBLEDiagnosticSensorEntityDescription(
        key="last_seen",
        name="Last Seen",
        device_class=SensorDeviceClass.TIMESTAMP,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda coord: dt_util.utc_from_timestamp(coord.last_seen)
        if coord.last_seen
        else None,
    ),
    TeslaBLEDiagnosticSensorEntityDescription(
        key="connection_count",
        name="Connection Count",
        icon="mdi:counter",
        state_class=SensorStateClass.TOTAL_INCREASING,
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda coord: coord.connection_count,
    ),
    TeslaBLEDiagnosticSensorEntityDescription(
        key="last_error",
        name="Last Error",
        icon="mdi:alert-circle",
        entity_category=EntityCategory.DIAGNOSTIC,
        value_fn=lambda coord: coord.last_error,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Tesla BLE sensor entities."""
    coordinator: TeslaBLECoordinator = hass.data[DOMAIN][entry.entry_id]

    entities: list[SensorEntity] = [
        TeslaBLESensor(coordinator, description) for description in SENSORS
    ]
    entities.extend(
        TeslaBLEDiagnosticSensor(coordinator, description)
        for description in DIAGNOSTIC_SENSORS
    )

    async_add_entities(entities)


class TeslaBLESensor(CoordinatorEntity[TeslaBLECoordinator], SensorEntity):
    """Tesla BLE sensor."""

    entity_description: TeslaBLESensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: TeslaBLECoordinator,
        description: TeslaBLESensorEntityDescription,
    ) -> None:
        """Initialize the sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{coordinator.vin}_{description.key}"
        self._attr_device_info = coordinator.device_info

    @property
    def native_value(self) -> Any:
        """Return the state of the sensor."""
        if self.coordinator.data is None:
            return None
        return self.entity_description.value_fn(self.coordinator.data)


class TeslaBLEDiagnosticSensor(CoordinatorEntity[TeslaBLECoordinator], SensorEntity):
    """Tesla BLE diagnostic sensor."""

    entity_description: TeslaBLEDiagnosticSensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: TeslaBLECoordinator,
        description: TeslaBLEDiagnosticSensorEntityDescription,
    ) -> None:
        """Initialize the diagnostic sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{coordinator.vin}_{description.key}"
        self._attr_device_info = coordinator.device_info

    @property
    def native_value(self) -> Any:
        """Return the state of the sensor."""
        return self.entity_description.value_fn(self.coordinator)
