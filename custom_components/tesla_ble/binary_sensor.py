"""Binary sensor platform for Tesla BLE."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import logging
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, ClosureState, VehicleSleepStatus
from .coordinator import TeslaBLECoordinator
from .protocol import VehicleState

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, kw_only=True)
class TeslaBLEBinarySensorEntityDescription(BinarySensorEntityDescription):
    """Describes Tesla BLE binary sensor entity."""

    value_fn: Callable[[VehicleState], bool | None]


BINARY_SENSORS: tuple[TeslaBLEBinarySensorEntityDescription, ...] = (
    TeslaBLEBinarySensorEntityDescription(
        key="front_driver_door",
        name="Front Driver Door",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=lambda state: state.front_driver_door != ClosureState.CLOSED
        if state.front_driver_door != ClosureState.UNKNOWN
        else None,
    ),
    TeslaBLEBinarySensorEntityDescription(
        key="front_passenger_door",
        name="Front Passenger Door",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=lambda state: state.front_passenger_door != ClosureState.CLOSED
        if state.front_passenger_door != ClosureState.UNKNOWN
        else None,
    ),
    TeslaBLEBinarySensorEntityDescription(
        key="rear_driver_door",
        name="Rear Driver Door",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=lambda state: state.rear_driver_door != ClosureState.CLOSED
        if state.rear_driver_door != ClosureState.UNKNOWN
        else None,
    ),
    TeslaBLEBinarySensorEntityDescription(
        key="rear_passenger_door",
        name="Rear Passenger Door",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=lambda state: state.rear_passenger_door != ClosureState.CLOSED
        if state.rear_passenger_door != ClosureState.UNKNOWN
        else None,
    ),
    TeslaBLEBinarySensorEntityDescription(
        key="front_trunk",
        name="Frunk",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=lambda state: state.front_trunk != ClosureState.CLOSED
        if state.front_trunk != ClosureState.UNKNOWN
        else None,
    ),
    TeslaBLEBinarySensorEntityDescription(
        key="rear_trunk",
        name="Trunk",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=lambda state: state.rear_trunk != ClosureState.CLOSED
        if state.rear_trunk != ClosureState.UNKNOWN
        else None,
    ),
    TeslaBLEBinarySensorEntityDescription(
        key="charge_port",
        name="Charge Port",
        device_class=BinarySensorDeviceClass.DOOR,
        value_fn=lambda state: state.charge_port != ClosureState.CLOSED
        if state.charge_port != ClosureState.UNKNOWN
        else None,
    ),
    TeslaBLEBinarySensorEntityDescription(
        key="user_present",
        name="User Present",
        device_class=BinarySensorDeviceClass.PRESENCE,
        value_fn=lambda state: state.user_present,
    ),
    TeslaBLEBinarySensorEntityDescription(
        key="vehicle_awake",
        name="Vehicle Awake",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        value_fn=lambda state: state.sleep_status == VehicleSleepStatus.AWAKE
        if state.sleep_status != VehicleSleepStatus.UNKNOWN
        else None,
    ),
    TeslaBLEBinarySensorEntityDescription(
        key="connected",
        name="BLE Connected",
        device_class=BinarySensorDeviceClass.CONNECTIVITY,
        value_fn=lambda state: state.connected,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Tesla BLE binary sensor entities."""
    coordinator: TeslaBLECoordinator = hass.data[DOMAIN][entry.entry_id]

    async_add_entities(
        TeslaBLEBinarySensor(coordinator, description) for description in BINARY_SENSORS
    )


class TeslaBLEBinarySensor(
    CoordinatorEntity[TeslaBLECoordinator], BinarySensorEntity
):
    """Tesla BLE binary sensor."""

    entity_description: TeslaBLEBinarySensorEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: TeslaBLECoordinator,
        description: TeslaBLEBinarySensorEntityDescription,
    ) -> None:
        """Initialize the binary sensor."""
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{coordinator.vin}_{description.key}"
        self._attr_device_info = coordinator.device_info

    @property
    def is_on(self) -> bool | None:
        """Return true if the binary sensor is on."""
        if self.coordinator.data is None:
            return None
        return self.entity_description.value_fn(self.coordinator.data)
