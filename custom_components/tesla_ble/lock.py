"""Lock platform for Tesla BLE."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.lock import LockEntity, LockEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, VehicleLockState
from .coordinator import TeslaBLECoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Tesla BLE lock entities."""
    coordinator: TeslaBLECoordinator = hass.data[DOMAIN][entry.entry_id]

    async_add_entities([TeslaBLELock(coordinator)])


class TeslaBLELock(CoordinatorEntity[TeslaBLECoordinator], LockEntity):
    """Tesla BLE vehicle lock."""

    _attr_has_entity_name = True
    _attr_name = "Lock"

    def __init__(self, coordinator: TeslaBLECoordinator) -> None:
        """Initialize the lock."""
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.vin}_lock"
        self._attr_device_info = coordinator.device_info

    @property
    def is_locked(self) -> bool | None:
        """Return true if the lock is locked."""
        if self.coordinator.data is None:
            return None
        return self.coordinator.data.lock_state == VehicleLockState.LOCKED

    @property
    def is_locking(self) -> bool:
        """Return true if the lock is locking."""
        return False

    @property
    def is_unlocking(self) -> bool:
        """Return true if the lock is unlocking."""
        return False

    async def async_lock(self, **kwargs: Any) -> None:
        """Lock the vehicle."""
        _LOGGER.info("Locking vehicle")
        await self.coordinator.async_lock()

    async def async_unlock(self, **kwargs: Any) -> None:
        """Unlock the vehicle."""
        _LOGGER.info("Unlocking vehicle")
        await self.coordinator.async_unlock()
