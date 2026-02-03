"""Services for Tesla BLE integration."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import voluptuous as vol

from homeassistant.core import HomeAssistant, ServiceCall, callback
from homeassistant.helpers import config_validation as cv, device_registry as dr

from .const import DOMAIN
from .coordinator import TeslaBLECoordinator

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry

_LOGGER = logging.getLogger(__name__)

SERVICE_WAKE = "wake"
SERVICE_LOCK = "lock"
SERVICE_UNLOCK = "unlock"
SERVICE_OPEN_TRUNK = "open_trunk"
SERVICE_OPEN_FRUNK = "open_frunk"
SERVICE_OPEN_CHARGE_PORT = "open_charge_port"
SERVICE_CLOSE_CHARGE_PORT = "close_charge_port"

SERVICE_SCHEMA = vol.Schema(
    {
        vol.Required("device_id"): cv.string,
    }
)


def _get_coordinator(
    hass: HomeAssistant, device_id: str
) -> TeslaBLECoordinator | None:
    """Get coordinator from device ID."""
    device_registry = dr.async_get(hass)
    device = device_registry.async_get(device_id)

    if not device:
        _LOGGER.error("Device %s not found", device_id)
        return None

    # Find the config entry for this device
    for entry_id in device.config_entries:
        if entry_id in hass.data.get(DOMAIN, {}):
            return hass.data[DOMAIN][entry_id]

    _LOGGER.error("No Tesla BLE coordinator found for device %s", device_id)
    return None


async def async_setup_services(hass: HomeAssistant) -> None:
    """Set up Tesla BLE services."""

    async def handle_wake(call: ServiceCall) -> None:
        """Handle wake service call."""
        device_id = call.data["device_id"]
        coordinator = _get_coordinator(hass, device_id)
        if coordinator:
            await coordinator.async_wake()

    async def handle_lock(call: ServiceCall) -> None:
        """Handle lock service call."""
        device_id = call.data["device_id"]
        coordinator = _get_coordinator(hass, device_id)
        if coordinator:
            await coordinator.async_lock()

    async def handle_unlock(call: ServiceCall) -> None:
        """Handle unlock service call."""
        device_id = call.data["device_id"]
        coordinator = _get_coordinator(hass, device_id)
        if coordinator:
            await coordinator.async_unlock()

    async def handle_open_trunk(call: ServiceCall) -> None:
        """Handle open trunk service call."""
        device_id = call.data["device_id"]
        coordinator = _get_coordinator(hass, device_id)
        if coordinator:
            await coordinator.async_open_trunk()

    async def handle_open_frunk(call: ServiceCall) -> None:
        """Handle open frunk service call."""
        device_id = call.data["device_id"]
        coordinator = _get_coordinator(hass, device_id)
        if coordinator:
            await coordinator.async_open_frunk()

    async def handle_open_charge_port(call: ServiceCall) -> None:
        """Handle open charge port service call."""
        device_id = call.data["device_id"]
        coordinator = _get_coordinator(hass, device_id)
        if coordinator:
            await coordinator.async_open_charge_port()

    async def handle_close_charge_port(call: ServiceCall) -> None:
        """Handle close charge port service call."""
        device_id = call.data["device_id"]
        coordinator = _get_coordinator(hass, device_id)
        if coordinator:
            await coordinator.async_close_charge_port()

    hass.services.async_register(
        DOMAIN, SERVICE_WAKE, handle_wake, schema=SERVICE_SCHEMA
    )
    hass.services.async_register(
        DOMAIN, SERVICE_LOCK, handle_lock, schema=SERVICE_SCHEMA
    )
    hass.services.async_register(
        DOMAIN, SERVICE_UNLOCK, handle_unlock, schema=SERVICE_SCHEMA
    )
    hass.services.async_register(
        DOMAIN, SERVICE_OPEN_TRUNK, handle_open_trunk, schema=SERVICE_SCHEMA
    )
    hass.services.async_register(
        DOMAIN, SERVICE_OPEN_FRUNK, handle_open_frunk, schema=SERVICE_SCHEMA
    )
    hass.services.async_register(
        DOMAIN, SERVICE_OPEN_CHARGE_PORT, handle_open_charge_port, schema=SERVICE_SCHEMA
    )
    hass.services.async_register(
        DOMAIN, SERVICE_CLOSE_CHARGE_PORT, handle_close_charge_port, schema=SERVICE_SCHEMA
    )


async def async_unload_services(hass: HomeAssistant) -> None:
    """Unload Tesla BLE services."""
    hass.services.async_remove(DOMAIN, SERVICE_WAKE)
    hass.services.async_remove(DOMAIN, SERVICE_LOCK)
    hass.services.async_remove(DOMAIN, SERVICE_UNLOCK)
    hass.services.async_remove(DOMAIN, SERVICE_OPEN_TRUNK)
    hass.services.async_remove(DOMAIN, SERVICE_OPEN_FRUNK)
    hass.services.async_remove(DOMAIN, SERVICE_OPEN_CHARGE_PORT)
    hass.services.async_remove(DOMAIN, SERVICE_CLOSE_CHARGE_PORT)
