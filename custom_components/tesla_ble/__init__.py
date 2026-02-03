"""Tesla BLE integration for Home Assistant."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .const import (
    DOMAIN,
    CONF_VIN,
    CONF_PRIVATE_KEY,
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    TESLA_SERVICE_UUID,
)
from .coordinator import TeslaBLECoordinator
from .protocol import TeslaBLEVehicle
from .services import async_setup_services, async_unload_services

if TYPE_CHECKING:
    from homeassistant.components.bluetooth import BluetoothServiceInfoBleak

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [
    Platform.BINARY_SENSOR,
    Platform.BUTTON,
    Platform.LOCK,
    Platform.SENSOR,
]


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Set up the Tesla BLE component."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Tesla BLE from a config entry."""
    address = entry.data[CONF_ADDRESS]
    vin = entry.data[CONF_VIN]
    private_key_hex = entry.data[CONF_PRIVATE_KEY]
    private_key = bytes.fromhex(private_key_hex)

    _LOGGER.info("Setting up Tesla BLE for VIN: %s", vin[-6:])

    # Find the BLE device
    ble_device = bluetooth.async_ble_device_from_address(
        hass, address, connectable=True
    )

    if not ble_device:
        # Try to find by service UUID
        service_infos = bluetooth.async_discovered_service_info(hass, True)
        for service_info in service_infos:
            if (
                service_info.address == address
                or TESLA_SERVICE_UUID.lower()
                in [str(uuid).lower() for uuid in service_info.service_uuids]
            ):
                ble_device = service_info.device
                break

    if not ble_device:
        raise ConfigEntryNotReady(
            f"Could not find Tesla BLE device with address {address}"
        )

    # Create the vehicle instance
    vehicle = TeslaBLEVehicle(ble_device, private_key, vin)

    # Get scan interval from options (or use default)
    scan_interval = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)

    # Create the coordinator
    coordinator = TeslaBLECoordinator(hass, entry, vehicle, vin, scan_interval)
    coordinator.set_ble_device(ble_device)

    # Start the coordinator
    await coordinator.async_start()

    # Perform initial data fetch
    await coordinator.async_config_entry_first_refresh()

    # Store coordinator
    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = coordinator

    # Set up platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Set up services (only once)
    if len(hass.data[DOMAIN]) == 1:
        await async_setup_services(hass)

    # Register update listener for options
    entry.async_on_unload(entry.add_update_listener(async_update_options))

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        coordinator: TeslaBLECoordinator = hass.data[DOMAIN].pop(entry.entry_id)
        await coordinator.async_stop()

        # Unload services when last entry is removed
        if not hass.data[DOMAIN]:
            await async_unload_services(hass)

    return unload_ok


async def async_update_options(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update."""
    coordinator: TeslaBLECoordinator = hass.data[DOMAIN][entry.entry_id]

    # Update scan interval if changed
    new_scan_interval = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    coordinator.set_scan_interval(new_scan_interval)
