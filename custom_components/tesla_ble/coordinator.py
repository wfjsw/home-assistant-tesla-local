"""Data update coordinator for Tesla BLE."""
from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from homeassistant.components import bluetooth
from homeassistant.components.bluetooth.match import BluetoothCallbackMatcher
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    DOMAIN,
    DEFAULT_SCAN_INTERVAL,
    TESLA_SERVICE_UUID,
)
from .protocol import TeslaBLEVehicle, VehicleState

if TYPE_CHECKING:
    from bleak.backends.device import BLEDevice
    from homeassistant.components.bluetooth import BluetoothServiceInfoBleak
    from homeassistant.config_entries import ConfigEntry

_LOGGER = logging.getLogger(__name__)


class TeslaBLECoordinator(DataUpdateCoordinator[VehicleState]):
    """Coordinator to manage Tesla BLE vehicle data."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        vehicle: TeslaBLEVehicle,
        vin: str,
        scan_interval: int = DEFAULT_SCAN_INTERVAL,
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            name=f"Tesla BLE {vin}",
            update_interval=timedelta(seconds=scan_interval),
        )
        self.entry = entry
        self.vehicle = vehicle
        self.vin = vin
        self._ble_device: BLEDevice | None = None
        self._cancel_bluetooth_callback: callback | None = None
        self._connection_lock = asyncio.Lock()

    def set_scan_interval(self, scan_interval: int) -> None:
        """Update the polling interval."""
        self.update_interval = timedelta(seconds=scan_interval)
        _LOGGER.info("Polling interval updated to %d seconds", scan_interval)

    @property
    def device_info(self) -> dict[str, Any]:
        """Return device info for this vehicle."""
        return {
            "identifiers": {(DOMAIN, self.vin)},
            "name": f"Tesla {self.vin[-6:]}",
            "manufacturer": "Tesla",
            "model": "Vehicle",
            "sw_version": "BLE",
        }

    def set_ble_device(self, ble_device: BLEDevice) -> None:
        """Update the BLE device reference."""
        self._ble_device = ble_device
        self.vehicle._ble_device = ble_device

    @callback
    def _async_handle_bluetooth_event(
        self,
        service_info: BluetoothServiceInfoBleak,
        change: bluetooth.BluetoothChange,
    ) -> None:
        """Handle Bluetooth advertisement events."""
        _LOGGER.debug(
            "Bluetooth event: %s, %s, RSSI: %s",
            service_info.address,
            change,
            service_info.rssi,
        )
        self.set_ble_device(service_info.device)

    async def async_start(self) -> None:
        """Start the coordinator and register for Bluetooth updates."""
        # Register callback for Bluetooth advertisements
        self._cancel_bluetooth_callback = bluetooth.async_register_callback(
            self.hass,
            self._async_handle_bluetooth_event,
            BluetoothCallbackMatcher(service_uuid=TESLA_SERVICE_UUID),
            bluetooth.BluetoothScanningMode.ACTIVE,
        )

        # Try to find device via Bluetooth
        service_info = bluetooth.async_last_service_info(
            self.hass, self._ble_device.address if self._ble_device else "", True
        )
        if service_info:
            self.set_ble_device(service_info.device)

    async def async_stop(self) -> None:
        """Stop the coordinator and unregister callbacks."""
        if self._cancel_bluetooth_callback:
            self._cancel_bluetooth_callback()
            self._cancel_bluetooth_callback = None

        await self.vehicle.disconnect()

    async def _async_update_data(self) -> VehicleState:
        """Fetch data from the vehicle."""
        async with self._connection_lock:
            try:
                # Try to connect if not connected
                if not self.vehicle.is_connected:
                    if not self._ble_device:
                        raise UpdateFailed("No BLE device available")

                    if not await self.vehicle.connect():
                        raise UpdateFailed("Failed to connect to vehicle")

                # Establish session if needed
                if not self.vehicle.has_session:
                    if not await self.vehicle.establish_session():
                        raise UpdateFailed("Failed to establish session")

                # Get vehicle status
                state = await self.vehicle.get_vehicle_status()
                return state

            except Exception as ex:
                _LOGGER.error("Error updating vehicle data: %s", ex)
                # Disconnect on error to force reconnection
                await self.vehicle.disconnect()
                raise UpdateFailed(f"Error communicating with vehicle: {ex}") from ex

    async def async_wake(self) -> bool:
        """Wake the vehicle."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            return await self.vehicle.wake()

    async def async_lock(self) -> bool:
        """Lock the vehicle."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            result = await self.vehicle.lock()
            if result:
                await self.async_request_refresh()
            return result

    async def async_unlock(self) -> bool:
        """Unlock the vehicle."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            result = await self.vehicle.unlock()
            if result:
                await self.async_request_refresh()
            return result

    async def async_open_trunk(self) -> bool:
        """Open the trunk."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.open_trunk()

    async def async_open_frunk(self) -> bool:
        """Open the frunk."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.open_frunk()

    async def async_open_charge_port(self) -> bool:
        """Open the charge port."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.open_charge_port()

    async def async_close_charge_port(self) -> bool:
        """Close the charge port."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.close_charge_port()
