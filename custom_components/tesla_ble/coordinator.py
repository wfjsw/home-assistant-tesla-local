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
    TESLA_ALT_SERVICE_UUID,
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
        self._cancel_bluetooth_callbacks: list[callback] = []
        self._connection_lock = asyncio.Lock()

        # Diagnostic data
        self.rssi: int | None = None
        self.ble_address: str | None = None
        self.last_seen: float | None = None
        self.connection_count: int = 0
        self.last_error: str | None = None

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
        # Only process events for our device
        if self._ble_device and service_info.address != self._ble_device.address:
            return

        import time

        _LOGGER.debug(
            "Bluetooth event: %s, %s, RSSI: %s",
            service_info.address,
            change,
            service_info.rssi,
        )
        self.set_ble_device(service_info.device)

        # Update diagnostic data
        self.rssi = service_info.rssi
        self.ble_address = service_info.address
        self.last_seen = time.time()

        # Notify listeners of the update (for RSSI sensor)
        if self.data:
            self.async_set_updated_data(self.data)

    async def async_start(self) -> None:
        """Start the coordinator and register for Bluetooth updates."""
        # Register callbacks for both known Tesla service UUIDs
        for service_uuid in [TESLA_SERVICE_UUID, TESLA_ALT_SERVICE_UUID]:
            cancel = bluetooth.async_register_callback(
                self.hass,
                self._async_handle_bluetooth_event,
                BluetoothCallbackMatcher(service_uuid=service_uuid),
                bluetooth.BluetoothScanningMode.ACTIVE,
            )
            self._cancel_bluetooth_callbacks.append(cancel)

        # Try to find device via Bluetooth
        service_info = bluetooth.async_last_service_info(
            self.hass, self._ble_device.address if self._ble_device else "", True
        )
        if service_info:
            self.set_ble_device(service_info.device)

    async def async_stop(self) -> None:
        """Stop the coordinator and unregister callbacks."""
        for cancel in self._cancel_bluetooth_callbacks:
            cancel()
        self._cancel_bluetooth_callbacks.clear()

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

                    # Track successful connections
                    self.connection_count += 1

                # Establish session if needed
                if not self.vehicle.has_session:
                    if not await self.vehicle.establish_session():
                        raise UpdateFailed("Failed to establish session")

                # Get vehicle status
                state = await self.vehicle.get_vehicle_status()
                self.last_error = None  # Clear error on success
                return state

            except Exception as ex:
                _LOGGER.error("Error updating vehicle data: %s", ex)
                self.last_error = str(ex)
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

    async def async_close_trunk(self) -> bool:
        """Close the trunk."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.close_trunk()

    async def async_actuate_trunk(self) -> bool:
        """Actuate (toggle) the trunk."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.actuate_trunk()

    async def async_open_tonneau(self) -> bool:
        """Open the tonneau (Cybertruck)."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.open_tonneau()

    async def async_close_tonneau(self) -> bool:
        """Close the tonneau (Cybertruck)."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.close_tonneau()

    async def async_stop_tonneau(self) -> bool:
        """Stop the tonneau (Cybertruck)."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.stop_tonneau()

    # Horn and lights

    async def async_honk_horn(self) -> bool:
        """Honk the horn."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.honk_horn()

    async def async_flash_lights(self) -> bool:
        """Flash the lights."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.flash_lights()

    # Windows

    async def async_vent_windows(self) -> bool:
        """Vent all windows."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.vent_windows()

    async def async_close_windows(self) -> bool:
        """Close all windows."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.close_windows()

    # Climate control

    async def async_climate_on(self) -> bool:
        """Turn on climate control."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.climate_on()

    async def async_climate_off(self) -> bool:
        """Turn off climate control."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.climate_off()

    async def async_set_temperature(
        self, driver_temp: float, passenger_temp: float | None = None
    ) -> bool:
        """Set cabin temperature."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.set_temperature(driver_temp, passenger_temp)

    async def async_set_steering_wheel_heater(self, enabled: bool) -> bool:
        """Turn steering wheel heater on or off."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.set_steering_wheel_heater(enabled)

    # Charging

    async def async_charge_start(self) -> bool:
        """Start charging."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.charge_start()

    async def async_charge_stop(self) -> bool:
        """Stop charging."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.charge_stop()

    async def async_set_charge_limit(self, percent: int) -> bool:
        """Set charge limit percentage."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.set_charge_limit(percent)

    async def async_set_charging_amps(self, amps: int) -> bool:
        """Set charging current in amps."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.set_charging_amps(amps)

    # Security

    async def async_set_sentry_mode(self, enabled: bool) -> bool:
        """Enable or disable sentry mode."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.set_sentry_mode(enabled)

    # Media

    async def async_media_next_track(self) -> bool:
        """Skip to next media track."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.media_next_track()

    async def async_media_previous_track(self) -> bool:
        """Skip to previous media track."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.media_previous_track()

    async def async_media_toggle_playback(self) -> bool:
        """Toggle media playback."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.media_toggle_playback()

    async def async_media_volume_up(self) -> bool:
        """Increase media volume."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.media_volume_up()

    async def async_media_volume_down(self) -> bool:
        """Decrease media volume."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.media_volume_down()

    async def async_set_volume(self, volume: float) -> bool:
        """Set media volume."""
        async with self._connection_lock:
            if not self.vehicle.is_connected:
                await self.vehicle.connect()
            if not self.vehicle.has_session:
                await self.vehicle.establish_session()
            return await self.vehicle.set_volume(volume)
