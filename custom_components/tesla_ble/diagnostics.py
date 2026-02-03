"""Diagnostics support for Tesla BLE."""
from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS
from homeassistant.core import HomeAssistant

from .const import DOMAIN, CONF_PRIVATE_KEY, CONF_PUBLIC_KEY, CONF_VIN
from .coordinator import TeslaBLECoordinator

TO_REDACT = {
    CONF_ADDRESS,
    CONF_PRIVATE_KEY,
    CONF_PUBLIC_KEY,
    CONF_VIN,
}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    coordinator: TeslaBLECoordinator = hass.data[DOMAIN][entry.entry_id]

    state = coordinator.data
    state_dict = {}
    if state:
        state_dict = {
            "connected": state.connected,
            "lock_state": state.lock_state.name if hasattr(state.lock_state, 'name') else state.lock_state,
            "sleep_status": state.sleep_status.name if hasattr(state.sleep_status, 'name') else state.sleep_status,
            "user_present": state.user_present,
            "front_driver_door": state.front_driver_door.name if hasattr(state.front_driver_door, 'name') else state.front_driver_door,
            "front_passenger_door": state.front_passenger_door.name if hasattr(state.front_passenger_door, 'name') else state.front_passenger_door,
            "rear_driver_door": state.rear_driver_door.name if hasattr(state.rear_driver_door, 'name') else state.rear_driver_door,
            "rear_passenger_door": state.rear_passenger_door.name if hasattr(state.rear_passenger_door, 'name') else state.rear_passenger_door,
            "front_trunk": state.front_trunk.name if hasattr(state.front_trunk, 'name') else state.front_trunk,
            "rear_trunk": state.rear_trunk.name if hasattr(state.rear_trunk, 'name') else state.rear_trunk,
            "charge_port": state.charge_port.name if hasattr(state.charge_port, 'name') else state.charge_port,
            "last_update": state.last_update,
        }

    return {
        "config_entry": async_redact_data(entry.as_dict(), TO_REDACT),
        "vehicle_state": state_dict,
        "is_connected": coordinator.vehicle.is_connected,
        "has_session": coordinator.vehicle.has_session,
    }
