"""Button platform for Tesla BLE."""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
import logging
from typing import Any

from homeassistant.components.button import ButtonEntity, ButtonEntityDescription
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import TeslaBLECoordinator

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, kw_only=True)
class TeslaBLEButtonEntityDescription(ButtonEntityDescription):
    """Describes Tesla BLE button entity."""

    press_fn: Callable[[TeslaBLECoordinator], Awaitable[bool]]


BUTTONS: tuple[TeslaBLEButtonEntityDescription, ...] = (
    TeslaBLEButtonEntityDescription(
        key="wake",
        name="Wake",
        icon="mdi:car-electric",
        press_fn=lambda coordinator: coordinator.async_wake(),
    ),
    # Trunk operations
    TeslaBLEButtonEntityDescription(
        key="open_trunk",
        name="Open Trunk",
        icon="mdi:car-back",
        press_fn=lambda coordinator: coordinator.async_open_trunk(),
    ),
    TeslaBLEButtonEntityDescription(
        key="close_trunk",
        name="Close Trunk",
        icon="mdi:car-back",
        press_fn=lambda coordinator: coordinator.async_close_trunk(),
    ),
    TeslaBLEButtonEntityDescription(
        key="actuate_trunk",
        name="Actuate Trunk",
        icon="mdi:car-back",
        press_fn=lambda coordinator: coordinator.async_actuate_trunk(),
    ),
    TeslaBLEButtonEntityDescription(
        key="open_frunk",
        name="Open Frunk",
        icon="mdi:car",
        press_fn=lambda coordinator: coordinator.async_open_frunk(),
    ),
    # Charge port
    TeslaBLEButtonEntityDescription(
        key="open_charge_port",
        name="Open Charge Port",
        icon="mdi:ev-plug-type2",
        press_fn=lambda coordinator: coordinator.async_open_charge_port(),
    ),
    TeslaBLEButtonEntityDescription(
        key="close_charge_port",
        name="Close Charge Port",
        icon="mdi:ev-plug-type2",
        press_fn=lambda coordinator: coordinator.async_close_charge_port(),
    ),
    # Tonneau (Cybertruck)
    TeslaBLEButtonEntityDescription(
        key="open_tonneau",
        name="Open Tonneau",
        icon="mdi:truck-cargo-container",
        press_fn=lambda coordinator: coordinator.async_open_tonneau(),
    ),
    TeslaBLEButtonEntityDescription(
        key="close_tonneau",
        name="Close Tonneau",
        icon="mdi:truck-cargo-container",
        press_fn=lambda coordinator: coordinator.async_close_tonneau(),
    ),
    TeslaBLEButtonEntityDescription(
        key="stop_tonneau",
        name="Stop Tonneau",
        icon="mdi:truck-cargo-container",
        press_fn=lambda coordinator: coordinator.async_stop_tonneau(),
    ),
    # Horn and lights
    TeslaBLEButtonEntityDescription(
        key="honk_horn",
        name="Honk Horn",
        icon="mdi:bullhorn",
        press_fn=lambda coordinator: coordinator.async_honk_horn(),
    ),
    TeslaBLEButtonEntityDescription(
        key="flash_lights",
        name="Flash Lights",
        icon="mdi:car-light-high",
        press_fn=lambda coordinator: coordinator.async_flash_lights(),
    ),
    # Windows
    TeslaBLEButtonEntityDescription(
        key="vent_windows",
        name="Vent Windows",
        icon="mdi:window-open-variant",
        press_fn=lambda coordinator: coordinator.async_vent_windows(),
    ),
    TeslaBLEButtonEntityDescription(
        key="close_windows",
        name="Close Windows",
        icon="mdi:window-closed-variant",
        press_fn=lambda coordinator: coordinator.async_close_windows(),
    ),
    # Climate control
    TeslaBLEButtonEntityDescription(
        key="climate_on",
        name="Climate On",
        icon="mdi:air-conditioner",
        press_fn=lambda coordinator: coordinator.async_climate_on(),
    ),
    TeslaBLEButtonEntityDescription(
        key="climate_off",
        name="Climate Off",
        icon="mdi:air-conditioner",
        press_fn=lambda coordinator: coordinator.async_climate_off(),
    ),
    # Charging
    TeslaBLEButtonEntityDescription(
        key="charge_start",
        name="Start Charging",
        icon="mdi:battery-charging",
        press_fn=lambda coordinator: coordinator.async_charge_start(),
    ),
    TeslaBLEButtonEntityDescription(
        key="charge_stop",
        name="Stop Charging",
        icon="mdi:battery-charging",
        press_fn=lambda coordinator: coordinator.async_charge_stop(),
    ),
    # Media controls
    TeslaBLEButtonEntityDescription(
        key="media_next_track",
        name="Media Next Track",
        icon="mdi:skip-next",
        press_fn=lambda coordinator: coordinator.async_media_next_track(),
    ),
    TeslaBLEButtonEntityDescription(
        key="media_previous_track",
        name="Media Previous Track",
        icon="mdi:skip-previous",
        press_fn=lambda coordinator: coordinator.async_media_previous_track(),
    ),
    TeslaBLEButtonEntityDescription(
        key="media_toggle_playback",
        name="Media Toggle Playback",
        icon="mdi:play-pause",
        press_fn=lambda coordinator: coordinator.async_media_toggle_playback(),
    ),
    TeslaBLEButtonEntityDescription(
        key="media_volume_up",
        name="Media Volume Up",
        icon="mdi:volume-plus",
        press_fn=lambda coordinator: coordinator.async_media_volume_up(),
    ),
    TeslaBLEButtonEntityDescription(
        key="media_volume_down",
        name="Media Volume Down",
        icon="mdi:volume-minus",
        press_fn=lambda coordinator: coordinator.async_media_volume_down(),
    ),
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up Tesla BLE button entities."""
    coordinator: TeslaBLECoordinator = hass.data[DOMAIN][entry.entry_id]

    async_add_entities(
        TeslaBLEButton(coordinator, description) for description in BUTTONS
    )


class TeslaBLEButton(CoordinatorEntity[TeslaBLECoordinator], ButtonEntity):
    """Tesla BLE button."""

    entity_description: TeslaBLEButtonEntityDescription
    _attr_has_entity_name = True

    def __init__(
        self,
        coordinator: TeslaBLECoordinator,
        description: TeslaBLEButtonEntityDescription,
    ) -> None:
        """Initialize the button."""
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_unique_id = f"{coordinator.vin}_{description.key}"
        self._attr_device_info = coordinator.device_info

    async def async_press(self) -> None:
        """Handle the button press."""
        _LOGGER.info("Pressing button: %s", self.entity_description.key)
        await self.entity_description.press_fn(self.coordinator)
