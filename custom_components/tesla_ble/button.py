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
    TeslaBLEButtonEntityDescription(
        key="open_trunk",
        name="Open Trunk",
        icon="mdi:car-back",
        press_fn=lambda coordinator: coordinator.async_open_trunk(),
    ),
    TeslaBLEButtonEntityDescription(
        key="open_frunk",
        name="Open Frunk",
        icon="mdi:car",
        press_fn=lambda coordinator: coordinator.async_open_frunk(),
    ),
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
