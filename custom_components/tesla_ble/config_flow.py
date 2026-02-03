"""Config flow for Tesla BLE integration."""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.components import bluetooth
from homeassistant.components.bluetooth import BluetoothServiceInfoBleak
from homeassistant.const import CONF_ADDRESS, CONF_NAME
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import config_validation as cv

from .const import (
    DOMAIN,
    CONF_VIN,
    CONF_PRIVATE_KEY,
    CONF_PUBLIC_KEY,
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    MIN_SCAN_INTERVAL,
    MAX_SCAN_INTERVAL,
    TESLA_SERVICE_UUIDS,
    is_tesla_device_name,
)
from .protocol.crypto import generate_key_pair, vin_from_local_name, compute_vin_hash

_LOGGER = logging.getLogger(__name__)


class TeslaBLEConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for Tesla BLE."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize the config flow."""
        self._discovery_info: BluetoothServiceInfoBleak | None = None
        self._discovered_devices: dict[str, BluetoothServiceInfoBleak] = {}
        self._vin: str | None = None
        self._private_key: bytes | None = None
        self._public_key: bytes | None = None
        self._address: str | None = None
        self._name: str | None = None

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> FlowResult:
        """Handle the Bluetooth discovery step."""
        _LOGGER.debug("Bluetooth discovery: %s", discovery_info)

        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()

        self._discovery_info = discovery_info
        self._address = discovery_info.address
        self._name = discovery_info.name

        # Try to extract VIN hash from local name
        vin_hash = vin_from_local_name(discovery_info.name)
        if vin_hash:
            self._vin = vin_hash

        return await self.async_step_bluetooth_confirm()

    async def async_step_bluetooth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Confirm discovery."""
        assert self._discovery_info is not None

        if user_input is not None:
            return await self.async_step_generate_key()

        self._set_confirm_only()
        return self.async_show_form(
            step_id="bluetooth_confirm",
            description_placeholders={
                "name": self._name or "Unknown",
                "address": self._address or "Unknown",
            },
        )

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle the initial step - scan for devices or enter VIN manually."""
        errors: dict[str, str] = {}

        if user_input is not None:
            # Check if user wants to enter VIN manually
            if user_input.get("manual_entry"):
                return await self.async_step_manual_vin()

            address = user_input.get(CONF_ADDRESS)
            if address and address in self._discovered_devices:
                self._discovery_info = self._discovered_devices[address]
                self._address = address
                self._name = self._discovery_info.name

                vin_hash = vin_from_local_name(self._discovery_info.name)
                if vin_hash:
                    self._vin = vin_hash

                await self.async_set_unique_id(address)
                self._abort_if_unique_id_configured()

                return await self.async_step_generate_key()

            errors["base"] = "no_device_selected"

        # Scan for Tesla BLE devices
        self._discovered_devices = {}

        # Get all discovered devices - check service UUIDs and name pattern
        for service_info in bluetooth.async_discovered_service_info(self.hass, True):
            # Check if any service UUID matches Tesla's known UUIDs
            service_uuids_lower = {str(uuid).lower() for uuid in service_info.service_uuids}
            has_tesla_uuid = bool(service_uuids_lower & TESLA_SERVICE_UUIDS)

            # Check if name matches Tesla pattern (S<16 hex chars>C)
            has_tesla_name = is_tesla_device_name(service_info.name)

            if has_tesla_uuid or has_tesla_name:
                self._discovered_devices[service_info.address] = service_info
                _LOGGER.debug(
                    "Found Tesla device: %s (name=%s, uuid_match=%s, name_match=%s)",
                    service_info.address,
                    service_info.name,
                    has_tesla_uuid,
                    has_tesla_name,
                )

        if not self._discovered_devices:
            # No devices found - offer manual VIN entry
            return self.async_show_form(
                step_id="user",
                data_schema=vol.Schema(
                    {
                        vol.Required("manual_entry", default=True): bool,
                    }
                ),
                errors={"base": "no_devices_found"},
                description_placeholders={
                    "manual_hint": "Enter your VIN to search for your vehicle.",
                },
            )

        # Build device selection list with manual entry option
        device_options = {
            addr: f"{info.name or 'Unknown'} ({addr})"
            for addr, info in self._discovered_devices.items()
        }

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Optional(CONF_ADDRESS): vol.In(device_options),
                    vol.Optional("manual_entry", default=False): bool,
                }
            ),
            errors=errors,
        )

    async def async_step_manual_vin(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle manual VIN entry to find vehicle."""
        errors: dict[str, str] = {}

        if user_input is not None:
            vin = user_input.get(CONF_VIN, "").strip().upper()

            if not vin or len(vin) != 17:
                errors[CONF_VIN] = "invalid_vin"
            else:
                self._vin = vin

                # Compute expected BLE local name from VIN
                expected_name = compute_vin_hash(vin)
                _LOGGER.debug("Looking for vehicle with BLE name: %s", expected_name)

                # Search for device by expected name or service UUID
                found_device = None
                for service_info in bluetooth.async_discovered_service_info(
                    self.hass, True
                ):
                    # Match by exact name (VIN hash)
                    if service_info.name == expected_name:
                        found_device = service_info
                        _LOGGER.info("Found vehicle by VIN hash: %s", expected_name)
                        break

                    # Check service UUIDs
                    service_uuids_lower = {
                        str(uuid).lower() for uuid in service_info.service_uuids
                    }
                    has_tesla_uuid = bool(service_uuids_lower & TESLA_SERVICE_UUIDS)

                    # Check name pattern
                    has_tesla_name = is_tesla_device_name(service_info.name)

                    if has_tesla_uuid or has_tesla_name:
                        # Could be our vehicle - save as potential match
                        if found_device is None:
                            found_device = service_info

                if found_device:
                    self._discovery_info = found_device
                    self._address = found_device.address
                    self._name = found_device.name

                    await self.async_set_unique_id(found_device.address)
                    self._abort_if_unique_id_configured()

                    return await self.async_step_generate_key()
                else:
                    # Vehicle not found - allow proceeding anyway for later setup
                    errors["base"] = "vehicle_not_found"

        return self.async_show_form(
            step_id="manual_vin",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_VIN): str,
                }
            ),
            errors=errors,
        )

    async def async_step_generate_key(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Generate or import a key pair."""
        errors: dict[str, str] = {}

        if user_input is not None:
            if user_input.get("generate_new", True):
                # Generate new key pair
                self._private_key, self._public_key = await self.hass.async_add_executor_job(
                    generate_key_pair
                )
                return await self.async_step_pair_key()
            else:
                # Import existing key
                return await self.async_step_import_key()

        return self.async_show_form(
            step_id="generate_key",
            data_schema=vol.Schema(
                {
                    vol.Required("generate_new", default=True): bool,
                }
            ),
            description_placeholders={
                "name": self._name or "Unknown",
            },
            errors=errors,
        )

    async def async_step_import_key(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Import an existing key pair."""
        errors: dict[str, str] = {}

        if user_input is not None:
            try:
                # Parse hex-encoded private key
                private_key_hex = user_input.get("private_key", "").strip()
                self._private_key = bytes.fromhex(private_key_hex)

                # Re-derive public key from private key
                from .protocol.crypto import load_private_key, get_public_key_bytes

                private_key = load_private_key(self._private_key)
                self._public_key = get_public_key_bytes(private_key)

                return await self.async_step_pair_key()
            except Exception:
                _LOGGER.exception("Failed to import key")
                errors["base"] = "invalid_key"

        return self.async_show_form(
            step_id="import_key",
            data_schema=vol.Schema(
                {
                    vol.Required("private_key"): str,
                }
            ),
            errors=errors,
        )

    async def async_step_pair_key(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Pair the key with the vehicle."""
        errors: dict[str, str] = {}

        if user_input is not None:
            vin = user_input.get(CONF_VIN, "").strip().upper()

            if not vin or len(vin) != 17:
                errors[CONF_VIN] = "invalid_vin"
            else:
                self._vin = vin

                # Try to send add-key request to the vehicle
                # The vehicle will then prompt the user to tap their NFC card
                try:
                    from .protocol import TeslaBLEVehicle

                    assert self._discovery_info is not None
                    assert self._private_key is not None

                    vehicle = TeslaBLEVehicle(
                        self._discovery_info.device,
                        self._private_key,
                        vin,
                    )

                    # Connect and send add key request
                    if await vehicle.connect():
                        try:
                            # Send the add-key request FIRST
                            # This triggers the vehicle to prompt for NFC tap
                            success = await vehicle.add_key_to_whitelist()

                            if success:
                                _LOGGER.info(
                                    "Add-key request sent. Vehicle should now prompt for NFC tap."
                                )
                                # Now show the tap key card step for user to confirm
                                return await self.async_step_tap_key_card()
                            else:
                                errors["base"] = "add_key_request_failed"
                        finally:
                            await vehicle.disconnect()
                    else:
                        errors["base"] = "cannot_connect"

                except Exception:
                    _LOGGER.exception("Failed to send add-key request")
                    errors["base"] = "pairing_failed"

        return self.async_show_form(
            step_id="pair_key",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_VIN): str,
                }
            ),
            description_placeholders={
                "public_key": self._public_key.hex() if self._public_key else "Unknown",
            },
            errors=errors,
        )

    async def async_step_tap_key_card(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> FlowResult:
        """Wait for user to tap key card and verify key was added."""
        errors: dict[str, str] = {}

        if user_input is not None:
            # User confirmed they tapped the key card
            # Now verify the key was actually added by establishing a session
            try:
                from .protocol import TeslaBLEVehicle

                assert self._discovery_info is not None
                assert self._private_key is not None
                assert self._vin is not None

                vehicle = TeslaBLEVehicle(
                    self._discovery_info.device,
                    self._private_key,
                    self._vin,
                )

                if await vehicle.connect():
                    try:
                        # Try to establish a session - this verifies our key is whitelisted
                        # If the key wasn't added, session establishment will fail
                        if await vehicle.establish_session():
                            _LOGGER.info("Session established - key successfully added to whitelist")
                            # Key is valid and whitelisted, create entry
                            return self.async_create_entry(
                                title=f"Tesla {self._vin[-6:]}",
                                data={
                                    CONF_ADDRESS: self._address,
                                    CONF_VIN: self._vin,
                                    CONF_PRIVATE_KEY: self._private_key.hex(),
                                    CONF_PUBLIC_KEY: self._public_key.hex(),
                                    CONF_NAME: self._name,
                                },
                            )
                        else:
                            # Session failed - key probably wasn't added
                            _LOGGER.warning("Session establishment failed - key may not have been added")
                            errors["base"] = "key_not_added"
                    finally:
                        await vehicle.disconnect()
                else:
                    errors["base"] = "cannot_connect"

            except asyncio.TimeoutError:
                errors["base"] = "timeout"
            except Exception:
                _LOGGER.exception("Failed to verify key")
                errors["base"] = "verification_failed"

        return self.async_show_form(
            step_id="tap_key_card",
            data_schema=vol.Schema({}),
            description_placeholders={},
            errors=errors,
        )

    async def async_step_already_paired(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Handle case where key is already paired - just set up the entry."""
        errors: dict[str, str] = {}

        if user_input is not None:
            vin = user_input.get(CONF_VIN, "").strip().upper()

            if not vin or len(vin) != 17:
                errors[CONF_VIN] = "invalid_vin"
            else:
                self._vin = vin

                # Verify we can connect and establish session
                try:
                    from .protocol import TeslaBLEVehicle

                    assert self._discovery_info is not None
                    assert self._private_key is not None

                    vehicle = TeslaBLEVehicle(
                        self._discovery_info.device,
                        self._private_key,
                        vin,
                    )

                    if await vehicle.connect():
                        try:
                            if await vehicle.establish_session():
                                # Session established - key is valid
                                return self.async_create_entry(
                                    title=f"Tesla {self._vin[-6:]}",
                                    data={
                                        CONF_ADDRESS: self._address,
                                        CONF_VIN: self._vin,
                                        CONF_PRIVATE_KEY: self._private_key.hex(),
                                        CONF_PUBLIC_KEY: self._public_key.hex(),
                                        CONF_NAME: self._name,
                                    },
                                )
                            else:
                                errors["base"] = "key_not_paired"
                        finally:
                            await vehicle.disconnect()
                    else:
                        errors["base"] = "cannot_connect"

                except Exception:
                    _LOGGER.exception("Failed to verify key")
                    errors["base"] = "verification_failed"

        return self.async_show_form(
            step_id="already_paired",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_VIN): str,
                }
            ),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        """Get the options flow for this handler."""
        return TeslaBLEOptionsFlowHandler(config_entry)


class TeslaBLEOptionsFlowHandler(config_entries.OptionsFlow):
    """Handle Tesla BLE options."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self.config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Manage the options."""
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_SCAN_INTERVAL,
                        default=self.config_entry.options.get(
                            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
                        ),
                    ): vol.All(
                        vol.Coerce(int),
                        vol.Range(min=MIN_SCAN_INTERVAL, max=MAX_SCAN_INTERVAL),
                    ),
                }
            ),
        )
