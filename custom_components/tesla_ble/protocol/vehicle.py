"""Tesla BLE Vehicle control implementation."""
from __future__ import annotations

import asyncio
import logging
import os
import struct
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable

from bleak import BleakClient
from bleak.exc import BleakError
from bleak_retry_connector import establish_connection

from ..const import (
    TESLA_RX_CHAR_UUID,
    TESLA_TX_CHAR_UUID,
    KeyFormFactor,
    Domain,
    GenericError,
    OperationStatus,
    RKEAction,
    ClosureMoveType,
    VehicleLockState,
    VehicleSleepStatus,
    ClosureState,
    InformationRequestType,
)
from .crypto import TeslaCrypto
from .messages import (
    RoutableMessage,
    Destination,
    SessionInfoRequest,
    SessionInfo,
    SignatureData,
    VCSECMessage,
    InformationRequest,
    RKEActionMessage,
    ClosureMoveRequest,
    VCSECResponse,
    WhitelistOperation,
    KeyMetadata,
)

if TYPE_CHECKING:
    from bleak.backends.device import BLEDevice
    from home_assistant.components.bluetooth import BluetoothServiceInfoBleak

_LOGGER = logging.getLogger(__name__)


@dataclass
class VehicleState:
    """Current state of the vehicle."""

    connected: bool = False
    lock_state: VehicleLockState = VehicleLockState.UNLOCKED
    sleep_status: VehicleSleepStatus = VehicleSleepStatus.UNKNOWN
    user_present: bool = False
    front_driver_door: ClosureState = ClosureState.UNKNOWN
    front_passenger_door: ClosureState = ClosureState.UNKNOWN
    rear_driver_door: ClosureState = ClosureState.UNKNOWN
    rear_passenger_door: ClosureState = ClosureState.UNKNOWN
    front_trunk: ClosureState = ClosureState.UNKNOWN
    rear_trunk: ClosureState = ClosureState.UNKNOWN
    charge_port: ClosureState = ClosureState.UNKNOWN
    last_update: float = 0.0


class TeslaBLEVehicle:
    """Tesla vehicle BLE interface."""

    def __init__(
        self,
        ble_device: BLEDevice,
        private_key: bytes,
        vin: str | None = None,
    ) -> None:
        """Initialize Tesla BLE vehicle.

        Args:
            ble_device: The BLE device to connect to.
            private_key: Private key bytes (DER format).
            vin: Vehicle identification number (optional).
        """
        self._ble_device = ble_device
        self._vin = vin
        self._crypto = TeslaCrypto(private_key)
        self._client: BleakClient | None = None
        self._state = VehicleState()
        self._rx_buffer: bytearray = bytearray()
        self._expected_length: int = 0
        self._pending_requests: dict[bytes, asyncio.Future[bytes]] = {}
        self._unsolicited_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._lock = asyncio.Lock()
        self._disconnect_callbacks: list[Callable[[], None]] = []

    @property
    def state(self) -> VehicleState:
        """Return current vehicle state."""
        return self._state

    @property
    def public_key(self) -> bytes:
        """Return our public key."""
        return self._crypto.public_key_bytes

    @property
    def is_connected(self) -> bool:
        """Return True if connected to vehicle."""
        return self._client is not None and self._client.is_connected

    @property
    def has_session(self) -> bool:
        """Return True if we have an active session."""
        return self._crypto.has_session

    def register_disconnect_callback(self, callback: Callable[[], None]) -> None:
        """Register a callback for disconnect events."""
        self._disconnect_callbacks.append(callback)

    def _on_disconnect(self, client: BleakClient) -> None:
        """Handle disconnect event."""
        _LOGGER.info("Disconnected from vehicle")
        self._state.connected = False
        for callback in self._disconnect_callbacks:
            try:
                callback()
            except Exception as ex:  # noqa: BLE001
                _LOGGER.exception("Error in disconnect callback: %s", ex)

    def _notification_handler(
        self, characteristic: int, data: bytearray
    ) -> None:
        """Handle incoming notifications from the vehicle."""
        _LOGGER.debug("Received notification: %s", data.hex())

        # Check if this is the start of a new message
        if len(data) >= 2:
            # First two bytes are the message length (big-endian)
            if not self._rx_buffer:
                self._expected_length = struct.unpack(">H", data[:2])[0]
                self._rx_buffer.extend(data[2:])
            else:
                self._rx_buffer.extend(data)

            # Check if message is complete
            if len(self._rx_buffer) >= self._expected_length:
                message = bytes(self._rx_buffer[: self._expected_length])
                self._rx_buffer = bytearray(
                    self._rx_buffer[self._expected_length :]
                )
                self._dispatch_message(message)

    def _dispatch_message(self, message: bytes) -> None:
        """Route incoming message to the appropriate handler."""
        try:
            response = RoutableMessage.decode(message)
            request_uuid = response.request_uuid

            if request_uuid and request_uuid in self._pending_requests:
                # Deliver to waiting caller
                future = self._pending_requests[request_uuid]
                if not future.done():
                    future.set_result(message)
                else:
                    _LOGGER.debug("Future already done for UUID: %s", request_uuid.hex())
            else:
                # Unsolicited message - queue for other processing
                _LOGGER.debug(
                    "Received unsolicited message (UUID: %s): %s",
                    request_uuid.hex() if request_uuid else "none",
                    response,
                )
                try:
                    self._unsolicited_queue.put_nowait(message)
                except asyncio.QueueFull:
                    _LOGGER.warning("Unsolicited message queue full, dropping message")
        except Exception as ex:
            _LOGGER.warning("Failed to dispatch message: %s", ex)

    async def connect(self) -> bool:
        """Connect to the vehicle."""
        async with self._lock:
            if self.is_connected:
                return True

            try:
                _LOGGER.info("Connecting to vehicle: %s", self._ble_device.address)
                self._client = await establish_connection(
                    BleakClient,
                    self._ble_device,
                    self._ble_device.address,
                    disconnected_callback=self._on_disconnect,
                )

                # Subscribe to notifications
                await self._client.start_notify(
                    TESLA_RX_CHAR_UUID, self._notification_handler
                )

                self._state.connected = True
                _LOGGER.info("Connected to vehicle")
                return True

            except BleakError as ex:
                _LOGGER.error("Failed to connect: %s", ex)
                self._client = None
                return False

    async def disconnect(self) -> None:
        """Disconnect from the vehicle."""
        async with self._lock:
            if self._client and self._client.is_connected:
                try:
                    await self._client.stop_notify(TESLA_RX_CHAR_UUID)
                    await self._client.disconnect()
                except BleakError as ex:
                    _LOGGER.debug("Error during disconnect: %s", ex)
                finally:
                    self._client = None
                    self._state.connected = False

    async def _send_message(self, message: bytes) -> None:
        """Send a message to the vehicle."""
        if not self._client or not self._client.is_connected:
            raise ConnectionError("Not connected to vehicle")

        # Frame the message with length prefix
        framed = struct.pack(">H", len(message)) + message
        _LOGGER.debug("Sending message: %s", framed.hex())

        # Send in chunks if necessary (MTU is typically 512 for BLE)
        mtu = 512
        for i in range(0, len(framed), mtu):
            chunk = framed[i : i + mtu]
            await self._client.write_gatt_char(TESLA_TX_CHAR_UUID, chunk)

    async def _send_and_receive(
        self,
        message: RoutableMessage,
        timeout: float = 5.0,
    ) -> RoutableMessage | None:
        """Send a message and wait for correlated response."""
        request_uuid = message.request_uuid
        if not request_uuid:
            _LOGGER.warning("Message has no request_uuid, cannot correlate response")
            return None

        # Create a future to wait for the response
        loop = asyncio.get_event_loop()
        future: asyncio.Future[bytes] = loop.create_future()
        self._pending_requests[request_uuid] = future

        try:
            encoded = message.encode()
            await self._send_message(encoded)

            # Wait for correlated response
            response_data = await asyncio.wait_for(future, timeout)
            return RoutableMessage.decode(response_data)
        except asyncio.TimeoutError:
            _LOGGER.debug("Timeout waiting for response to UUID: %s", request_uuid.hex())
            return None
        finally:
            # Clean up the pending request
            self._pending_requests.pop(request_uuid, None)

    async def establish_session(self) -> bool:
        """Establish a secure session with the vehicle."""
        if not self.is_connected:
            if not await self.connect():
                return False

        # Generate a random challenge
        challenge = os.urandom(16)

        # Create session info request
        session_request = SessionInfoRequest(
            public_key=self._crypto.public_key_bytes,
            challenge=challenge,
        )

        message = RoutableMessage(
            to_destination=Destination(domain=Domain.VEHICLE_SECURITY),
            from_destination=Destination(routing_address=self._crypto.public_key_bytes),
            session_info_request=session_request,
            request_uuid=os.urandom(16),
        )

        _LOGGER.debug("Requesting session info")
        response = await self._send_and_receive(message, timeout=10.0)

        if not response or not response.session_info:
            _LOGGER.error("No session info in response")
            return False

        session_info = response.session_info

        # Set vehicle's public key and initialize session
        self._crypto.set_vehicle_public_key(session_info.public_key)
        self._crypto.initialize_session(
            epoch=session_info.epoch,
            time_zero=session_info.time_zero,
            counter=session_info.counter,
        )

        _LOGGER.info("Session established successfully")
        return True

    def _create_signed_message(
        self,
        payload: bytes,
        domain: Domain = Domain.VEHICLE_SECURITY,
    ) -> RoutableMessage:
        """Create a signed routable message."""
        sig_data = self._crypto.create_signature_data()

        # Encrypt the payload
        ciphertext, nonce, counter = self._crypto.encrypt_message(payload)

        signature = SignatureData(
            epoch=sig_data["epoch"],
            nonce=nonce,
            counter=counter,
            expires_at=sig_data["expires_at"],
            tag=ciphertext[-16:],  # AES-GCM tag is last 16 bytes
        )

        return RoutableMessage(
            to_destination=Destination(domain=domain),
            from_destination=Destination(routing_address=self._crypto.public_key_bytes),
            payload=ciphertext[:-16],  # Ciphertext without tag
            signature_data=signature,
            request_uuid=os.urandom(16),
        )

    async def _send_vcsec_command(
        self,
        vcsec_message: VCSECMessage,
        require_session: bool = True,
    ) -> VCSECResponse | None:
        """Send a VCSEC command and return the response."""
        if require_session and not self.has_session:
            if not await self.establish_session():
                raise ConnectionError("Failed to establish session")

        payload = vcsec_message.encode()

        if require_session:
            message = self._create_signed_message(payload, Domain.VEHICLE_SECURITY)
        else:
            message = RoutableMessage(
                to_destination=Destination(domain=Domain.VEHICLE_SECURITY),
                from_destination=Destination(
                    routing_address=self._crypto.public_key_bytes
                ),
                payload=payload,
                request_uuid=os.urandom(16),
            )

        response = await self._send_and_receive(message)
        if response and response.payload:
            return VCSECResponse.decode(response.payload)
        return None

    def _check_response_error(self, response: VCSECResponse | None) -> tuple[bool, str | None]:
        """Check response for errors.
        
        Returns:
            Tuple of (success, error_message)
        """
        if not response:
            return False, "No response from vehicle"
            
        # Check for nominal error first
        if response.nominal_error:
            error = response.nominal_error.generic_error
            if error != GenericError.NONE:
                error_msgs = {
                    GenericError.UNKNOWN: "Unknown error",
                    GenericError.CLOSURES_OPEN: "Closures are open",
                    GenericError.ALREADY_ON: "Already on",
                    GenericError.DISABLED_FOR_USER_COMMAND: "Disabled for user command",
                    GenericError.VEHICLE_NOT_IN_PARK: "Vehicle not in park",
                    GenericError.UNAUTHORIZED: "Unauthorized",
                    GenericError.NOT_ALLOWED_OVER_TRANSPORT: "Not allowed over this transport",
                }
                error_msg = error_msgs.get(error, f"Error code {error}")
                return False, error_msg
        
        # Check command status
        if response.command_status:
            if response.command_status.operation_status == OperationStatus.OK:
                return True, None
            elif response.command_status.operation_status == OperationStatus.ERROR:
                return False, "Command returned error status"
            elif response.command_status.operation_status == OperationStatus.WAIT:
                return False, "Command returned wait status"
        
        return False, "No command status in response"

    async def wake(self) -> bool:
        """Wake up the vehicle."""
        _LOGGER.info("Waking vehicle")
        vcsec = VCSECMessage(rke_action=RKEActionMessage(action=RKEAction.WAKE_VEHICLE))
        response = await self._send_vcsec_command(vcsec)

        success, error_msg = self._check_response_error(response)
        if not success:
            _LOGGER.warning("Wake failed: %s", error_msg)
        return success

    async def lock(self) -> bool:
        """Lock the vehicle."""
        _LOGGER.info("Locking vehicle")
        vcsec = VCSECMessage(rke_action=RKEActionMessage(action=RKEAction.LOCK))
        response = await self._send_vcsec_command(vcsec)

        success, error_msg = self._check_response_error(response)
        if not success:
            _LOGGER.warning("Lock failed: %s", error_msg)
        elif success:
            self._state.lock_state = VehicleLockState.LOCKED
        return success

    async def unlock(self) -> bool:
        """Unlock the vehicle."""
        _LOGGER.info("Unlocking vehicle")
        vcsec = VCSECMessage(rke_action=RKEActionMessage(action=RKEAction.UNLOCK))
        response = await self._send_vcsec_command(vcsec)

        success, error_msg = self._check_response_error(response)
        if not success:
            _LOGGER.warning("Unlock failed: %s", error_msg)
        elif success:
            self._state.lock_state = VehicleLockState.UNLOCKED
        return success

    async def open_trunk(self) -> bool:
        """Open the rear trunk."""
        _LOGGER.info("Opening trunk")
        vcsec = VCSECMessage(
            closure_move_request=ClosureMoveRequest(
                rear_trunk=ClosureMoveType.OPEN,
            )
        )
        response = await self._send_vcsec_command(vcsec)

        success, error_msg = self._check_response_error(response)
        if not success:
            _LOGGER.warning("Open trunk failed: %s", error_msg)
        return success

    async def open_frunk(self) -> bool:
        """Open the front trunk (frunk)."""
        _LOGGER.info("Opening frunk")
        vcsec = VCSECMessage(
            closure_move_request=ClosureMoveRequest(
                front_trunk=ClosureMoveType.OPEN,
            )
        )
        response = await self._send_vcsec_command(vcsec)

        success, error_msg = self._check_response_error(response)
        if not success:
            _LOGGER.warning("Open frunk failed: %s", error_msg)
        return success

    async def open_charge_port(self) -> bool:
        """Open the charge port."""
        _LOGGER.info("Opening charge port")
        vcsec = VCSECMessage(
            closure_move_request=ClosureMoveRequest(
                charge_port=ClosureMoveType.OPEN,
            )
        )
        response = await self._send_vcsec_command(vcsec)

        success, error_msg = self._check_response_error(response)
        if not success:
            _LOGGER.warning("Open charge port failed: %s", error_msg)
        return success

    async def close_charge_port(self) -> bool:
        """Close the charge port."""
        _LOGGER.info("Closing charge port")
        vcsec = VCSECMessage(
            closure_move_request=ClosureMoveRequest(
                charge_port=ClosureMoveType.CLOSE,
            )
        )
        response = await self._send_vcsec_command(vcsec)

        success, error_msg = self._check_response_error(response)
        if not success:
            _LOGGER.warning("Close charge port failed: %s", error_msg)
        return success

    async def get_vehicle_status(self) -> VehicleState:
        """Get current vehicle status."""
        _LOGGER.debug("Getting vehicle status")
        vcsec = VCSECMessage(
            information_request=InformationRequest(
                request_type=InformationRequestType.GET_STATUS
            )
        )
        response = await self._send_vcsec_command(vcsec)

        # Check for errors first
        if response and response.nominal_error:
            if response.nominal_error.generic_error != GenericError.NONE:
                _LOGGER.warning(
                    "Get vehicle status error: %s",
                    response.nominal_error.generic_error.name
                )
                return self._state

        if response and response.vehicle_status:
            status = response.vehicle_status
            self._state.lock_state = VehicleLockState(status.lock_state)
            self._state.sleep_status = VehicleSleepStatus(status.sleep_status)
            self._state.user_present = status.user_presence

            if status.closure_statuses:
                cs = status.closure_statuses
                self._state.front_driver_door = ClosureState(cs.front_driver_door)
                self._state.front_passenger_door = ClosureState(cs.front_passenger_door)
                self._state.rear_driver_door = ClosureState(cs.rear_driver_door)
                self._state.rear_passenger_door = ClosureState(cs.rear_passenger_door)
                self._state.front_trunk = ClosureState(cs.front_trunk)
                self._state.rear_trunk = ClosureState(cs.rear_trunk)
                self._state.charge_port = ClosureState(cs.charge_port)

            import time

            self._state.last_update = time.time()

        return self._state

    async def add_key_to_whitelist(
        self,
    ) -> bool:
        """Add our public key to the vehicle's whitelist.

        This requires the user to tap their key card on the center console
        within 30 seconds of sending the command.

        Returns:
            True if the key was added successfully.
        """
        _LOGGER.info("Adding key to vehicle whitelist")

        whitelist_op = WhitelistOperation(
            public_key_to_add=self._crypto.public_key_bytes,
            metadata_for_key=KeyMetadata(key_form_factor=KeyFormFactor.NFC_CARD),
        )

        vcsec = VCSECMessage(whitelist_operation=whitelist_op)

        # Send without requiring existing session
        message = RoutableMessage(
            to_destination=Destination(domain=Domain.VEHICLE_SECURITY),
            from_destination=Destination(
                routing_address=self._crypto.public_key_bytes
            ),
            payload=vcsec.encode(),
            request_uuid=os.urandom(16),
        )

        # Give user more time to tap their key card
        response = await self._send_and_receive(message, timeout=35.0)

        if response and response.payload:
            vcsec_response = VCSECResponse.decode(response.payload)
            success, error_msg = self._check_response_error(vcsec_response)
            if not success:
                _LOGGER.warning("Add key to whitelist failed: %s", error_msg)
            return success
        
        _LOGGER.warning(f"No response received when adding key to whitelist: {response}")

        return False

    async def remove_key_from_whitelist(self, public_key: bytes) -> bool:
        """Remove a key from the vehicle's whitelist.

        Args:
            public_key: The public key to remove.

        Returns:
            True if the key was removed successfully.
        """
        _LOGGER.info("Removing key from vehicle whitelist")

        whitelist_op = WhitelistOperation(
            public_key_to_remove=public_key,
        )

        vcsec = VCSECMessage(whitelist_operation=whitelist_op)
        response = await self._send_vcsec_command(vcsec)

        success, error_msg = self._check_response_error(response)
        if not success:
            _LOGGER.warning("Remove key from whitelist failed: %s", error_msg)
        return success
