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
    DEFAULT_FLAGS,
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
    ToVCSECMessage,
)
from .protos_py import tesla_car_server_pb2 as carserver
from .protos_py import tesla_common_pb2 as common
from .protos_py import tesla_vehicle_pb2 as vehicle_pb

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
        """Handle incoming notifications from the vehicle.

        Message format: [2-byte big-endian length] + [payload]
        This matches the framing in vehicle-command/pkg/connector/ble/ble.go
        """
        _LOGGER.debug("Received notification: %s", data.hex())

        # Append incoming data to buffer (matching reference implementation)
        self._rx_buffer.extend(data)

        # Process all complete messages in the buffer
        # This loop handles the case where multiple messages arrive together
        while self._flush_message():
            pass

    def _flush_message(self) -> bool:
        """Extract and dispatch a complete message from the buffer.

        Returns True if a message was extracted, False otherwise.
        This matches the flush() implementation in vehicle-command.
        """
        # Need at least 2 bytes for the length prefix
        if len(self._rx_buffer) < 2:
            return False

        # Extract message length from first 2 bytes (big-endian)
        msg_length = struct.unpack(">H", self._rx_buffer[:2])[0]

        # Sanity check - reject oversized messages
        max_message_size = 1024
        if msg_length > max_message_size:
            _LOGGER.warning(
                "Message length %d exceeds max %d, clearing buffer",
                msg_length,
                max_message_size,
            )
            self._rx_buffer.clear()
            return False

        # Check if we have the complete message (length prefix + payload)
        if len(self._rx_buffer) < 2 + msg_length:
            return False

        # Extract the message payload (excluding length prefix)
        message = bytes(self._rx_buffer[2 : 2 + msg_length])

        # Remove processed data from buffer, keeping any remainder
        self._rx_buffer = bytearray(self._rx_buffer[2 + msg_length :])

        # Dispatch the complete message
        self._dispatch_message(message)
        return True

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
        """Connect to the vehicle.
        
        Uses Home Assistant's recommended bleak_retry_connector for robust
        connection handling with automatic retries and proper error handling.
        """
        async with self._lock:
            if self.is_connected:
                _LOGGER.debug("Already connected to %s", self._ble_device.address)
                return True

            try:
                _LOGGER.info("Connecting to vehicle: %s", self._ble_device.address)
                
                # Use establish_connection for robust connection with retries
                # This follows Home Assistant Bluetooth best practices
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
                _LOGGER.info(
                    "Connected to vehicle %s (MTU: %s)",
                    self._ble_device.address,
                    getattr(self._client, "mtu_size", "unknown"),
                )
                return True

            except (BleakError, asyncio.TimeoutError) as ex:
                _LOGGER.error(
                    "Failed to connect to %s: %s",
                    self._ble_device.address,
                    ex,
                )
                self._client = None
                return False
            except Exception as ex:
                _LOGGER.exception(
                    "Unexpected error connecting to %s",
                    self._ble_device.address,
                )
                self._client = None
                return False

    async def disconnect(self) -> None:
        """Disconnect from the vehicle.
        
        Properly cleans up Bluetooth connection and notification subscriptions.
        """
        async with self._lock:
            if not self._client:
                return
                
            if self._client.is_connected:
                try:
                    _LOGGER.debug("Stopping notifications and disconnecting from %s", self._ble_device.address)
                    await self._client.stop_notify(TESLA_RX_CHAR_UUID)
                    await self._client.disconnect()
                except (BleakError, asyncio.TimeoutError) as ex:
                    _LOGGER.debug("Error during disconnect: %s", ex)
                except Exception as ex:
                    _LOGGER.warning("Unexpected error during disconnect: %s", ex)
                finally:
                    self._client = None
                    self._state.connected = False
            else:
                _LOGGER.debug("Client not connected, cleaning up")
                self._client = None
                self._state.connected = False

    async def _send_message(self, message: bytes) -> None:
        """Send a message to the vehicle.
        
        Handles message framing and chunking according to BLE MTU size.
        Follows Home Assistant best practices for BLE write operations.
        """
        if not self._client or not self._client.is_connected:
            raise ConnectionError("Not connected to vehicle")

        # Frame the message with 2-byte big-endian length prefix
        framed = struct.pack(">H", len(message)) + message
        _LOGGER.debug("Sending %d byte message (framed: %d bytes)", len(message), len(framed))

        # Get MTU size from client (typically 512 for BLE, but can vary)
        # Use safe default if not available
        mtu = getattr(self._client, "mtu_size", 512)
        if mtu > 512:
            mtu = 512  # Conservative limit for compatibility
        
        # Send in chunks if message exceeds MTU
        if len(framed) <= mtu:
            # Single write
            await self._client.write_gatt_char(TESLA_TX_CHAR_UUID, framed, response=False)
        else:
            # Chunked writes
            _LOGGER.debug("Message requires chunking (MTU: %d)", mtu)
            for i in range(0, len(framed), mtu):
                chunk = framed[i : i + mtu]
                _LOGGER.debug("Sending chunk %d-%d of %d", i, i + len(chunk), len(framed))
                await self._client.write_gatt_char(TESLA_TX_CHAR_UUID, chunk, response=False)

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
        """Create a signed routable message.

        Encrypts the payload with proper metadata authentication and creates
        a RoutableMessage with AES-GCM signature data.

        This follows the reference implementation in vehicle-command which:
        1. Computes a metadata checksum from signature type, domain, epoch, etc.
        2. Uses this checksum as the Associated Data (AD) for AES-GCM encryption
        3. Includes the signer's public key in the signature data
        """
        # Encrypt with proper metadata authentication
        ciphertext, nonce, counter, expires_at = self._crypto.encrypt_with_metadata(
            plaintext=payload,
            domain=domain,
            flags=DEFAULT_FLAGS,
        )

        signature = SignatureData(
            epoch=self._crypto._epoch,
            nonce=nonce,
            counter=counter,
            expires_at=expires_at,
            tag=ciphertext[-16:],  # AES-GCM tag is last 16 bytes
            signer_public_key=self._crypto.public_key_bytes,  # Include signer identity
        )

        return RoutableMessage(
            to_destination=Destination(domain=domain),
            from_destination=Destination(routing_address=self._crypto.public_key_bytes),
            payload=ciphertext[:-16],  # Ciphertext without tag
            signature_data=signature,
            request_uuid=os.urandom(16),
            flags=DEFAULT_FLAGS,  # Request encrypted responses
        )

    async def _get_vcsec_result(
        self,
        payload: bytes,
        require_session: bool = True,
    ) -> VCSECResponse | None:
        """Send a VCSEC command with retry logic and return the response.
        
        This matches the getVCSECResult pattern from the reference implementation.
        """
        if require_session and not self.has_session:
            if not await self.establish_session():
                raise ConnectionError("Failed to establish session")

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
    
    async def _send_vcsec_command(
        self,
        vcsec_message: VCSECMessage,
        require_session: bool = True,
    ) -> VCSECResponse | None:
        """Send a VCSEC command and return the response."""
        payload = vcsec_message.encode()
        return await self._get_vcsec_result(payload, require_session)

    async def _execute_rke_action(self, action: RKEAction) -> bool:
        """Execute an RKE (Remote Keyless Entry) action.
        
        This matches the executeRKEAction pattern from the reference implementation.
        RKE actions typically don't return a command status, just wait for vehicle
        to acknowledge.
        """
        _LOGGER.debug("Executing RKE action: %s", action.name)
        vcsec = VCSECMessage(rke_action=RKEActionMessage(action=action))
        response = await self._send_vcsec_command(vcsec)
        
        # For RKE actions, we wait until we receive any response (command status or nothing)
        # The reference implementation checks if command_status is None to determine completion
        if response and response.command_status is None:
            return True
        
        success, error_msg = self._check_response_error(response)
        if not success:
            _LOGGER.warning("RKE action %s failed: %s", action.name, error_msg)
        return success

    async def _execute_closure_action(
        self, action: ClosureMoveType, closure_field: str
    ) -> bool:
        """Execute a closure move action (trunk, frunk, charge port, etc).
        
        This matches the executeClosureAction pattern from the reference implementation.
        
        Args:
            action: The move type (MOVE, OPEN, CLOSE, STOP)
            closure_field: The field name (e.g., 'rear_trunk', 'front_trunk', 'charge_port')
        """
        _LOGGER.debug("Executing closure action: %s on %s", action.name, closure_field)
        
        # Build the closure request with the appropriate field set
        closure_kwargs = {closure_field: action}
        vcsec = VCSECMessage(
            closure_move_request=ClosureMoveRequest(**closure_kwargs)
        )
        
        response = await self._send_vcsec_command(vcsec)
        
        # Wait for any response (similar to RKE)
        if response and response.command_status is None:
            return True
        
        success, error_msg = self._check_response_error(response)
        if not success:
            _LOGGER.warning("Closure action %s on %s failed: %s", action.name, closure_field, error_msg)
        return success

    async def _execute_carserver_action(
        self, vehicle_action: "carserver.VehicleAction"
    ) -> "carserver.Response | None":
        """Execute a carserver (infotainment) command.
        
        This matches the executeCarServerAction pattern from the reference implementation.
        
        Args:
            vehicle_action: The VehicleAction protobuf message
            
        Returns:
            The Response protobuf message or None
        """
        if carserver is None:
            _LOGGER.error("Carserver protobuf not available")
            return None
            
        if not self.has_session:
            if not await self.establish_session():
                raise ConnectionError("Failed to establish session")

        # Wrap VehicleAction in Action
        action = carserver.Action()
        action.vehicleAction.CopyFrom(vehicle_action)
        
        payload = action.SerializeToString()
        
        # Create signed message for infotainment domain
        message = self._create_signed_message(payload, Domain.INFOTAINMENT)
        
        response = await self._send_and_receive(message)
        if not response or not response.payload:
            return None
            
        # Parse response
        car_response = carserver.Response()
        car_response.ParseFromString(response.payload)
        
        # Check for errors
        if car_response.HasField("actionStatus"):
            status = car_response.actionStatus
            if status.result == carserver.OperationStatus_E.E_OPERATIONSTATUS_ERROR:
                error_msg = status.result_reason.plain_text if status.HasField("result_reason") else "unspecified error"
                _LOGGER.error("Carserver command failed: %s", error_msg)
                return None
                
        return car_response

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
        return await self._execute_rke_action(RKEAction.WAKE_VEHICLE)

    async def lock(self) -> bool:
        """Lock the vehicle."""
        _LOGGER.info("Locking vehicle")
        success = await self._execute_rke_action(RKEAction.LOCK)
        if success:
            self._state.lock_state = VehicleLockState.LOCKED
        return success

    async def unlock(self) -> bool:
        """Unlock the vehicle."""
        _LOGGER.info("Unlocking vehicle")
        success = await self._execute_rke_action(RKEAction.UNLOCK)
        if success:
            self._state.lock_state = VehicleLockState.UNLOCKED
        return success

    async def remote_drive(self) -> bool:
        """Enable remote drive mode."""
        _LOGGER.info("Enabling remote drive")
        return await self._execute_rke_action(RKEAction.REMOTE_DRIVE)

    async def auto_secure_vehicle(self) -> bool:
        """Auto-secure the vehicle."""
        _LOGGER.info("Auto-securing vehicle")
        return await self._execute_rke_action(RKEAction.AUTO_SECURE_VEHICLE)

    async def actuate_trunk(self) -> bool:
        """Actuate (toggle) the rear trunk."""
        _LOGGER.info("Actuating trunk")
        return await self._execute_closure_action(ClosureMoveType.MOVE, "rear_trunk")

    async def open_trunk(self) -> bool:
        """Open the rear trunk."""
        _LOGGER.info("Opening trunk")
        return await self._execute_closure_action(ClosureMoveType.MOVE, "rear_trunk")

    async def close_trunk(self) -> bool:
        """Close the rear trunk (not available on all vehicle types)."""
        _LOGGER.info("Closing trunk")
        return await self._execute_closure_action(ClosureMoveType.CLOSE, "rear_trunk")

    async def open_frunk(self) -> bool:
        """Open the front trunk (frunk)."""
        _LOGGER.info("Opening frunk")
        return await self._execute_closure_action(ClosureMoveType.MOVE, "front_trunk")

    async def open_charge_port(self) -> bool:
        """Open the charge port."""
        _LOGGER.info("Opening charge port")
        return await self._execute_closure_action(ClosureMoveType.OPEN, "charge_port")

    async def close_charge_port(self) -> bool:
        """Close the charge port."""
        _LOGGER.info("Closing charge port")
        return await self._execute_closure_action(ClosureMoveType.CLOSE, "charge_port")

    async def open_tonneau(self) -> bool:
        """Open the tonneau (Cybertruck bed cover)."""
        _LOGGER.info("Opening tonneau")
        return await self._execute_closure_action(ClosureMoveType.OPEN, "tonneau")

    async def close_tonneau(self) -> bool:
        """Close the tonneau (Cybertruck bed cover)."""
        _LOGGER.info("Closing tonneau")
        return await self._execute_closure_action(ClosureMoveType.CLOSE, "tonneau")

    async def stop_tonneau(self) -> bool:
        """Stop the tonneau (Cybertruck bed cover)."""
        _LOGGER.info("Stopping tonneau")
        return await self._execute_closure_action(ClosureMoveType.STOP, "tonneau")

    async def honk_horn(self) -> bool:
        """Honk the horn."""
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        _LOGGER.info("Honking horn")
        vehicle_action = carserver.VehicleAction()
        vehicle_action.vehicleControlHonkHornAction.CopyFrom(
            carserver.VehicleControlHonkHornAction()
        )
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def flash_lights(self) -> bool:
        """Flash the lights."""
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        _LOGGER.info("Flashing lights")
        vehicle_action = carserver.VehicleAction()
        vehicle_action.vehicleControlFlashLightsAction.CopyFrom(
            carserver.VehicleControlFlashLightsAction()
        )
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def vent_windows(self) -> bool:
        """Vent all windows."""
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        _LOGGER.info("Venting windows")
        vehicle_action = carserver.VehicleAction()
        window_action = carserver.VehicleControlWindowAction()
        window_action.vent.CopyFrom(carserver.Void())
        vehicle_action.vehicleControlWindowAction.CopyFrom(window_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def close_windows(self) -> bool:
        """Close all windows."""
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        _LOGGER.info("Closing windows")
        vehicle_action = carserver.VehicleAction()
        window_action = carserver.VehicleControlWindowAction()
        window_action.close.CopyFrom(carserver.Void())
        vehicle_action.vehicleControlWindowAction.CopyFrom(window_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def ping(self) -> bool:
        """Ping the vehicle (authenticated no-op)."""
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        _LOGGER.debug("Pinging vehicle")
        vehicle_action = carserver.VehicleAction()
        ping_msg = carserver.Ping()
        ping_msg.pingId = 1
        vehicle_action.ping.CopyFrom(ping_msg)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    # Climate control commands

    async def climate_on(self) -> bool:
        """Turn on climate control."""
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        _LOGGER.info("Turning on climate")
        vehicle_action = carserver.VehicleAction()
        hvac_action = carserver.HvacAutoAction()
        hvac_action.powerOn = True
        vehicle_action.hvacAutoAction.CopyFrom(hvac_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def climate_off(self) -> bool:
        """Turn off climate control."""
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        _LOGGER.info("Turning off climate")
        vehicle_action = carserver.VehicleAction()
        hvac_action = carserver.HvacAutoAction()
        hvac_action.powerOn = False
        vehicle_action.hvacAutoAction.CopyFrom(hvac_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def set_temperature(self, driver_temp_celsius: float, passenger_temp_celsius: float | None = None) -> bool:
        """Set cabin temperature.
        
        Args:
            driver_temp_celsius: Driver side temperature in Celsius
            passenger_temp_celsius: Passenger side temperature in Celsius (optional, defaults to driver temp)
        """
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        if passenger_temp_celsius is None:
            passenger_temp_celsius = driver_temp_celsius
            
        _LOGGER.info("Setting temperature: driver=%.1f°C, passenger=%.1f°C", 
                     driver_temp_celsius, passenger_temp_celsius)
        vehicle_action = carserver.VehicleAction()
        temp_action = carserver.HvacTemperatureAdjustmentAction()
        temp_action.driverTempCelsius = driver_temp_celsius
        temp_action.passengerTempCelsius = passenger_temp_celsius
        vehicle_action.hvacTemperatureAdjustmentAction.CopyFrom(temp_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def set_seat_heater(self, seat_position: str, level: int) -> bool:
        """Set seat heater level.
        
        Args:
            seat_position: Seat position ('front_left', 'front_right', etc.)
            level: Heating level (0=off, 1=low, 2=medium, 3=high)
        """
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        _LOGGER.info("Setting seat heater: %s to level %d", seat_position, level)
        # This is a simplified implementation - full implementation would need proper seat mapping
        vehicle_action = carserver.VehicleAction()
        # TODO: Implement full seat heater mapping from reference
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def set_steering_wheel_heater(self, enabled: bool) -> bool:
        """Turn steering wheel heater on or off."""
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        _LOGGER.info("Setting steering wheel heater: %s", "on" if enabled else "off")
        vehicle_action = carserver.VehicleAction()
        heater_action = carserver.HvacSteeringWheelHeaterAction()
        heater_action.powerOn = enabled
        vehicle_action.hvacSteeringWheelHeaterAction.CopyFrom(heater_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    # Charging commands

    async def charge_start(self) -> bool:
        """Start charging."""
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        _LOGGER.info("Starting charge")
        vehicle_action = carserver.VehicleAction()
        charge_action = carserver.ChargingStartStopAction()
        charge_action.start.CopyFrom(carserver.Void())
        vehicle_action.chargingStartStopAction.CopyFrom(charge_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def charge_stop(self) -> bool:
        """Stop charging."""
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        _LOGGER.info("Stopping charge")
        vehicle_action = carserver.VehicleAction()
        charge_action = carserver.ChargingStartStopAction()
        charge_action.stop.CopyFrom(carserver.Void())
        vehicle_action.chargingStartStopAction.CopyFrom(charge_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def set_charge_limit(self, percent: int) -> bool:
        """Set charge limit percentage.
        
        Args:
            percent: Charge limit (50-100)
        """
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        if not 50 <= percent <= 100:
            _LOGGER.error("Charge limit must be between 50 and 100")
            return False
            
        _LOGGER.info("Setting charge limit to %d%%", percent)
        vehicle_action = carserver.VehicleAction()
        limit_action = carserver.ChargingSetLimitAction()
        limit_action.percent = percent
        vehicle_action.chargingSetLimitAction.CopyFrom(limit_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def set_charging_amps(self, amps: int) -> bool:
        """Set charging current in amps.
        
        Args:
            amps: Charging current in amps
        """
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        _LOGGER.info("Setting charging amps to %d", amps)
        vehicle_action = carserver.VehicleAction()
        amps_action = carserver.SetChargingAmpsAction()
        amps_action.chargingAmps = amps
        vehicle_action.setChargingAmpsAction.CopyFrom(amps_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    # Security commands

    async def set_sentry_mode(self, enabled: bool) -> bool:
        """Enable or disable sentry mode.

        Args:
            enabled: True to enable, False to disable
        """
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False

        _LOGGER.info("Setting sentry mode: %s", "on" if enabled else "off")
        vehicle_action = carserver.VehicleAction()
        sentry_action = carserver.VehicleControlSetSentryModeAction()
        sentry_action.on = enabled
        vehicle_action.vehicleControlSetSentryModeAction.CopyFrom(sentry_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def enable_valet_mode(self, pin: str) -> bool:
        """Enable valet mode with PIN.

        Args:
            pin: A 4-digit PIN code.
        """
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False

        if len(pin) != 4 or not pin.isdigit():
            _LOGGER.error("PIN must be exactly 4 digits")
            return False

        _LOGGER.info("Enabling valet mode")
        vehicle_action = carserver.VehicleAction()
        valet_action = carserver.VehicleControlSetValetModeAction()
        valet_action.on = True
        valet_action.password = pin
        vehicle_action.vehicleControlSetValetModeAction.CopyFrom(valet_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def disable_valet_mode(self) -> bool:
        """Disable valet mode."""
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False

        _LOGGER.info("Disabling valet mode")
        vehicle_action = carserver.VehicleAction()
        valet_action = carserver.VehicleControlSetValetModeAction()
        valet_action.on = False
        vehicle_action.vehicleControlSetValetModeAction.CopyFrom(valet_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def trigger_homelink(self, latitude: float, longitude: float) -> bool:
        """Trigger HomeLink at the specified location.

        Args:
            latitude: GPS latitude.
            longitude: GPS longitude.
        """
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False

        _LOGGER.info("Triggering HomeLink at (%f, %f)", latitude, longitude)
        vehicle_action = carserver.VehicleAction()
        homelink_action = carserver.VehicleControlTriggerHomelinkAction()
        location = common.LatLong()
        location.latitude = latitude
        location.longitude = longitude
        homelink_action.location.CopyFrom(location)
        vehicle_action.vehicleControlTriggerHomelinkAction.CopyFrom(homelink_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def set_speed_limit(self, speed_limit_mph: float) -> bool:
        """Set speed limit in MPH.

        Args:
            speed_limit_mph: Speed limit in miles per hour.
        """
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False

        _LOGGER.info("Setting speed limit to %.1f MPH", speed_limit_mph)
        vehicle_action = carserver.VehicleAction()
        limit_action = carserver.DrivingSetSpeedLimitAction()
        limit_action.limitMph = speed_limit_mph
        vehicle_action.drivingSetSpeedLimitAction.CopyFrom(limit_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def activate_speed_limit(self, pin: str) -> bool:
        """Activate speed limit with PIN.

        Args:
            pin: The speed limit PIN.
        """
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False

        _LOGGER.info("Activating speed limit")
        vehicle_action = carserver.VehicleAction()
        speed_action = carserver.DrivingSpeedLimitAction()
        speed_action.activate = True
        speed_action.pin = pin
        vehicle_action.drivingSpeedLimitAction.CopyFrom(speed_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def deactivate_speed_limit(self, pin: str) -> bool:
        """Deactivate speed limit with PIN.

        Args:
            pin: The speed limit PIN.
        """
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False

        _LOGGER.info("Deactivating speed limit")
        vehicle_action = carserver.VehicleAction()
        speed_action = carserver.DrivingSpeedLimitAction()
        speed_action.activate = False
        speed_action.pin = pin
        vehicle_action.drivingSpeedLimitAction.CopyFrom(speed_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def set_guest_mode(self, enabled: bool) -> bool:
        """Enable or disable guest mode.

        Args:
            enabled: True to enable, False to disable.
        """
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False

        _LOGGER.info("Setting guest mode: %s", "on" if enabled else "off")
        vehicle_action = carserver.VehicleAction()
        guest_action = vehicle_pb.VehicleState.GuestMode()
        guest_action.guestModeActive = enabled
        vehicle_action.guestModeAction.CopyFrom(guest_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    # Media commands

    async def media_next_track(self) -> bool:
        """Skip to next media track."""
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        _LOGGER.info("Next track")
        vehicle_action = carserver.VehicleAction()
        vehicle_action.mediaNextTrack.CopyFrom(carserver.MediaNextTrack())
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def media_previous_track(self) -> bool:
        """Skip to previous media track."""
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        _LOGGER.info("Previous track")
        vehicle_action = carserver.VehicleAction()
        vehicle_action.mediaPreviousTrack.CopyFrom(carserver.MediaPreviousTrack())
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def media_toggle_playback(self) -> bool:
        """Toggle media playback (play/pause)."""
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        _LOGGER.info("Toggle playback")
        vehicle_action = carserver.VehicleAction()
        vehicle_action.mediaPlayAction.CopyFrom(carserver.MediaPlayAction())
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def media_volume_up(self) -> bool:
        """Increase media volume."""
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        _LOGGER.info("Volume up")
        vehicle_action = carserver.VehicleAction()
        volume_action = carserver.MediaUpdateVolume()
        volume_action.volumeDelta = 1
        vehicle_action.mediaUpdateVolume.CopyFrom(volume_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def media_volume_down(self) -> bool:
        """Decrease media volume."""
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        _LOGGER.info("Volume down")
        vehicle_action = carserver.VehicleAction()
        volume_action = carserver.MediaUpdateVolume()
        volume_action.volumeDelta = -1
        vehicle_action.mediaUpdateVolume.CopyFrom(volume_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

    async def set_volume(self, volume: float) -> bool:
        """Set media volume.
        
        Args:
            volume: Volume level (0.0 to 10.0)
        """
        if carserver is None:
            _LOGGER.error("Carserver not available")
            return False
            
        if not 0.0 <= volume <= 10.0:
            _LOGGER.error("Volume must be between 0.0 and 10.0")
            return False
            
        _LOGGER.info("Setting volume to %.1f", volume)
        vehicle_action = carserver.VehicleAction()
        volume_action = carserver.MediaUpdateVolume()
        volume_action.volumeAbsoluteFloat = volume
        vehicle_action.mediaUpdateVolume.CopyFrom(volume_action)
        response = await self._execute_carserver_action(vehicle_action)
        return response is not None

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
        key_form_factor: KeyFormFactor = KeyFormFactor.CLOUD_KEY,
    ) -> bool:
        """Add our public key to the vehicle's whitelist.

        This is a "fire-and-forget" operation that sends the add-key request
        to the vehicle. The user must then tap their NFC key card on the
        center console to authorize the key.

        Note: This method returns True as soon as the request is transmitted.
        A True return value does NOT guarantee the key was added - the user
        must complete the NFC card tap to authorize the new key.

        Args:
            key_form_factor: The form factor of the key being added.
                Defaults to CLOUD_KEY for Home Assistant integrations.

        Returns:
            True if the request was sent successfully.
        """
        if not self.is_connected:
            if not await self.connect():
                return False

        _LOGGER.info("Sending add-key request to vehicle whitelist")

        # Build the whitelist operation with our public key
        whitelist_op = WhitelistOperation(
            public_key_to_add=self._crypto.public_key_bytes,
            metadata_for_key=KeyMetadata(key_form_factor=key_form_factor),
        )

        # Wrap in UnsignedMessage
        unsigned_msg = VCSECMessage(whitelist_operation=whitelist_op)

        # Wrap in ToVCSECMessage with SignedMessage (SIGNATURE_TYPE_PRESENT_KEY)
        # This indicates authentication will be via physical NFC card tap
        to_vcsec = ToVCSECMessage(unsigned_message=unsigned_msg.encode())

        # IMPORTANT: For add-key requests, send ToVCSECMessage DIRECTLY without
        # wrapping in RoutableMessage. This matches the reference implementation
        # in vehicle-command/pkg/vehicle/security.go SendAddKeyRequestWithRole()
        try:
            encoded = to_vcsec.encode()
            await self._send_message(encoded)
            _LOGGER.info(
                "Add-key request sent. User must tap NFC card on center console to confirm."
            )
            return True
        except Exception as ex:
            _LOGGER.error("Failed to send add-key request: %s", ex)
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

    # Session persistence methods

    def export_session(self) -> dict | None:
        """Export session state for persistence.

        This allows saving session state to storage and restoring it later,
        avoiding the need to re-establish the session on each restart.

        Returns:
            Dict with session state, or None if no session is active.
        """
        return self._crypto.export_session()

    def import_session(self, session_data: dict) -> bool:
        """Import session state from persistence.

        This restores a previously exported session, allowing continued
        communication without re-establishing the session.

        Args:
            session_data: Dict with session state from export_session().

        Returns:
            True if session was successfully restored.
        """
        return self._crypto.import_session(session_data)
