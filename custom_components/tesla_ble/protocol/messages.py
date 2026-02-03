"""Protocol buffer message definitions for Tesla BLE.

This module implements a simplified protobuf-compatible message format
without requiring protobuf compilation, using manual wire format encoding.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from ..const import (
    ClosureMoveType,
    Domain,
    HVACAction,
    InformationRequestType,
    KeyFormFactor,
    OperationStatus,
    RKEAction,
    SignatureType,
    WhitelistOperationType,
)


# Protobuf wire types
WIRE_VARINT = 0
WIRE_FIXED64 = 1
WIRE_LENGTH_DELIMITED = 2
WIRE_FIXED32 = 5


def encode_varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    result = []
    while value > 127:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def decode_varint(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a protobuf varint, returning (value, bytes_consumed)."""
    result = 0
    shift = 0
    pos = offset
    while True:
        byte = data[pos]
        result |= (byte & 0x7F) << shift
        pos += 1
        if not (byte & 0x80):
            break
        shift += 7
    return result, pos - offset


def encode_field(field_number: int, wire_type: int, value: bytes | int) -> bytes:
    """Encode a protobuf field."""
    tag = (field_number << 3) | wire_type
    if wire_type == WIRE_VARINT:
        return encode_varint(tag) + encode_varint(value)
    elif wire_type == WIRE_LENGTH_DELIMITED:
        return encode_varint(tag) + encode_varint(len(value)) + value
    elif wire_type == WIRE_FIXED32:
        return encode_varint(tag) + struct.pack("<I", value)
    elif wire_type == WIRE_FIXED64:
        return encode_varint(tag) + struct.pack("<Q", value)
    raise ValueError(f"Unknown wire type: {wire_type}")


def parse_fields(data: bytes) -> dict[int, list[tuple[int, Any]]]:
    """Parse protobuf fields into {field_number: [(wire_type, value), ...]}."""
    fields: dict[int, list[tuple[int, Any]]] = {}
    offset = 0

    while offset < len(data):
        tag, consumed = decode_varint(data, offset)
        offset += consumed
        field_number = tag >> 3
        wire_type = tag & 0x07

        if wire_type == WIRE_VARINT:
            value, consumed = decode_varint(data, offset)
            offset += consumed
        elif wire_type == WIRE_LENGTH_DELIMITED:
            length, consumed = decode_varint(data, offset)
            offset += consumed
            value = data[offset : offset + length]
            offset += length
        elif wire_type == WIRE_FIXED32:
            value = struct.unpack("<I", data[offset : offset + 4])[0]
            offset += 4
        elif wire_type == WIRE_FIXED64:
            value = struct.unpack("<Q", data[offset : offset + 8])[0]
            offset += 8
        else:
            raise ValueError(f"Unknown wire type: {wire_type}")

        if field_number not in fields:
            fields[field_number] = []
        fields[field_number].append((wire_type, value))

    return fields


@dataclass
class Destination:
    """Message destination (domain or routing address)."""

    domain: Domain | None = None
    routing_address: bytes | None = None

    def encode(self) -> bytes:
        """Encode destination to protobuf bytes."""
        result = b""
        if self.domain is not None:
            result += encode_field(1, WIRE_VARINT, self.domain)
        if self.routing_address is not None:
            result += encode_field(2, WIRE_LENGTH_DELIMITED, self.routing_address)
        return result

    @classmethod
    def decode(cls, data: bytes) -> "Destination":
        """Decode destination from protobuf bytes."""
        fields = parse_fields(data)
        domain = None
        routing_address = None
        if 1 in fields:
            domain = Domain(fields[1][0][1])
        if 2 in fields:
            routing_address = fields[2][0][1]
        return cls(domain=domain, routing_address=routing_address)


@dataclass
class SignatureData:
    """AES-GCM signature data."""

    signature_type: SignatureType = SignatureType.AES_GCM_PERSONALIZED
    epoch: bytes = field(default_factory=bytes)
    nonce: bytes = field(default_factory=bytes)
    counter: int = 0
    expires_at: int = 0
    tag: bytes = field(default_factory=bytes)

    def encode(self) -> bytes:
        """Encode signature data to protobuf bytes."""
        # AES_GCM_PERSONALIZED_DATA field structure
        inner = b""
        if self.epoch:
            inner += encode_field(1, WIRE_LENGTH_DELIMITED, self.epoch)
        if self.nonce:
            inner += encode_field(2, WIRE_LENGTH_DELIMITED, self.nonce)
        inner += encode_field(3, WIRE_VARINT, self.counter)
        inner += encode_field(4, WIRE_VARINT, self.expires_at)
        if self.tag:
            inner += encode_field(5, WIRE_LENGTH_DELIMITED, self.tag)

        result = encode_field(1, WIRE_VARINT, self.signature_type)
        result += encode_field(6, WIRE_LENGTH_DELIMITED, inner)  # AES_GCM_PERSONALIZED
        return result

    @classmethod
    def decode(cls, data: bytes) -> "SignatureData":
        """Decode signature data from protobuf bytes."""
        fields = parse_fields(data)
        sig_type = SignatureType.AES_GCM_PERSONALIZED
        epoch = b""
        nonce = b""
        counter = 0
        expires_at = 0
        tag = b""

        if 1 in fields:
            sig_type = SignatureType(fields[1][0][1])

        # Parse inner data based on signature type
        inner_field = 6 if sig_type == SignatureType.AES_GCM_PERSONALIZED else 5
        if inner_field in fields:
            inner_data = fields[inner_field][0][1]
            inner_fields = parse_fields(inner_data)
            if 1 in inner_fields:
                epoch = inner_fields[1][0][1]
            if 2 in inner_fields:
                nonce = inner_fields[2][0][1]
            if 3 in inner_fields:
                counter = inner_fields[3][0][1]
            if 4 in inner_fields:
                expires_at = inner_fields[4][0][1]
            if 5 in inner_fields:
                tag = inner_fields[5][0][1]

        return cls(
            signature_type=sig_type,
            epoch=epoch,
            nonce=nonce,
            counter=counter,
            expires_at=expires_at,
            tag=tag,
        )


@dataclass
class SessionInfoRequest:
    """Request for session info from vehicle."""

    public_key: bytes = field(default_factory=bytes)
    challenge: bytes = field(default_factory=bytes)

    def encode(self) -> bytes:
        """Encode to protobuf bytes."""
        result = b""
        if self.public_key:
            result += encode_field(1, WIRE_LENGTH_DELIMITED, self.public_key)
        if self.challenge:
            result += encode_field(2, WIRE_LENGTH_DELIMITED, self.challenge)
        return result

    @classmethod
    def decode(cls, data: bytes) -> "SessionInfoRequest":
        """Decode from protobuf bytes."""
        fields = parse_fields(data)
        public_key = fields.get(1, [(0, b"")])[0][1]
        challenge = fields.get(2, [(0, b"")])[0][1]
        return cls(public_key=public_key, challenge=challenge)


@dataclass
class SessionInfo:
    """Session info from vehicle."""

    public_key: bytes = field(default_factory=bytes)
    epoch: bytes = field(default_factory=bytes)
    time_zero: int = 0
    counter: int = 0
    status: OperationStatus = OperationStatus.OK

    def encode(self) -> bytes:
        """Encode to protobuf bytes."""
        result = b""
        if self.public_key:
            result += encode_field(1, WIRE_LENGTH_DELIMITED, self.public_key)
        if self.epoch:
            result += encode_field(2, WIRE_LENGTH_DELIMITED, self.epoch)
        result += encode_field(3, WIRE_VARINT, self.time_zero)
        result += encode_field(4, WIRE_VARINT, self.counter)
        result += encode_field(5, WIRE_VARINT, self.status)
        return result

    @classmethod
    def decode(cls, data: bytes) -> "SessionInfo":
        """Decode from protobuf bytes."""
        fields = parse_fields(data)
        return cls(
            public_key=fields.get(1, [(0, b"")])[0][1],
            epoch=fields.get(2, [(0, b"")])[0][1],
            time_zero=fields.get(3, [(0, 0)])[0][1],
            counter=fields.get(4, [(0, 0)])[0][1],
            status=OperationStatus(fields.get(5, [(0, 0)])[0][1]),
        )


@dataclass
class MessageStatus:
    """Message status response."""

    operation_status: OperationStatus = OperationStatus.OK
    message_fault: int = 0

    @classmethod
    def decode(cls, data: bytes) -> "MessageStatus":
        """Decode from protobuf bytes."""
        fields = parse_fields(data)
        return cls(
            operation_status=OperationStatus(fields.get(1, [(0, 0)])[0][1]),
            message_fault=fields.get(2, [(0, 0)])[0][1],
        )


@dataclass
class RoutableMessage:
    """Universal routable message wrapper."""

    to_destination: Destination = field(default_factory=Destination)
    from_destination: Destination = field(default_factory=Destination)
    payload: bytes = field(default_factory=bytes)
    session_info_request: SessionInfoRequest | None = None
    session_info: SessionInfo | None = None
    signature_data: SignatureData | None = None
    message_status: MessageStatus | None = None
    request_uuid: bytes = field(default_factory=bytes)
    flags: int = 0

    def encode(self) -> bytes:
        """Encode to protobuf bytes."""
        result = b""

        # Field 1: to_destination
        to_bytes = self.to_destination.encode()
        if to_bytes:
            result += encode_field(1, WIRE_LENGTH_DELIMITED, to_bytes)

        # Field 2: from_destination
        from_bytes = self.from_destination.encode()
        if from_bytes:
            result += encode_field(2, WIRE_LENGTH_DELIMITED, from_bytes)

        # Field 3: payload (protobuf_message_as_bytes)
        if self.payload:
            result += encode_field(3, WIRE_LENGTH_DELIMITED, self.payload)

        # Field 4: session_info_request
        if self.session_info_request:
            result += encode_field(
                4, WIRE_LENGTH_DELIMITED, self.session_info_request.encode()
            )

        # Field 5: session_info
        if self.session_info:
            result += encode_field(
                5, WIRE_LENGTH_DELIMITED, self.session_info.encode()
            )

        # Field 6: signature_data
        if self.signature_data:
            result += encode_field(
                6, WIRE_LENGTH_DELIMITED, self.signature_data.encode()
            )

        # Field 7: message_status
        # (read-only, not encoded)

        # Field 50: request_uuid
        if self.request_uuid:
            result += encode_field(50, WIRE_LENGTH_DELIMITED, self.request_uuid)

        # Field 51: flags
        if self.flags:
            result += encode_field(51, WIRE_VARINT, self.flags)

        return result

    @classmethod
    def decode(cls, data: bytes) -> "RoutableMessage":
        """Decode from protobuf bytes."""
        fields = parse_fields(data)

        to_dest = Destination()
        from_dest = Destination()
        if 1 in fields:
            to_dest = Destination.decode(fields[1][0][1])
        if 2 in fields:
            from_dest = Destination.decode(fields[2][0][1])

        payload = fields.get(3, [(0, b"")])[0][1]

        session_info_request = None
        if 4 in fields:
            session_info_request = SessionInfoRequest.decode(fields[4][0][1])

        session_info = None
        if 5 in fields:
            session_info = SessionInfo.decode(fields[5][0][1])

        signature_data = None
        if 6 in fields:
            signature_data = SignatureData.decode(fields[6][0][1])

        message_status = None
        if 7 in fields:
            message_status = MessageStatus.decode(fields[7][0][1])

        request_uuid = fields.get(50, [(0, b"")])[0][1]
        flags = fields.get(51, [(0, 0)])[0][1]

        return cls(
            to_destination=to_dest,
            from_destination=from_dest,
            payload=payload,
            session_info_request=session_info_request,
            session_info=session_info,
            signature_data=signature_data,
            message_status=message_status,
            request_uuid=request_uuid,
            flags=flags,
        )


@dataclass
class UnsignedMessage:
    """Unsigned message container."""

    sub_message: bytes = field(default_factory=bytes)

    def encode(self) -> bytes:
        """Encode to protobuf bytes."""
        return encode_field(1, WIRE_LENGTH_DELIMITED, self.sub_message)

    @classmethod
    def decode(cls, data: bytes) -> "UnsignedMessage":
        """Decode from protobuf bytes."""
        fields = parse_fields(data)
        return cls(sub_message=fields.get(1, [(0, b"")])[0][1])


# VCSEC Messages


@dataclass
class InformationRequest:
    """VCSEC information request."""

    request_type: InformationRequestType = InformationRequestType.GET_STATUS
    key_slot: int = 0
    public_key: bytes = field(default_factory=bytes)

    def encode(self) -> bytes:
        """Encode to protobuf bytes."""
        result = encode_field(1, WIRE_VARINT, self.request_type)
        if self.key_slot:
            result += encode_field(2, WIRE_VARINT, self.key_slot)
        if self.public_key:
            result += encode_field(3, WIRE_LENGTH_DELIMITED, self.public_key)
        return result


@dataclass
class RKEActionMessage:
    """Remote keyless entry action message."""

    action: RKEAction = RKEAction.WAKE_VEHICLE

    def encode(self) -> bytes:
        """Encode to protobuf bytes."""
        return encode_field(1, WIRE_VARINT, self.action)


@dataclass
class ClosureMoveRequest:
    """Request to move a closure (door, trunk, etc.)."""

    front_driver_door: ClosureMoveType | None = None
    front_passenger_door: ClosureMoveType | None = None
    rear_driver_door: ClosureMoveType | None = None
    rear_passenger_door: ClosureMoveType | None = None
    rear_trunk: ClosureMoveType | None = None
    front_trunk: ClosureMoveType | None = None
    charge_port: ClosureMoveType | None = None
    tonneau: ClosureMoveType | None = None

    def encode(self) -> bytes:
        """Encode to protobuf bytes."""
        result = b""
        if self.front_driver_door is not None:
            result += encode_field(1, WIRE_VARINT, self.front_driver_door)
        if self.front_passenger_door is not None:
            result += encode_field(2, WIRE_VARINT, self.front_passenger_door)
        if self.rear_driver_door is not None:
            result += encode_field(3, WIRE_VARINT, self.rear_driver_door)
        if self.rear_passenger_door is not None:
            result += encode_field(4, WIRE_VARINT, self.rear_passenger_door)
        if self.rear_trunk is not None:
            result += encode_field(5, WIRE_VARINT, self.rear_trunk)
        if self.front_trunk is not None:
            result += encode_field(6, WIRE_VARINT, self.front_trunk)
        if self.charge_port is not None:
            result += encode_field(7, WIRE_VARINT, self.charge_port)
        if self.tonneau is not None:
            result += encode_field(8, WIRE_VARINT, self.tonneau)
        return result


@dataclass
class KeyIdentity:
    """Key identity (public key or handle)."""

    public_key: bytes | None = None
    handle: int | None = None

    def encode(self) -> bytes:
        """Encode to protobuf bytes."""
        if self.public_key:
            return encode_field(1, WIRE_LENGTH_DELIMITED, self.public_key)
        if self.handle is not None:
            return encode_field(3, WIRE_VARINT, self.handle)
        return b""


@dataclass
class PermissionChange:
    """Permission change for whitelist operation."""

    key: KeyIdentity = field(default_factory=KeyIdentity)
    second_factor_required: bool = False

    def encode(self) -> bytes:
        """Encode to protobuf bytes."""
        result = encode_field(1, WIRE_LENGTH_DELIMITED, self.key.encode())
        if self.second_factor_required:
            result += encode_field(2, WIRE_VARINT, 1)
        return result


@dataclass
class WhitelistOperation:
    """Whitelist operation (add/remove key)."""

    operation: WhitelistOperationType = WhitelistOperationType.ADD_KEY_TO_WHITELIST
    public_key_to_add: bytes | None = None
    public_key_to_remove: bytes | None = None
    key_to_add_permissions: PermissionChange | None = None
    key_to_remove_permissions: PermissionChange | None = None
    metadata_for_key: KeyMetadata | None = None

    def encode(self) -> bytes:
        """Encode to protobuf bytes."""
        inner = b""
        if self.public_key_to_add:
            inner += encode_field(1, WIRE_LENGTH_DELIMITED, self.public_key_to_add)
        if self.public_key_to_remove:
            inner += encode_field(2, WIRE_LENGTH_DELIMITED, self.public_key_to_remove)
        if self.key_to_add_permissions:
            inner += encode_field(
                3, WIRE_LENGTH_DELIMITED, self.key_to_add_permissions.encode()
            )
        if self.key_to_remove_permissions:
            inner += encode_field(
                4, WIRE_LENGTH_DELIMITED, self.key_to_remove_permissions.encode()
            )
        if self.metadata_for_key:
            inner += encode_field(
                5, WIRE_LENGTH_DELIMITED, self.metadata_for_key.encode()
            )

        # Wrap in WhitelistOperation_information_request field
        return encode_field(16, WIRE_LENGTH_DELIMITED, inner)


@dataclass
class KeyMetadata:
    """Key metadata for registration."""

    key_form_factor: KeyFormFactor = KeyFormFactor.CLOUD_KEY
    key_name: str = ""

    def encode(self) -> bytes:
        """Encode to protobuf bytes."""
        result = encode_field(1, WIRE_VARINT, self.key_form_factor)
        if self.key_name:
            result += encode_field(2, WIRE_LENGTH_DELIMITED, self.key_name.encode())
        return result


@dataclass
class VCSECMessage:
    """VCSEC message container."""

    # Possible payloads (oneof)
    information_request: InformationRequest | None = None
    rke_action: RKEActionMessage | None = None
    closure_move_request: ClosureMoveRequest | None = None
    whitelist_operation: WhitelistOperation | None = None
    signed_message: bytes | None = None

    def encode(self) -> bytes:
        """Encode to protobuf bytes."""
        if self.information_request:
            return encode_field(
                1, WIRE_LENGTH_DELIMITED, self.information_request.encode()
            )
        if self.rke_action:
            return encode_field(2, WIRE_LENGTH_DELIMITED, self.rke_action.encode())
        if self.closure_move_request:
            return encode_field(
                4, WIRE_LENGTH_DELIMITED, self.closure_move_request.encode()
            )
        if self.whitelist_operation:
            return encode_field(
                16, WIRE_LENGTH_DELIMITED, self.whitelist_operation.encode()
            )
        if self.signed_message:
            return encode_field(2, WIRE_LENGTH_DELIMITED, self.signed_message)
        return b""


# Vehicle state response parsing


@dataclass
class ClosureStatus:
    """Closure status."""

    front_driver_door: int = 0
    front_passenger_door: int = 0
    rear_driver_door: int = 0
    rear_passenger_door: int = 0
    rear_trunk: int = 0
    front_trunk: int = 0
    charge_port: int = 0
    tonneau: int = 0

    @classmethod
    def decode(cls, data: bytes) -> "ClosureStatus":
        """Decode from protobuf bytes."""
        fields = parse_fields(data)
        return cls(
            front_driver_door=fields.get(1, [(0, 0)])[0][1],
            front_passenger_door=fields.get(2, [(0, 0)])[0][1],
            rear_driver_door=fields.get(3, [(0, 0)])[0][1],
            rear_passenger_door=fields.get(4, [(0, 0)])[0][1],
            rear_trunk=fields.get(5, [(0, 0)])[0][1],
            front_trunk=fields.get(6, [(0, 0)])[0][1],
            charge_port=fields.get(7, [(0, 0)])[0][1],
            tonneau=fields.get(8, [(0, 0)])[0][1],
        )


@dataclass
class VehicleStatus:
    """Vehicle status response."""

    closure_statuses: ClosureStatus | None = None
    lock_state: int = 0
    sleep_status: int = 0
    user_presence: bool = False

    @classmethod
    def decode(cls, data: bytes) -> "VehicleStatus":
        """Decode from protobuf bytes."""
        fields = parse_fields(data)
        closure_status = None
        if 1 in fields:
            closure_status = ClosureStatus.decode(fields[1][0][1])
        return cls(
            closure_statuses=closure_status,
            lock_state=fields.get(2, [(0, 0)])[0][1],
            sleep_status=fields.get(3, [(0, 0)])[0][1],
            user_presence=bool(fields.get(4, [(0, 0)])[0][1]),
        )


@dataclass
class CommandStatus:
    """Command status response."""

    operation_status: OperationStatus = OperationStatus.OK
    which_error: int = 0

    @classmethod
    def decode(cls, data: bytes) -> "CommandStatus":
        """Decode from protobuf bytes."""
        fields = parse_fields(data)
        return cls(
            operation_status=OperationStatus(fields.get(1, [(0, 0)])[0][1]),
            which_error=fields.get(4, [(0, 0)])[0][1],
        )


@dataclass
class VCSECResponse:
    """VCSEC response message."""

    vehicle_status: VehicleStatus | None = None
    command_status: CommandStatus | None = None
    whitelist_info: bytes | None = None
    whitelist_entry_info: bytes | None = None

    @classmethod
    def decode(cls, data: bytes) -> "VCSECResponse":
        """Decode from protobuf bytes."""
        fields = parse_fields(data)
        vehicle_status = None
        command_status = None
        whitelist_info = None
        whitelist_entry_info = None

        if 1 in fields:
            vehicle_status = VehicleStatus.decode(fields[1][0][1])
        if 4 in fields:
            command_status = CommandStatus.decode(fields[4][0][1])
        if 16 in fields:
            whitelist_info = fields[16][0][1]
        if 17 in fields:
            whitelist_entry_info = fields[17][0][1]

        return cls(
            vehicle_status=vehicle_status,
            command_status=command_status,
            whitelist_info=whitelist_info,
            whitelist_entry_info=whitelist_entry_info,
        )
