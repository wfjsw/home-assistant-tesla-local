"""Protocol buffer message wrappers for Tesla BLE.

This module provides a clean API using the generated protobuf classes.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..const import (
    ClosureMoveType,
    Domain,
    GenericError,
    InformationRequestType,
    KeyFormFactor,
    OperationStatus,
    RKEAction,
)

# Import generated protobuf classes
from .protos_py import (
    errors_pb2,
    signatures_pb2,
    universal_message_pb2,
    vcsec_pb2,
)


# Universal Message wrappers


@dataclass
class Destination:
    """Message destination (domain or routing address)."""

    domain: Domain | None = None
    routing_address: bytes | None = None

    def to_proto(self) -> universal_message_pb2.Destination:
        """Convert to protobuf message."""
        dest = universal_message_pb2.Destination()
        if self.domain is not None:
            dest.domain = self.domain
        if self.routing_address is not None:
            dest.routing_address = self.routing_address
        return dest

    @classmethod
    def from_proto(cls, proto: universal_message_pb2.Destination) -> Destination:
        """Create from protobuf message."""
        domain = None
        routing_address = None
        
        if proto.HasField("domain"):
            domain = Domain(proto.domain)
        if proto.HasField("routing_address"):
            routing_address = proto.routing_address
            
        return cls(domain=domain, routing_address=routing_address)


@dataclass
class SignatureData:
    """AES-GCM signature data."""

    epoch: bytes = field(default_factory=bytes)
    nonce: bytes = field(default_factory=bytes)
    counter: int = 0
    expires_at: int = 0
    tag: bytes = field(default_factory=bytes)

    def to_proto(self) -> signatures_pb2.SignatureData:
        """Convert to protobuf message."""
        sig_data = signatures_pb2.SignatureData()
        aes_gcm_data = signatures_pb2.AES_GCM_Personalized_Signature_Data()
        aes_gcm_data.epoch = self.epoch
        aes_gcm_data.nonce = self.nonce
        aes_gcm_data.counter = self.counter
        aes_gcm_data.expires_at = self.expires_at
        aes_gcm_data.tag = self.tag
        sig_data.AES_GCM_Personalized_data.CopyFrom(aes_gcm_data)
        return sig_data

    @classmethod
    def from_proto(cls, proto: signatures_pb2.SignatureData) -> SignatureData:
        """Create from protobuf message."""
        if proto.HasField("AES_GCM_Personalized_data"):
            aes_gcm_data = proto.AES_GCM_Personalized_data
            return cls(
                epoch=aes_gcm_data.epoch,
                nonce=aes_gcm_data.nonce,
                counter=aes_gcm_data.counter,
                expires_at=aes_gcm_data.expires_at,
                tag=aes_gcm_data.tag,
            )
        return cls()


@dataclass
class SessionInfoRequest:
    """Request for session info from vehicle."""

    public_key: bytes = field(default_factory=bytes)
    challenge: bytes = field(default_factory=bytes)

    def to_proto(self) -> universal_message_pb2.SessionInfoRequest:
        """Convert to protobuf message."""
        req = universal_message_pb2.SessionInfoRequest()
        req.public_key = self.public_key
        req.challenge = self.challenge
        return req

    @classmethod
    def from_proto(cls, proto: universal_message_pb2.SessionInfoRequest) -> SessionInfoRequest:
        """Create from protobuf message."""
        return cls(
            public_key=proto.public_key,
            challenge=proto.challenge,
        )


@dataclass
class SessionInfo:
    """Session info from vehicle."""

    public_key: bytes = field(default_factory=bytes)
    epoch: bytes = field(default_factory=bytes)
    time_zero: int = 0
    counter: int = 0
    status: int = 0

    @classmethod
    def from_proto(cls, proto: signatures_pb2.SessionInfo) -> SessionInfo:
        """Create from protobuf message."""
        return cls(
            public_key=proto.publicKey,
            epoch=proto.epoch,
            time_zero=proto.clock_time,
            counter=proto.counter,
            status=proto.status,
        )


@dataclass
class MessageStatus:
    """Message status response."""

    operation_status: OperationStatus = OperationStatus.OK
    message_fault: int = 0

    @classmethod
    def from_proto(cls, proto: universal_message_pb2.MessageStatus) -> MessageStatus:
        """Create from protobuf message."""
        return cls(
            operation_status=OperationStatus(proto.operation_status),
            message_fault=proto.signed_message_fault,
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
        msg = universal_message_pb2.RoutableMessage()
        
        msg.to_destination.CopyFrom(self.to_destination.to_proto())
        msg.from_destination.CopyFrom(self.from_destination.to_proto())
        
        if self.payload:
            msg.protobuf_message_as_bytes = self.payload
            
        if self.session_info_request:
            msg.session_info_request.CopyFrom(self.session_info_request.to_proto())
            
        if self.session_info:
            # SessionInfo comes as bytes from vehicle
            msg.session_info = self.session_info
            
        if self.signature_data:
            msg.signature_data.CopyFrom(self.signature_data.to_proto())
            
        if self.request_uuid:
            msg.request_uuid = self.request_uuid
            
        if self.flags:
            msg.flags = self.flags
            
        return msg.SerializeToString()

    @classmethod
    def decode(cls, data: bytes) -> RoutableMessage:
        """Decode from protobuf bytes."""
        msg = universal_message_pb2.RoutableMessage()
        msg.ParseFromString(data)
        
        to_dest = Destination.from_proto(msg.to_destination)
        from_dest = Destination.from_proto(msg.from_destination)
        
        payload = None
        if msg.HasField("protobuf_message_as_bytes"):
            payload = msg.protobuf_message_as_bytes
            
        session_info_request = None
        if msg.HasField("session_info_request"):
            session_info_request = SessionInfoRequest.from_proto(msg.session_info_request)
            
        session_info = None
        if msg.HasField("session_info"):
            # Parse session info from bytes
            session_info_proto = signatures_pb2.SessionInfo()
            session_info_proto.ParseFromString(msg.session_info)
            session_info = SessionInfo.from_proto(session_info_proto)
            
        signature_data = None
        if msg.HasField("signature_data"):
            signature_data = SignatureData.from_proto(msg.signature_data)
            
        message_status = None
        if msg.HasField("signedMessageStatus"):
            message_status = MessageStatus.from_proto(msg.signedMessageStatus)
            
        return cls(
            to_destination=to_dest,
            from_destination=from_dest,
            payload=payload,
            session_info_request=session_info_request,
            session_info=session_info,
            signature_data=signature_data,
            message_status=message_status,
            request_uuid=msg.request_uuid,
            flags=msg.flags,
        )


@dataclass
class UnsignedMessage:
    """Unsigned message container."""

    sub_message: bytes = field(default_factory=bytes)

    def encode(self) -> bytes:
        """Encode to protobuf bytes."""
        msg = vcsec_pb2.UnsignedMessage()
        if self.sub_message:
            msg.InformationRequest.ParseFromString(self.sub_message)
        return msg.SerializeToString()


# VCSEC Messages


@dataclass
class InformationRequest:
    """VCSEC information request."""

    request_type: InformationRequestType = InformationRequestType.GET_STATUS
    key_slot: int = 0
    public_key: bytes = field(default_factory=bytes)

    def encode(self) -> bytes:
        """Encode to protobuf bytes."""
        msg = vcsec_pb2.InformationRequest()
        msg.informationRequestType = self.request_type
        if self.key_slot:
            msg.slot = self.key_slot
        if self.public_key:
            msg.publicKey = self.public_key
        return msg.SerializeToString()


@dataclass
class RKEActionMessage:
    """Remote keyless entry action message."""

    action: RKEAction = RKEAction.WAKE_VEHICLE

    def encode(self) -> bytes:
        """Encode to protobuf bytes."""
        msg = vcsec_pb2.UnsignedMessage()
        msg.RKEAction = self.action
        return msg.SerializeToString()


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
        msg = vcsec_pb2.ClosureMoveRequest()
        if self.front_driver_door is not None:
            msg.frontDriverDoor = self.front_driver_door
        if self.front_passenger_door is not None:
            msg.frontPassengerDoor = self.front_passenger_door
        if self.rear_driver_door is not None:
            msg.rearDriverDoor = self.rear_driver_door
        if self.rear_passenger_door is not None:
            msg.rearPassengerDoor = self.rear_passenger_door
        if self.rear_trunk is not None:
            msg.rearTrunk = self.rear_trunk
        if self.front_trunk is not None:
            msg.frontTrunk = self.front_trunk
        if self.charge_port is not None:
            msg.chargePort = self.charge_port
        if self.tonneau is not None:
            msg.tonneau = self.tonneau
        return msg.SerializeToString()


@dataclass
class KeyMetadata:
    """Key metadata for registration."""

    key_form_factor: KeyFormFactor = KeyFormFactor.CLOUD_KEY
    key_name: str = ""

    def to_proto(self) -> vcsec_pb2.KeyMetadata:
        """Convert to protobuf message."""
        msg = vcsec_pb2.KeyMetadata()
        msg.keyFormFactor = self.key_form_factor
        if self.key_name:
            msg.keyName = self.key_name
        return msg


@dataclass
class WhitelistOperation:
    """Whitelist operation (add/remove key)."""

    public_key_to_add: bytes | None = None
    public_key_to_remove: bytes | None = None
    metadata_for_key: KeyMetadata | None = None

    def encode(self) -> bytes:
        """Encode to protobuf bytes."""
        msg = vcsec_pb2.WhitelistOperation()
        
        if self.public_key_to_add:
            public_key = vcsec_pb2.PublicKey()
            public_key.PublicKeyRaw = self.public_key_to_add
            
            # Create permission change with key
            perm = vcsec_pb2.PermissionChange()
            perm.key.CopyFrom(public_key)
            msg.addKeyToWhitelistAndAddPermissions.CopyFrom(perm)
            
        if self.public_key_to_remove:
            public_key = vcsec_pb2.PublicKey()
            public_key.PublicKeyRaw = self.public_key_to_remove
            msg.removePublicKeyFromWhitelist.CopyFrom(public_key)
            
        if self.metadata_for_key:
            msg.metadataForKey.CopyFrom(self.metadata_for_key.to_proto())
            
        return msg.SerializeToString()


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
        msg = vcsec_pb2.UnsignedMessage()
        
        if self.information_request:
            info_req = vcsec_pb2.InformationRequest()
            info_req.ParseFromString(self.information_request.encode())
            msg.InformationRequest.CopyFrom(info_req)
        elif self.rke_action:
            msg.RKEAction = self.rke_action.action
        elif self.closure_move_request:
            closure_req = vcsec_pb2.ClosureMoveRequest()
            closure_req.ParseFromString(self.closure_move_request.encode())
            msg.closureMoveRequest.CopyFrom(closure_req)
        elif self.whitelist_operation:
            whitelist_op = vcsec_pb2.WhitelistOperation()
            whitelist_op.ParseFromString(self.whitelist_operation.encode())
            msg.WhitelistOperation.CopyFrom(whitelist_op)
        elif self.signed_message:
            # For signed messages, return the signed message directly
            return self.signed_message
            
        return msg.SerializeToString()


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
    def from_proto(cls, proto: vcsec_pb2.ClosureStatuses) -> ClosureStatus:
        """Create from protobuf message."""
        return cls(
            front_driver_door=proto.frontDriverDoor,
            front_passenger_door=proto.frontPassengerDoor,
            rear_driver_door=proto.rearDriverDoor,
            rear_passenger_door=proto.rearPassengerDoor,
            rear_trunk=proto.rearTrunk,
            front_trunk=proto.frontTrunk,
            charge_port=proto.chargePort,
            tonneau=proto.tonneau,
        )


@dataclass
class VehicleStatus:
    """Vehicle status response."""

    closure_statuses: ClosureStatus | None = None
    lock_state: int = 0
    sleep_status: int = 0
    user_presence: bool = False

    @classmethod
    def from_proto(cls, proto: vcsec_pb2.VehicleStatus) -> VehicleStatus:
        """Create from protobuf message."""
        closure_status = None
        if proto.HasField("closureStatuses"):
            closure_status = ClosureStatus.from_proto(proto.closureStatuses)
            
        # Convert user_presence enum to bool
        user_presence = proto.userPresence == 2  # VEHICLE_USER_PRESENCE_PRESENT
            
        return cls(
            closure_statuses=closure_status,
            lock_state=proto.vehicleLockState,
            sleep_status=proto.vehicleSleepStatus,
            user_presence=user_presence,
        )


@dataclass
class CommandStatus:
    """Command status response."""

    operation_status: OperationStatus = OperationStatus.OK
    which_error: int = 0

    @classmethod
    def from_proto(cls, proto: vcsec_pb2.CommandStatus) -> CommandStatus:
        """Create from protobuf message."""
        which_error = 0
        if proto.HasField("signedMessageStatus"):
            which_error = proto.signedMessageStatus.signedMessageInformation
        elif proto.HasField("whitelistOperationStatus"):
            which_error = proto.whitelistOperationStatus.whitelistOperationInformation
            
        return cls(
            operation_status=OperationStatus(proto.operationStatus),
            which_error=which_error,
        )


@dataclass
class NominalError:
    """Generic error from vehicle."""

    generic_error: GenericError = GenericError.NONE

    @classmethod
    def from_proto(cls, proto: errors_pb2.NominalError) -> NominalError:
        """Create from protobuf message."""
        return cls(generic_error=GenericError(proto.genericError))


@dataclass
class VCSECResponse:
    """VCSEC response message."""

    vehicle_status: VehicleStatus | None = None
    command_status: CommandStatus | None = None
    whitelist_info: bytes | None = None
    whitelist_entry_info: bytes | None = None
    nominal_error: NominalError | None = None

    @classmethod
    def decode(cls, data: bytes) -> VCSECResponse:
        """Decode from protobuf bytes."""
        msg = vcsec_pb2.FromVCSECMessage()
        msg.ParseFromString(data)
        
        vehicle_status = None
        if msg.HasField("vehicleStatus"):
            vehicle_status = VehicleStatus.from_proto(msg.vehicleStatus)
            
        command_status = None
        if msg.HasField("commandStatus"):
            command_status = CommandStatus.from_proto(msg.commandStatus)
            
        whitelist_info = None
        if msg.HasField("whitelistInfo"):
            whitelist_info = msg.whitelistInfo.SerializeToString()
            
        whitelist_entry_info = None
        if msg.HasField("whitelistEntryInfo"):
            whitelist_entry_info = msg.whitelistEntryInfo.SerializeToString()
            
        nominal_error = None
        if msg.HasField("nominalError"):
            nominal_error = NominalError.from_proto(msg.nominalError)
            
        return cls(
            vehicle_status=vehicle_status,
            command_status=command_status,
            whitelist_info=whitelist_info,
            whitelist_entry_info=whitelist_entry_info,
            nominal_error=nominal_error,
        )
