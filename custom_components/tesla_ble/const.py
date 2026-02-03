"""Constants for Tesla BLE integration."""
from __future__ import annotations

from enum import IntEnum
from typing import Final

DOMAIN: Final = "tesla_ble"

# BLE UUIDs
TESLA_SERVICE_UUID: Final = "00000211-b2d1-43f0-9b88-960cebf8b91e"
TESLA_TX_CHAR_UUID: Final = "00000212-b2d1-43f0-9b88-960cebf8b91e"
TESLA_RX_CHAR_UUID: Final = "00000213-b2d1-43f0-9b88-960cebf8b91e"

# Alternative service UUID that some Tesla vehicles advertise
TESLA_ALT_SERVICE_UUID: Final = "00001122-0000-1000-8000-00805f9b34fb"

# All service UUIDs to look for
TESLA_SERVICE_UUIDS: Final = frozenset([
    TESLA_SERVICE_UUID.lower(),
    TESLA_ALT_SERVICE_UUID.lower(),
])


def is_tesla_device_name(name: str | None) -> bool:
    """Check if a BLE device name matches Tesla's naming pattern.

    Tesla vehicles broadcast as "S" + 16 hex chars (SHA1 of VIN) + "C"
    Example: "S1a2b3c4d5e6f7a8bC"
    """
    if not name or len(name) != 18:
        return False
    if not name.startswith("S") or not name.endswith("C"):
        return False
    # Check middle 16 chars are hex
    try:
        int(name[1:17], 16)
        return True
    except ValueError:
        return False

# Protocol constants
MAX_MESSAGE_SIZE: Final = 1024
RX_TIMEOUT: Final = 1.0  # seconds
MAX_CLOCK_LATENCY: Final = 4  # seconds
CONNECTION_TIMEOUT: Final = 30.0  # seconds

# Config keys
CONF_VIN: Final = "vin"
CONF_PRIVATE_KEY: Final = "private_key"
CONF_PUBLIC_KEY: Final = "public_key"
CONF_KEY_NAME: Final = "key_name"

# Options keys
CONF_SCAN_INTERVAL: Final = "scan_interval"

# Update intervals
DEFAULT_SCAN_INTERVAL: Final = 60  # seconds
MIN_SCAN_INTERVAL: Final = 30  # seconds
MAX_SCAN_INTERVAL: Final = 600  # seconds (10 minutes)


class Domain(IntEnum):
    """Message domain types."""

    BROADCAST = 0
    VEHICLE_SECURITY = 2
    INFOTAINMENT = 3


class OperationStatus(IntEnum):
    """Operation status values."""

    OK = 0
    WAIT = 1
    ERROR = 2


class SignatureType(IntEnum):
    """Signature validation modes."""

    NONE = 0
    PRESENT_KEY = 2
    AES_GCM = 5
    AES_GCM_PERSONALIZED = 6
    HMAC = 8
    HMAC_PERSONALIZED = 9
    AES_GCM_RESPONSE = 10


class RKEAction(IntEnum):
    """Remote keyless entry actions."""

    UNLOCK = 0
    LOCK = 1
    REMOTE_DRIVE = 20
    AUTO_SECURE_VEHICLE = 29
    WAKE_VEHICLE = 30


class KeyFormFactor(IntEnum):
    """Key device form factors."""

    UNKNOWN = 0
    NFC_CARD = 1
    IOS_DEVICE = 6
    ANDROID_DEVICE = 7
    CLOUD_KEY = 9


class ClosureState(IntEnum):
    """Closure state values."""

    CLOSED = 0
    OPEN = 1
    AJAR = 2
    UNKNOWN = 3
    FAILED_UNLATCH = 4
    OPENING = 5
    CLOSING = 6


class VehicleLockState(IntEnum):
    """Vehicle lock state values."""

    UNLOCKED = 0
    LOCKED = 1
    INTERNAL_LOCKED = 2
    SELECTIVE_UNLOCKED = 3


class VehicleSleepStatus(IntEnum):
    """Vehicle sleep status values."""

    UNKNOWN = 0
    AWAKE = 1
    ASLEEP = 2


class InformationRequestType(IntEnum):
    """Information request types."""

    GET_STATUS = 0
    GET_WHITELIST_INFO = 1
    GET_WHITELIST_ENTRY_INFO = 2


class WhitelistOperationType(IntEnum):
    """Whitelist operation types."""

    ADD_KEY = 0
    REMOVE_KEY = 1
    ADD_KEY_PERMISSIONS = 2
    REMOVE_KEY_PERMISSIONS = 3
    ADD_KEY_TO_WHITELIST = 4


class ClosureMoveType(IntEnum):
    """Closure move types."""

    MOVE = 0
    STOP = 1
    OPEN = 2
    CLOSE = 3


class HVACAction(IntEnum):
    """HVAC action values."""

    OFF = 0
    ON = 1
    DOG = 2
    CAMP = 3


class ChargingAction(IntEnum):
    """Charging action values."""

    START = 0
    STOP = 1
    START_STANDARD = 2
    START_MAX_RANGE = 3


class GenericError(IntEnum):
    """Generic error codes from vehicle."""

    NONE = 0
    UNKNOWN = 1
    CLOSURES_OPEN = 2
    ALREADY_ON = 3
    DISABLED_FOR_USER_COMMAND = 4
    VEHICLE_NOT_IN_PARK = 5
    UNAUTHORIZED = 6
    NOT_ALLOWED_OVER_TRANSPORT = 7
