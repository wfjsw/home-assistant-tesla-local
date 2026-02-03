"""Cryptographic operations for Tesla BLE protocol."""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import struct
import time
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
    )

_LOGGER = logging.getLogger(__name__)

# AES-GCM constants
NONCE_LENGTH = 12
TAG_LENGTH = 16


def generate_key_pair() -> tuple[bytes, bytes]:
    """Generate a new ECDH P-256 key pair.

    Returns:
        Tuple of (private_key_bytes, public_key_bytes) in DER format.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return private_bytes, public_bytes


def load_private_key(private_bytes: bytes) -> EllipticCurvePrivateKey:
    """Load a private key from DER bytes."""
    return serialization.load_der_private_key(private_bytes, password=None)


def load_public_key(public_bytes: bytes) -> EllipticCurvePublicKey:
    """Load a public key from uncompressed point bytes."""
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_bytes)


def get_public_key_bytes(private_key: EllipticCurvePrivateKey) -> bytes:
    """Get public key bytes from private key."""
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def compute_shared_secret(
    private_key: EllipticCurvePrivateKey,
    peer_public_key: EllipticCurvePublicKey,
) -> bytes:
    """Compute ECDH shared secret.

    Returns the raw x-coordinate of the shared point (32 bytes).
    """
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_key


def derive_session_key(shared_secret: bytes) -> bytes:
    """Derive session key from shared secret using SHA1.

    This matches the reference implementation in vehicle-command:
    session.key = SHA1(shared_secret)[:16]
    """
    digest = hashlib.sha1(shared_secret).digest()
    return digest[:16]  # First 16 bytes (128 bits)


class TeslaCrypto:
    """Handle cryptographic operations for Tesla BLE."""

    def __init__(
        self,
        private_key_bytes: bytes,
        vehicle_public_key_bytes: bytes | None = None,
    ) -> None:
        """Initialize with private key and optionally vehicle public key."""
        self._private_key = load_private_key(private_key_bytes)
        self._public_key_bytes = get_public_key_bytes(self._private_key)
        self._vehicle_public_key: EllipticCurvePublicKey | None = None
        self._shared_secret: bytes | None = None
        self._session_key: bytes | None = None
        self._epoch: bytes = b""
        self._counter: int = 0
        self._time_zero: int = 0
        self._clock_offset: int = 0

        if vehicle_public_key_bytes:
            self.set_vehicle_public_key(vehicle_public_key_bytes)

    @property
    def public_key_bytes(self) -> bytes:
        """Return the public key as uncompressed point bytes."""
        return self._public_key_bytes

    @property
    def has_session(self) -> bool:
        """Check if we have an active session."""
        return self._session_key is not None

    def set_vehicle_public_key(self, public_key_bytes: bytes) -> None:
        """Set vehicle's public key and compute shared secret and session key.

        The session key is derived using SHA1 of the shared secret, matching
        the reference implementation in vehicle-command/internal/authentication/native.go:
        session.key = SHA1(shared_secret)[:16]
        """
        self._vehicle_public_key = load_public_key(public_key_bytes)
        self._shared_secret = compute_shared_secret(
            self._private_key, self._vehicle_public_key
        )
        # Derive session key immediately using SHA1 (NOT HKDF!)
        # This matches the reference: digest := sha1.Sum(sharedSecret); session.key = digest[:16]
        self._session_key = derive_session_key(self._shared_secret)
        _LOGGER.debug("Computed shared secret and session key with vehicle")

    def initialize_session(
        self,
        epoch: bytes,
        time_zero: int,
        counter: int,
    ) -> None:
        """Initialize session with vehicle's session info.

        Note: The session key is derived when set_vehicle_public_key is called.
        This method sets the epoch, counter, and time synchronization info.
        """
        self._epoch = epoch
        self._time_zero = time_zero
        self._counter = counter
        # Calculate clock offset (vehicle time_zero is seconds since epoch start)
        self._clock_offset = int(time.time()) - time_zero
        _LOGGER.debug(
            "Session initialized: epoch=%s, counter=%d, clock_offset=%d, has_key=%s",
            epoch.hex(),
            counter,
            self._clock_offset,
            self._session_key is not None,
        )

    def get_current_timestamp(self) -> int:
        """Get current timestamp in vehicle time."""
        return int(time.time()) - self._clock_offset

    def increment_counter(self) -> int:
        """Increment and return the counter."""
        self._counter += 1
        return self._counter

    def encrypt_message(
        self,
        plaintext: bytes,
        associated_data: bytes | None = None,
        counter: int | None = None,
    ) -> tuple[bytes, bytes, int]:
        """Encrypt a message using AES-GCM.

        Args:
            plaintext: The data to encrypt.
            associated_data: Optional authenticated data.
            counter: Counter value to use. If None, increments and uses next counter.

        Returns:
            Tuple of (ciphertext_with_tag, nonce, counter_used)
        """
        if not self._session_key:
            raise ValueError("No session key available")

        if counter is None:
            counter = self.increment_counter()

        # Build nonce: 4-byte counter (little-endian) + 8 random bytes
        counter_bytes = struct.pack("<I", counter)
        random_bytes = os.urandom(8)
        nonce = counter_bytes + random_bytes

        aesgcm = AESGCM(self._session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

        return ciphertext, nonce, counter

    def decrypt_message(
        self,
        ciphertext: bytes,
        nonce: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypt a message using AES-GCM.

        Uses the same session key as encryption - the reference implementation
        uses a single GCM cipher for both directions.
        """
        if not self._session_key:
            raise ValueError("No session key available")

        aesgcm = AESGCM(self._session_key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)

    def compute_hmac(
        self,
        data: bytes,
    ) -> bytes:
        """Compute HMAC-SHA256 for data."""
        if not self._session_key:
            raise ValueError("No session key available")

        return hmac.new(self._session_key, data, hashlib.sha256).digest()[:16]

    def create_signature_data(
        self,
        expiration_seconds: int = 15,
    ) -> dict:
        """Create signature data for a message.

        Returns:
            Dict with signature fields for message.
        """
        if not self._session_key:
            raise ValueError("No session key available")

        counter = self.increment_counter()
        expires_at = self.get_current_timestamp() + expiration_seconds

        return {
            "epoch": self._epoch,
            "counter": counter,
            "expires_at": expires_at,
        }


def compute_vin_hash(vin: str) -> str:
    """Compute the BLE local name hash from VIN.

    Tesla vehicles broadcast as "S" + first 8 hex chars of SHA1(VIN) + "C"
    """
    vin_hash = hashlib.sha1(vin.encode()).hexdigest()[:16]
    return f"S{vin_hash}C"


def vin_from_local_name(local_name: str) -> str | None:
    """Extract VIN hash from BLE local name.

    Returns None if not a valid Tesla local name format.
    """
    if (
        local_name
        and len(local_name) == 18
        and local_name.startswith("S")
        and local_name.endswith("C")
    ):
        return local_name[1:17]
    return None
