"""
mac.py — Core HMAC-SHA256 MAC generation and verification
Project Lead & Architect Module
"""

import hmac
import hashlib
import base64

from config import (
    HASH_ALGORITHM,
    MAC_ENCODING,
    MESSAGE_ENCODING,
    SECRET_ENCODING,
)


# ── Internal helpers ───────────────────────────────────────────────────────────

def _to_bytes(value: str | bytes, encoding: str) -> bytes:
    """Coerce a str or bytes value to bytes."""
    if isinstance(value, bytes):
        return value
    return value.encode(encoding)


def _encode_mac(raw_mac: bytes) -> str:
    """Encode raw HMAC digest bytes to the configured string representation."""
    if MAC_ENCODING == "hex":
        return raw_mac.hex()
    elif MAC_ENCODING == "base64":
        return base64.b64encode(raw_mac).decode("ascii")
    else:
        raise ValueError(f"Unsupported MAC_ENCODING: {MAC_ENCODING!r}. Use 'hex' or 'base64'.")


def _decode_mac(encoded_mac: str) -> bytes:
    """Decode a MAC string back to raw bytes for constant-time comparison."""
    if MAC_ENCODING == "hex":
        return bytes.fromhex(encoded_mac)
    elif MAC_ENCODING == "base64":
        return base64.b64decode(encoded_mac)
    else:
        raise ValueError(f"Unsupported MAC_ENCODING: {MAC_ENCODING!r}. Use 'hex' or 'base64'.")


# ── Public API ─────────────────────────────────────────────────────────────────

def generate_mac(message: str | bytes, secret: str | bytes) -> str:
    """
    Compute an HMAC-SHA256 MAC for *message* using *secret*.

    Parameters
    ----------
    message : str | bytes
        The plaintext message to authenticate.
    secret  : str | bytes
        The shared secret key.

    Returns
    -------
    str
        The MAC encoded as a hex string (or base64, per config.MAC_ENCODING).

    Example
    -------
    >>> mac = generate_mac("Hello, Bob!", "supersecret")
    >>> print(mac)   # e.g. 'a3f1...'
    """
    msg_bytes    = _to_bytes(message, MESSAGE_ENCODING)
    secret_bytes = _to_bytes(secret,  SECRET_ENCODING)

    h = hmac.new(secret_bytes, msg_bytes, hashlib.sha256)
    return _encode_mac(h.digest())


def verify_mac(message: str | bytes, secret: str | bytes, received_mac: str) -> bool:
    """
    Verify that *received_mac* is a valid MAC for *message* under *secret*.

    Uses ``hmac.compare_digest`` for constant-time comparison to prevent
    timing-based side-channel attacks.

    Parameters
    ----------
    message      : str | bytes
        The plaintext message that was authenticated.
    secret       : str | bytes
        The shared secret key.
    received_mac : str
        The MAC string received from the sender.

    Returns
    -------
    bool
        True if the MAC is valid, False otherwise.

    Example
    -------
    >>> verify_mac("Hello, Bob!", "supersecret", received_mac)
    True
    """
    expected_bytes = _decode_mac(generate_mac(message, secret))
    try:
        received_bytes = _decode_mac(received_mac)
    except (ValueError, Exception):
        # Malformed MAC — fail safely
        return False

    return hmac.compare_digest(expected_bytes, received_bytes)
