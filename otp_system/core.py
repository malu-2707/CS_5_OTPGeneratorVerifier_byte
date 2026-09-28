"""Core OTP primitives: HOTP (RFC 4226) and TOTP (RFC 6238).

This module contains no state and performs no I/O. It provides:

* ``OTPConfig``   - validated, immutable configuration
* secret helpers  - generation and strict Base32 decoding
* ``hotp``        - the counter-based HMAC one-time password function
* ``TOTP``        - time-based wrapper around ``hotp``
* ``provisioning_uri`` - otpauth:// URI for authenticator apps
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import quote, urlencode

# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------


class OTPError(Exception):
    """Base class for all errors raised by this package."""


class ConfigurationError(OTPError):
    """Invalid configuration value."""


class SecretError(OTPError):
    """Invalid or unusable shared secret."""


class OTPInputError(OTPError):
    """Malformed user-supplied OTP."""


class StateError(OTPError):
    """Persistent state could not be read or written safely."""


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

HASHES = {
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}

# RFC 4226 section 4: shared secrets MUST be at least 128 bits.
MIN_SECRET_BYTES = 16


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def _check_int(name: str, value: object, low: int, high: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{name} must be an integer")
    if not low <= value <= high:
        raise ConfigurationError(
            f"{name} must be between {low} and {high} (got {value})"
        )


@dataclass(frozen=True)
class OTPConfig:
    """Immutable, validated OTP parameters.

    digits           Length of the OTP (6-8).
    period           Time step in seconds; one code per period (10-300).
    algorithm        HMAC hash: sha1, sha256 (default) or sha512.
    drift            Number of periods accepted on each side of "now".
    max_attempts     Consecutive failures allowed before lockout.
    lockout_seconds  Length of the lockout after max_attempts failures.
    """

    digits: int = 6
    period: int = 30
    algorithm: str = "sha256"
    drift: int = 1
    max_attempts: int = 5
    lockout_seconds: int = 300

    def __post_init__(self) -> None:
        if (
            not isinstance(self.algorithm, str)
            or self.algorithm.lower() not in HASHES
        ):
            raise ConfigurationError(
                f"algorithm must be one of: {', '.join(sorted(HASHES))}"
            )
        object.__setattr__(self, "algorithm", self.algorithm.lower())

        _check_int("digits", self.digits, 6, 8)
        _check_int("period", self.period, 10, 300)
        _check_int("drift", self.drift, 0, 5)
        _check_int("max_attempts", self.max_attempts, 1, 100)
        _check_int("lockout_seconds", self.lockout_seconds, 1, 86_400)

    @property
    def acceptance_seconds(self) -> int:
        """How long (at most) a given code stays acceptable.

        A code belongs to one period, but the verifier also accepts codes
        from ``drift`` periods before and after the current one, so a code
        is acceptable for (2 * drift + 1) periods in total.
        """
        return (2 * self.drift + 1) * self.period


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------


def generate_secret(algorithm: str = "sha256") -> str:
    """Return a new random Base32 secret (no padding).

    The key length equals the hash output size (RFC 6238 section 5.1):
    20 bytes for SHA-1, 32 for SHA-256, 64 for SHA-512.
    """
    algorithm = algorithm.lower()
    if algorithm not in HASHES:
        raise ConfigurationError(f"unsupported algorithm: {algorithm}")
    size = HASHES[algorithm]().digest_size
    return base64.b32encode(secrets.token_bytes(size)).decode("ascii").rstrip("=")


def decode_secret(secret: str) -> bytes:
    """Strictly decode a Base32 secret into raw key bytes.

    Spaces and hyphens (common in displayed secrets) are ignored and the
    input is case-insensitive. Secrets shorter than 128 bits are rejected.
    """
    if not isinstance(secret, str):
        raise SecretError("secret must be a string")

    cleaned = secret.replace(" ", "").replace("-", "").upper().rstrip("=")
    if not cleaned:
        raise SecretError("secret cannot be empty")

    cleaned += "=" * (-len(cleaned) % 8)
    try:
        key = base64.b32decode(cleaned)
    except ValueError as exc:  # binascii.Error is a ValueError subclass
        raise SecretError("secret is not valid Base32") from exc

    if len(key) < MIN_SECRET_BYTES:
        raise SecretError(
            f"secret must decode to at least {MIN_SECRET_BYTES} bytes "
            f"({MIN_SECRET_BYTES * 8} bits); got {len(key)}"
        )
    return key


# --------------------------------------------------------------------------
# HOTP / TOTP
# --------------------------------------------------------------------------


def hotp(
    key: bytes,
    counter: int,
    digits: int = 6,
    algorithm: str = "sha256",
) -> str:
    """Compute an HOTP value (RFC 4226 section 5.3).

    1. HMAC(key, counter as 8-byte big-endian integer)
    2. Dynamic truncation: the low 4 bits of the last byte select an offset;
       4 bytes from that offset, with the top bit cleared, form a 31-bit int
    3. Reduce modulo 10**digits and left-pad with zeros
    """
    if not 0 <= counter < 2**64:
        raise ValueError("counter must fit in an unsigned 64-bit integer")

    digest = hmac.new(
        key, counter.to_bytes(8, "big"), HASHES[algorithm]
    ).digest()

    offset = digest[-1] & 0x0F
    binary = int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF
    return str(binary % 10**digits).zfill(digits)


def now() -> int:
    """Current Unix time in whole seconds."""
    return int(time.time())


class TOTP:
    """Time-based OTP generator (RFC 6238)."""

    def __init__(self, config: Optional[OTPConfig] = None) -> None:
        self.config = config or OTPConfig()

    def counter_at(self, timestamp: Optional[int] = None) -> int:
        """Time-step counter T = floor(unix_time / period)."""
        if timestamp is None:
            timestamp = now()
        if timestamp < 0:
            raise ValueError("timestamp cannot be negative")
        return timestamp // self.config.period

    def code_for_counter(self, secret: str, counter: int) -> str:
        return hotp(
            decode_secret(secret),
            counter,
            self.config.digits,
            self.config.algorithm,
        )

    def code_at(self, secret: str, timestamp: Optional[int] = None) -> str:
        return self.code_for_counter(secret, self.counter_at(timestamp))

    def seconds_remaining(self, timestamp: Optional[int] = None) -> int:
        """Seconds until the current code's period ends."""
        if timestamp is None:
            timestamp = now()
        return self.config.period - (timestamp % self.config.period)


def provisioning_uri(
    secret: str,
    account: str,
    issuer: str,
    config: Optional[OTPConfig] = None,
) -> str:
    """Build an ``otpauth://`` URI (the payload of an authenticator QR code)."""
    config = config or OTPConfig()
    normalized = base64.b32encode(decode_secret(secret)).decode().rstrip("=")
    label = quote(f"{issuer}:{account}", safe="")
    query = urlencode(
        {
            "secret": normalized,
            "issuer": issuer,
            "algorithm": config.algorithm.upper(),
            "digits": config.digits,
            "period": config.period,
        },
        quote_via=quote,
    )
    return f"otpauth://totp/{label}?{query}"