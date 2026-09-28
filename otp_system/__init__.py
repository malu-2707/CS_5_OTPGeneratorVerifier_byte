"""OTP Generator and Verifier package."""

from .core import (
    OTPConfig,
    OTPError,
    ConfigurationError,
    SecretError,
    OTPInputError,
    StateError,
    TOTP,
    generate_secret,
    decode_secret,
    hotp,
    provisioning_uri,
)

from .security import (
    ReplayGuard,
    RateLimiter,
    JsonStateStore,
    AuditLogger,
)

from .verifier import (
    OTPVerifier,
    VerificationResult,
    Status,
)

__version__ = "1.0.0"

__all__ = [
    "OTPConfig",
    "OTPError",
    "ConfigurationError",
    "SecretError",
    "OTPInputError",
    "StateError",
    "TOTP",
    "generate_secret",
    "decode_secret",
    "hotp",
    "provisioning_uri",
    "ReplayGuard",
    "RateLimiter",
    "JsonStateStore",
    "AuditLogger",
    "OTPVerifier",
    "VerificationResult",
    "Status",
]
