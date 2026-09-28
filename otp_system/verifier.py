"""OTP verification with drift tolerance, replay protection and lockout."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

from .core import (
    OTPConfig,
    OTPInputError,
    TOTP,
    decode_secret,
    hotp,
    now,
)
from .security import AuditLogger, JsonStateStore, RateLimiter, ReplayGuard

STATE_VERSION = 1


class Status(str, Enum):
    SUCCESS = "success"
    INVALID = "invalid"
    REPLAY = "replay"
    LOCKED = "locked"
    INVALID_INPUT = "invalid_input"


@dataclass(frozen=True)
class VerificationResult:
    status: Status
    message: str
    matched_counter: Optional[int] = None
    drift: Optional[int] = None
    remaining_attempts: Optional[int] = None
    retry_after: int = 0

    @property
    def valid(self) -> bool:
        return self.status is Status.SUCCESS

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "valid": self.valid,
            "message": self.message,
            "matched_counter": self.matched_counter,
            "drift": self.drift,
            "remaining_attempts": self.remaining_attempts,
            "retry_after": self.retry_after,
        }


def normalize_code(code: str, digits: int) -> str:
    """Strip whitespace and check the code is exactly ``digits`` ASCII digits."""
    if not isinstance(code, str):
        raise OTPInputError("OTP must be supplied as text")
    cleaned = "".join(code.split())
    if len(cleaned) != digits:
        raise OTPInputError(f"OTP must contain exactly {digits} digits")
    # str.isdigit() alone also accepts non-ASCII digits, so check both.
    if not (cleaned.isascii() and cleaned.isdigit()):
        raise OTPInputError("OTP must contain digits only")
    return cleaned


class OTPVerifier:
    """Verifies TOTP codes.

    Order of checks in ``verify``:
      1. lockout       - a locked identity is refused without evaluating the code
      2. format        - malformed input is rejected (not counted as a failure)
      3. window match  - every window in [now - drift, now + drift] is computed
                         and compared in constant time, with no early exit
      4. replay        - a matching counter must be newer than the last used one
      5. bookkeeping   - success clears failures; failure counts toward lockout

    Expired codes are reported as ``invalid`` on purpose: distinguishing
    "expired" from "wrong" would give an attacker a free oracle.
    """

    def __init__(
        self,
        config: Optional[OTPConfig] = None,
        store: Optional[JsonStateStore] = None,
        audit: Optional[AuditLogger] = None,
    ) -> None:
        self.config = config or OTPConfig()
        self.totp = TOTP(self.config)
        self.store = store
        self.audit = audit

        state = store.load() if store else {}
        self.replay = ReplayGuard(state.get("replay", {}))
        self.limiter = RateLimiter(
            self.config.max_attempts,
            self.config.lockout_seconds,
            RateLimiter.states_from_dict(state.get("attempts", {})),
        )

    # -- public API --------------------------------------------------------

    def verify(
        self,
        identity: str,
        secret: str,
        code: str,
        timestamp: Optional[int] = None,
    ) -> VerificationResult:
        """Verify ``code`` for ``identity``.

        ``timestamp`` exists for tests and demos; production callers should
        leave it unset so the server clock is used.
        """
        if not isinstance(identity, str) or not identity:
            raise ValueError("identity must be a non-empty string")

        key = decode_secret(secret)  # raises SecretError on a bad secret
        current_time = now() if timestamp is None else int(timestamp)

        # 1. Lockout
        locked_for = self.limiter.lock_remaining(identity, current_time)
        if locked_for:
            self._log("rate_limited", identity, retry_after=locked_for)
            return VerificationResult(
                Status.LOCKED,
                f"Too many failed attempts. Try again in {locked_for}s.",
                remaining_attempts=0,
                retry_after=locked_for,
            )

        # 2. Format
        try:
            candidate = normalize_code(code, self.config.digits)
        except OTPInputError as exc:
            self._log("invalid_input", identity)
            return VerificationResult(
                Status.INVALID_INPUT,
                str(exc),
                remaining_attempts=self.limiter.remaining_attempts(identity),
            )

        # 3. Window match: no early exit, so timing does not reveal which
        #    window (if any) matched.
        current_counter = self.totp.counter_at(current_time)
        candidate_bytes = candidate.encode("ascii")
        matches = []
        for drift in range(-self.config.drift, self.config.drift + 1):
            counter = current_counter + drift
            if counter < 0:
                continue
            expected = hotp(
                key, counter, self.config.digits, self.config.algorithm
            ).encode("ascii")
            if hmac.compare_digest(expected, candidate_bytes):
                matches.append((counter, drift))

        # 4. Replay
        fresh = [m for m in matches if not self.replay.is_replay(identity, m[0])]
        if fresh:
            counter, drift = min(fresh)
            self.replay.accept(identity, counter)
            self.limiter.register_success(identity)
            self._persist()
            self._log("verification_success", identity, drift=drift)
            return VerificationResult(
                Status.SUCCESS,
                "OTP verified.",
                matched_counter=counter,
                drift=drift,
                remaining_attempts=self.limiter.remaining_attempts(identity),
            )

        # 5. Failure bookkeeping
        remaining = self.limiter.register_failure(identity, current_time)
        self._persist()

        if matches:
            status, message, event = (
                Status.REPLAY,
                "This OTP has already been used.",
                "replay_blocked",
            )
        else:
            status, message, event = (
                Status.INVALID,
                "Invalid OTP.",
                "verification_failed",
            )

        retry_after = 0
        if remaining == 0:
            retry_after = self.limiter.lock_remaining(identity, current_time)
            message += f" Account locked for {retry_after}s."
            self._log("lockout_started", identity, lockout_seconds=retry_after)

        self._log(event, identity, remaining_attempts=remaining)
        return VerificationResult(
            status,
            message,
            remaining_attempts=remaining,
            retry_after=retry_after,
        )

    def reset_identity(self, identity: str) -> None:
        """Clear replay/attempt state (e.g. after secret rotation or admin unlock)."""
        self.replay.reset(identity)
        self.limiter.reset(identity)
        self._persist()
        self._log("identity_reset", identity)

    # -- internals ---------------------------------------------------------

    def _persist(self) -> None:
        if self.store is not None:
            self.store.save(
                {
                    "version": STATE_VERSION,
                    "replay": self.replay.to_dict(),
                    "attempts": self.limiter.to_dict(),
                }
            )

    def _log(self, event: str, identity: str, **details: Any) -> None:
        if self.audit is not None:
            self.audit.log(event, identity, **details)