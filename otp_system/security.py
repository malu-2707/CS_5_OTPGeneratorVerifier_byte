"""Security controls around verification.

* ``ReplayGuard``   - a code may be used only once (per identity)
* ``RateLimiter``   - lockout after repeated failures
* ``JsonStateStore``- atomic on-disk persistence so controls survive restarts
* ``AuditLogger``   - append-only JSON-lines log (never records secrets/codes)
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union

from .core import StateError

PathLike = Union[str, Path]


# --------------------------------------------------------------------------
# Replay protection
# --------------------------------------------------------------------------


class ReplayGuard:
    """Rejects any code whose counter is <= the last accepted counter.

    This is the approach recommended by RFC 6238 section 5.2: remembering a
    single integer per identity is enough to prevent reuse, needs O(1)
    memory, and never grows without bound.

    Side effect (by design): once a code from a *later* window has been
    accepted, earlier windows for that identity are no longer valid.
    """

    def __init__(self, last_counters: Optional[Dict[str, int]] = None) -> None:
        self._last: Dict[str, int] = dict(last_counters or {})

    def is_replay(self, identity: str, counter: int) -> bool:
        return counter <= self._last.get(identity, -1)

    def accept(self, identity: str, counter: int) -> None:
        if counter > self._last.get(identity, -1):
            self._last[identity] = counter

    def last_counter(self, identity: str) -> Optional[int]:
        return self._last.get(identity)

    def reset(self, identity: str) -> None:
        """Forget an identity (call this when its secret is rotated)."""
        self._last.pop(identity, None)

    def to_dict(self) -> Dict[str, int]:
        return dict(self._last)


# --------------------------------------------------------------------------
# Attempt limiting / lockout
# --------------------------------------------------------------------------


@dataclass
class AttemptState:
    failures: int = 0
    locked_until: int = 0


class RateLimiter:
    """Locks an identity for ``lockout_seconds`` after ``max_attempts``
    consecutive failures. A success clears the failure count."""

    def __init__(
        self,
        max_attempts: int,
        lockout_seconds: int,
        states: Optional[Dict[str, AttemptState]] = None,
    ) -> None:
        if max_attempts <= 0 or lockout_seconds <= 0:
            raise ValueError("max_attempts and lockout_seconds must be positive")
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self._states: Dict[str, AttemptState] = dict(states or {})

    def lock_remaining(self, identity: str, now: int) -> int:
        """Seconds left on the lockout; 0 if the identity is not locked."""
        state = self._states.get(identity)
        if state is None:
            return 0
        if state.locked_until > now:
            return state.locked_until - now
        if state.locked_until:  # lockout has elapsed: start fresh
            del self._states[identity]
        return 0

    def register_failure(self, identity: str, now: int) -> int:
        """Record a failure and return the attempts still remaining."""
        state = self._states.setdefault(identity, AttemptState())
        state.failures += 1
        if state.failures >= self.max_attempts:
            state.locked_until = now + self.lockout_seconds
        return self.remaining_attempts(identity)

    def register_success(self, identity: str) -> None:
        self._states.pop(identity, None)

    def remaining_attempts(self, identity: str) -> int:
        state = self._states.get(identity)
        if state is None:
            return self.max_attempts
        return max(0, self.max_attempts - state.failures)

    def reset(self, identity: str) -> None:
        self._states.pop(identity, None)

    def to_dict(self) -> Dict[str, Dict[str, int]]:
        return {name: asdict(state) for name, state in self._states.items()}

    @staticmethod
    def states_from_dict(data: Dict[str, Any]) -> Dict[str, AttemptState]:
        try:
            return {
                str(name): AttemptState(
                    failures=int(raw["failures"]),
                    locked_until=int(raw["locked_until"]),
                )
                for name, raw in data.items()
            }
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise StateError("attempt state is malformed") from exc


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------


class JsonStateStore:
    """Stores verifier state in a JSON file using atomic replacement.

    A corrupt file raises ``StateError`` instead of being silently reset:
    quietly discarding state would clear every lockout and replay record
    (a fail-open condition).

    Note: there is no cross-process locking. For concurrent servers use a
    database or Redis with atomic operations instead.
    """

    def __init__(self, path: PathLike) -> None:
        self.path = Path(path)

    def load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StateError(f"cannot read state file {self.path}: {exc}") from exc
        if not isinstance(data, dict):
            raise StateError(f"state file {self.path} has unexpected format")
        return data

    def save(self, data: Dict[str, Any]) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_name(self.path.name + ".tmp")
            tmp.write_text(
                json.dumps(data, indent=2, sort_keys=True), encoding="utf-8"
            )
            try:
                os.chmod(tmp, 0o600)  # best effort; no-op on some platforms
            except OSError:
                pass
            os.replace(tmp, self.path)  # atomic on POSIX and Windows
        except OSError as exc:
            raise StateError(f"cannot write state file {self.path}: {exc}") from exc


# --------------------------------------------------------------------------
# Audit log
# --------------------------------------------------------------------------


class AuditLogger:
    """Append-only JSON-lines audit trail.

    Only metadata is recorded (identity, outcome, drift, ...). Secrets and
    submitted codes are never written.
    """

    def __init__(self, path: PathLike) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: str, identity: str, **details: Any) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "identity": identity,
            **details,
        }
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")