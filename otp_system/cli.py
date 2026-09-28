"""Command-line interface.

    python -m otp_system secret
    python -m otp_system generate --secret <BASE32>
    python -m otp_system verify   --secret <BASE32> --code 123456
    python -m otp_system demo
    python -m otp_system vectors --output test_vectors.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .core import (
    OTPConfig,
    OTPError,
    TOTP,
    generate_secret,
    now,
    provisioning_uri,
)
from .security import AuditLogger, JsonStateStore
from .vectors import PROJECT_SECRET, export_vectors
from .verifier import OTPVerifier

DEFAULT_STATE_FILE = "state/otp_state.json"
DEFAULT_AUDIT_FILE = "audit/audit.log"


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    defaults = OTPConfig()

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--digits", type=int, default=defaults.digits)
    common.add_argument("--period", type=int, default=defaults.period,
                        help="time step in seconds")
    common.add_argument("--algorithm", default=defaults.algorithm,
                        choices=["sha1", "sha256", "sha512"])
    common.add_argument("--drift", type=int, default=defaults.drift,
                        help="periods accepted either side of now")
    common.add_argument("--max-attempts", type=int, default=defaults.max_attempts)
    common.add_argument("--lockout", type=int, default=defaults.lockout_seconds,
                        help="lockout length in seconds")

    parser = argparse.ArgumentParser(
        prog="otp_system",
        description="TOTP one-time password generator and verifier.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("secret", parents=[common], help="generate a random secret")
    p.set_defaults(func=cmd_secret)

    p = sub.add_parser("generate", parents=[common], help="generate the current OTP")
    p.add_argument("--secret", default=os.environ.get("OTP_SECRET"),
                   help="Base32 secret (or set OTP_SECRET to keep it out of "
                        "the process list)")
    p.add_argument("--timestamp", type=int, help="Unix time (default: now)")
    p.set_defaults(func=cmd_generate)

    p = sub.add_parser("verify", parents=[common], help="verify an OTP")
    p.add_argument("--secret", default=os.environ.get("OTP_SECRET"))
    p.add_argument("--code", required=True)
    p.add_argument("--identity", default="cli-user")
    p.add_argument("--timestamp", type=int, help="Unix time (default: now)")
    p.add_argument("--state-file", default=DEFAULT_STATE_FILE)
    p.add_argument("--audit-file", default=DEFAULT_AUDIT_FILE)
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("uri", parents=[common],
                       help="print an otpauth:// provisioning URI")
    p.add_argument("--secret", default=os.environ.get("OTP_SECRET"))
    p.add_argument("--account", required=True)
    p.add_argument("--issuer", default="OTP-Demo")
    p.set_defaults(func=cmd_uri)

    p = sub.add_parser("demo", parents=[common],
                       help="scripted walkthrough of every outcome")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("interactive", parents=[common],
                       help="generate a code and verify what you type")
    p.set_defaults(func=cmd_interactive)

    p = sub.add_parser("vectors", help="print or export test vectors as JSON")
    p.add_argument("--output", help="write to this file instead of stdout")
    p.set_defaults(func=cmd_vectors)

    return parser


def config_from_args(args: argparse.Namespace) -> OTPConfig:
    return OTPConfig(
        digits=args.digits,
        period=args.period,
        algorithm=args.algorithm,
        drift=args.drift,
        max_attempts=args.max_attempts,
        lockout_seconds=args.lockout,
    )


def require_secret(args: argparse.Namespace) -> str:
    if not args.secret:
        raise OTPError("no secret given: use --secret or set OTP_SECRET")
    return args.secret


# --------------------------------------------------------------------------
# Commands (each returns a process exit code)
# --------------------------------------------------------------------------


def cmd_secret(args: argparse.Namespace) -> int:
    config = config_from_args(args)
    print(generate_secret(config.algorithm))
    print("Store it securely; anyone with this value can generate valid codes.",
          file=sys.stderr)
    return 0


def cmd_generate(args: argparse.Namespace) -> int:
    config = config_from_args(args)
    totp = TOTP(config)
    secret = require_secret(args)
    timestamp = now() if args.timestamp is None else args.timestamp

    print(f"OTP        : {totp.code_at(secret, timestamp)}")
    print(f"Timestamp  : {timestamp}")
    print(f"Counter    : {totp.counter_at(timestamp)}")
    print(f"Expires in : {totp.seconds_remaining(timestamp)}s "
          f"(accepted for up to {config.acceptance_seconds}s with drift "
          f"+/-{config.drift})")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    verifier = OTPVerifier(
        config_from_args(args),
        store=JsonStateStore(args.state_file),
        audit=AuditLogger(args.audit_file),
    )
    result = verifier.verify(
        args.identity, require_secret(args), args.code, args.timestamp
    )
    print(f"Status   : {result.status.value}")
    print(f"Message  : {result.message}")
    if result.drift is not None:
        print(f"Drift    : {result.drift:+d} period(s)")
    if result.remaining_attempts is not None:
        print(f"Attempts : {result.remaining_attempts} remaining")
    return 0 if result.valid else 1


def cmd_uri(args: argparse.Namespace) -> int:
    print(provisioning_uri(require_secret(args), args.account, args.issuer,
                           config_from_args(args)))
    return 0


def cmd_vectors(args: argparse.Namespace) -> int:
    text = json.dumps(export_vectors(), indent=2)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
        print(f"Wrote test vectors to {path}")
    else:
        print(text)
    return 0


def cmd_interactive(args: argparse.Namespace) -> int:
    config = config_from_args(args)
    totp = TOTP(config)
    secret = input("Base32 secret (Enter to generate one): ").strip()
    if not secret:
        secret = generate_secret(config.algorithm)
        print(f"Generated secret: {secret}")

    print(f"Current OTP: {totp.code_at(secret)} "
          f"(changes in {totp.seconds_remaining()}s)")
    entered = input("Enter the OTP to verify: ")
    result = OTPVerifier(config).verify("interactive", secret, entered)
    print(f"Result: {result.status.value.upper()} - {result.message}")
    return 0 if result.valid else 1


def cmd_demo(args: argparse.Namespace) -> int:
    """Deterministic walkthrough: fixed secret, fixed clock, in-memory state."""
    config = config_from_args(args)
    totp = TOTP(config)
    verifier = OTPVerifier(config)
    secret = PROJECT_SECRET
    t0 = 1_700_000_000
    p = config.period
    wrong = "0" * config.digits

    def attempt(identity: str, label: str, code: str, ts: int) -> None:
        r = verifier.verify(identity, secret, code, ts)
        extra = f" drift={r.drift:+d}" if r.drift is not None else ""
        print(f"  [{identity:<5}] {label:<34} code={code}  "
              f"-> {r.status.value.upper()}{extra}")
        print(f"          {r.message}")

    print("=" * 72)
    print(" OTP DEMO - TOTP, HMAC-" + config.algorithm.upper())
    print("=" * 72)
    print(f" digits={config.digits}  period={p}s  drift=+/-{config.drift}  "
          f"max_attempts={config.max_attempts}  lockout={config.lockout_seconds}s")
    print(f" secret (demo only): {secret}")
    print(f" clock frozen at t0 = {t0}  (counter {totp.counter_at(t0)})")

    print("\n1) Correct code, then reuse (replay protection)")
    good = totp.code_at(secret, t0)
    attempt("alice", "correct code", good, t0)
    attempt("alice", "same code submitted again", good, t0 + 5)

    print("\n2) Clock drift tolerance")
    attempt("bob", "code from previous window", totp.code_at(secret, t0 - p), t0)
    stale_ts = t0 - (config.drift + 1) * p
    attempt("carol", f"code from {config.drift + 1} windows ago",
            totp.code_at(secret, stale_ts), t0)

    print("\n3) Malformed input (not counted as a failed attempt)")
    attempt("erin", "letters instead of digits",
            "12ab56" + "7" * (config.digits - 6), t0)

    print("\n4) Lockout after repeated failures, then recovery")
    for n in range(1, config.max_attempts + 1):
        attempt("dave", f"wrong code #{n}", wrong, t0 + n)
    attempt("dave", "correct code while locked",
            totp.code_at(secret, t0 + config.max_attempts + 1),
            t0 + config.max_attempts + 1)
    t_after = t0 + config.max_attempts + config.lockout_seconds + 1
    attempt("dave", "correct code after lockout ends",
            totp.code_at(secret, t_after), t_after)
    print()
    return 0


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except OTPError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())