"""Run with:  python -m unittest discover -s tests -v"""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from otp_system import (
    AuditLogger,
    ConfigurationError,
    JsonStateStore,
    OTPConfig,
    OTPVerifier,
    SecretError,
    StateError,
    Status,
    TOTP,
    decode_secret,
    generate_secret,
    hotp,
    provisioning_uri,
)
from otp_system.cli import main as cli_main
from otp_system.vectors import (
    PROJECT_SECRET,
    rfc4226_vectors,
    rfc6238_vectors,
)

SECRET = PROJECT_SECRET
T0 = 1_700_000_000


# --------------------------------------------------------------------------
# Standards conformance
# --------------------------------------------------------------------------


class TestRFCVectors(unittest.TestCase):
    def test_rfc4226_hotp(self):
        for v in rfc4226_vectors():
            with self.subTest(counter=v["counter"]):
                got = hotp(decode_secret(v["secret_base32"]), v["counter"], 6, "sha1")
                self.assertEqual(got, v["expected_otp"])

    def test_rfc6238_totp(self):
        for v in rfc6238_vectors():
            with self.subTest(alg=v["algorithm"], t=v["timestamp"]):
                totp = TOTP(OTPConfig(digits=8, period=30, algorithm=v["algorithm"]))
                self.assertEqual(
                    totp.code_at(v["secret_base32"], v["timestamp"]),
                    v["expected_otp"],
                )


# --------------------------------------------------------------------------
# Configuration and secrets
# --------------------------------------------------------------------------


class TestConfigAndSecrets(unittest.TestCase):
    def test_defaults_are_valid(self):
        config = OTPConfig()
        self.assertEqual(config.acceptance_seconds, 90)

    def test_invalid_config_rejected(self):
        bad = [
            {"digits": 5}, {"digits": 9}, {"period": 5}, {"period": 301},
            {"drift": -1}, {"drift": 6}, {"max_attempts": 0},
            {"lockout_seconds": 0}, {"algorithm": "md5"}, {"digits": True},
            {"digits": "6"},
        ]
        for kwargs in bad:
            with self.subTest(**kwargs):
                with self.assertRaises(ConfigurationError):
                    OTPConfig(**kwargs)

    def test_generate_secret(self):
        a, b = generate_secret(), generate_secret()
        self.assertNotEqual(a, b)
        self.assertEqual(len(decode_secret(a)), 32)
        self.assertEqual(len(decode_secret(generate_secret("sha1"))), 20)
        self.assertEqual(len(decode_secret(generate_secret("sha512"))), 64)

    def test_decode_secret_tolerates_formatting(self):
        plain = decode_secret(SECRET)
        self.assertEqual(decode_secret(SECRET.lower()), plain)
        spaced = " ".join(SECRET[i:i + 4] for i in range(0, len(SECRET), 4))
        self.assertEqual(decode_secret(spaced), plain)

    def test_bad_secrets_rejected(self):
        for bad in ["", "   ", "not base32!", "JBSWY3DPEHPK3PXP", "1" * 40, None, 123]:
            with self.subTest(bad=bad):
                with self.assertRaises(SecretError):
                    decode_secret(bad)

    def test_generation_is_deterministic_and_windowed(self):
        totp = TOTP()
        self.assertEqual(totp.code_at(SECRET, T0), totp.code_at(SECRET, T0))
        # Same 30 s window -> same code
        start = (T0 // 30) * 30
        self.assertEqual(totp.code_at(SECRET, start), totp.code_at(SECRET, start + 29))
        self.assertNotEqual(totp.code_at(SECRET, start), totp.code_at(SECRET, start + 30))

    def test_digits_and_leading_zeros(self):
        for digits in (6, 7, 8):
            totp = TOTP(OTPConfig(digits=digits))
            for t in range(0, 3000, 30):
                code = totp.code_at(SECRET, t)
                self.assertEqual(len(code), digits)
                self.assertTrue(code.isdigit())

    def test_seconds_remaining(self):
        totp = TOTP()
        self.assertEqual(totp.seconds_remaining(60), 30)
        self.assertEqual(totp.seconds_remaining(89), 1)

    def test_negative_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            TOTP().code_at(SECRET, -1)

    def test_provisioning_uri(self):
        uri = provisioning_uri(SECRET, "alice@example.com", "My App")
        self.assertTrue(uri.startswith("otpauth://totp/My%20App%3Aalice%40example.com?"))
        for part in ("algorithm=SHA256", "digits=6", "period=30", f"secret={SECRET}"):
            self.assertIn(part, uri)


# --------------------------------------------------------------------------
# Verification behaviour
# --------------------------------------------------------------------------


class TestVerifier(unittest.TestCase):
    def setUp(self):
        self.config = OTPConfig(max_attempts=3, lockout_seconds=60)
        self.totp = TOTP(self.config)
        self.verifier = OTPVerifier(self.config)

    def code(self, offset_seconds=0):
        return self.totp.code_at(SECRET, T0 + offset_seconds)

    def test_correct_code_accepted(self):
        r = self.verifier.verify("u", SECRET, self.code(), T0)
        self.assertTrue(r.valid)
        self.assertEqual(r.status, Status.SUCCESS)
        self.assertEqual(r.drift, 0)
        self.assertEqual(r.matched_counter, T0 // 30)

    def test_wrong_code_rejected(self):
        wrong = "000000" if self.code() != "000000" else "000001"
        r = self.verifier.verify("u", SECRET, wrong, T0)
        self.assertEqual(r.status, Status.INVALID)
        self.assertFalse(r.valid)

    def test_whitespace_in_code_is_ignored(self):
        code = self.code()
        spaced = f" {code[:3]} {code[3:]} "
        self.assertTrue(self.verifier.verify("u", SECRET, spaced, T0).valid)

    def test_replay_rejected(self):
        code = self.code()
        self.assertTrue(self.verifier.verify("u", SECRET, code, T0).valid)
        second = self.verifier.verify("u", SECRET, code, T0 + 1)
        self.assertEqual(second.status, Status.REPLAY)

    def test_older_window_rejected_after_newer_accepted(self):
        older, newer = self.code(-30), self.code(0)
        self.assertTrue(self.verifier.verify("u", SECRET, newer, T0).valid)
        r = self.verifier.verify("u", SECRET, older, T0)
        self.assertEqual(r.status, Status.REPLAY)

    def test_drift_boundaries(self):
        cases = [(-30, True, -1), (30, True, 1), (-60, False, None), (60, False, None)]
        for i, (offset, ok, drift) in enumerate(cases):
            with self.subTest(offset=offset):
                r = self.verifier.verify(f"user{i}", SECRET, self.code(offset), T0)
                self.assertEqual(r.valid, ok)
                self.assertEqual(r.drift, drift)

    def test_zero_drift_accepts_only_current_window(self):
        config = OTPConfig(drift=0)
        verifier = OTPVerifier(config)
        totp = TOTP(config)
        self.assertFalse(verifier.verify("a", SECRET, totp.code_at(SECRET, T0 - 30), T0).valid)
        self.assertTrue(verifier.verify("b", SECRET, totp.code_at(SECRET, T0), T0).valid)

    def test_malformed_input_rejected_and_not_counted(self):
        for bad in ["12345", "1234567", "abcdef", "12 34", "", "١٢٣٤٥٦", "12345\u00b2"]:
            with self.subTest(bad=bad):
                r = self.verifier.verify("u", SECRET, bad, T0)
                self.assertEqual(r.status, Status.INVALID_INPUT)
        self.assertEqual(self.verifier.limiter.remaining_attempts("u"), 3)

    def test_non_string_code_rejected(self):
        r = self.verifier.verify("u", SECRET, 123456, T0)
        self.assertEqual(r.status, Status.INVALID_INPUT)

    def test_bad_secret_raises(self):
        with self.assertRaises(SecretError):
            self.verifier.verify("u", "short", "123456", T0)

    def test_empty_identity_raises(self):
        with self.assertRaises(ValueError):
            self.verifier.verify("", SECRET, "123456", T0)

    def test_lockout_after_max_attempts(self):
        for i in range(3):
            r = self.verifier.verify("u", SECRET, "000000", T0 + i)
        self.assertEqual(r.status, Status.INVALID)
        self.assertEqual(r.remaining_attempts, 0)
        self.assertGreater(r.retry_after, 0)

        # Even the correct code is refused while locked.
        locked = self.verifier.verify("u", SECRET, self.code(3), T0 + 3)
        self.assertEqual(locked.status, Status.LOCKED)
        self.assertGreater(locked.retry_after, 0)

    def test_lockout_expires(self):
        for i in range(3):
            self.verifier.verify("u", SECRET, "000000", T0 + i)
        later = T0 + 2 + 60 + 1
        r = self.verifier.verify("u", SECRET, self.totp.code_at(SECRET, later), later)
        self.assertTrue(r.valid)

    def test_lockout_is_not_extended_by_attempts_while_locked(self):
        for i in range(3):
            self.verifier.verify("u", SECRET, "000000", T0 + i)
        first = self.verifier.verify("u", SECRET, "000000", T0 + 10)
        second = self.verifier.verify("u", SECRET, "000000", T0 + 20)
        self.assertEqual(first.status, Status.LOCKED)
        self.assertEqual(first.retry_after - second.retry_after, 10)

    def test_success_resets_failure_count(self):
        self.verifier.verify("u", SECRET, "000000", T0)
        self.verifier.verify("u", SECRET, "000000", T0 + 1)
        self.assertEqual(self.verifier.limiter.remaining_attempts("u"), 1)
        self.assertTrue(self.verifier.verify("u", SECRET, self.code(2), T0 + 2).valid)
        self.assertEqual(self.verifier.limiter.remaining_attempts("u"), 3)

    def test_replay_counts_as_failure(self):
        code = self.code()
        self.verifier.verify("u", SECRET, code, T0)
        self.verifier.verify("u", SECRET, code, T0)
        self.assertEqual(self.verifier.limiter.remaining_attempts("u"), 2)

    def test_identities_are_independent(self):
        for i in range(3):
            self.verifier.verify("mallory", SECRET, "000000", T0 + i)
        self.assertEqual(
            self.verifier.verify("mallory", SECRET, self.code(), T0 + 3).status,
            Status.LOCKED,
        )
        self.assertTrue(self.verifier.verify("alice", SECRET, self.code(), T0).valid)

    def test_reset_identity(self):
        for i in range(3):
            self.verifier.verify("u", SECRET, "000000", T0 + i)
        self.verifier.reset_identity("u")
        self.assertTrue(self.verifier.verify("u", SECRET, self.code(3), T0 + 3).valid)

    def test_timestamp_near_epoch_does_not_crash(self):
        r = self.verifier.verify("u", SECRET, "000000", 0)
        self.assertIn(r.status, (Status.INVALID, Status.SUCCESS))

    def test_result_to_dict_is_json_serialisable(self):
        r = self.verifier.verify("u", SECRET, self.code(), T0)
        self.assertEqual(json.loads(json.dumps(r.to_dict()))["status"], "success")


# --------------------------------------------------------------------------
# Persistence and audit
# --------------------------------------------------------------------------


class TestPersistenceAndAudit(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self.config = OTPConfig(max_attempts=3, lockout_seconds=60)
        self.totp = TOTP(self.config)

    def make(self, audit=False):
        return OTPVerifier(
            self.config,
            store=JsonStateStore(self.dir / "state.json"),
            audit=AuditLogger(self.dir / "audit.log") if audit else None,
        )

    def test_replay_protection_survives_restart(self):
        code = self.totp.code_at(SECRET, T0)
        self.assertTrue(self.make().verify("u", SECRET, code, T0).valid)
        again = self.make().verify("u", SECRET, code, T0 + 1)  # "new process"
        self.assertEqual(again.status, Status.REPLAY)

    def test_lockout_survives_restart(self):
        first = self.make()
        for i in range(3):
            first.verify("u", SECRET, "000000", T0 + i)
        r = self.make().verify("u", SECRET, self.totp.code_at(SECRET, T0 + 3), T0 + 3)
        self.assertEqual(r.status, Status.LOCKED)

    def test_corrupt_state_fails_closed(self):
        (self.dir / "state.json").write_text("{not json", encoding="utf-8")
        with self.assertRaises(StateError):
            self.make()

    def test_malformed_attempt_state_fails_closed(self):
        (self.dir / "state.json").write_text(
            json.dumps({"attempts": {"u": {"oops": 1}}}), encoding="utf-8"
        )
        with self.assertRaises(StateError):
            self.make()

    def test_no_temp_file_left_behind(self):
        self.make().verify("u", SECRET, "000000", T0)
        self.assertEqual([p.name for p in self.dir.iterdir()], ["state.json"])

    def test_audit_log_records_events_but_no_secrets_or_codes(self):
        verifier = self.make(audit=True)
        good = self.totp.code_at(SECRET, T0)
        wrong = "000000" if good != "000000" else "000001"
        verifier.verify("alice", SECRET, good, T0)
        verifier.verify("alice", SECRET, good, T0 + 1)
        verifier.verify("alice", SECRET, wrong, T0 + 2)

        text = (self.dir / "audit.log").read_text(encoding="utf-8")
        records = [json.loads(line) for line in text.splitlines()]
        events = [r["event"] for r in records]
        self.assertIn("verification_success", events)
        self.assertIn("replay_blocked", events)
        self.assertIn("verification_failed", events)

        # Ignore the timestamp field: its microsecond digits could
        # coincidentally equal a 6-digit code.
        values = " ".join(
            str(v) for r in records for k, v in r.items() if k != "timestamp"
        )
        self.assertNotIn(SECRET, text)
        self.assertNotIn(good, values)
        self.assertNotIn(wrong, values)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


class TestCLI(unittest.TestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli_main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_generate_matches_library(self):
        code, out, _ = self.run_cli("generate", "--secret", SECRET, "--timestamp", str(T0))
        self.assertEqual(code, 0)
        self.assertIn(TOTP().code_at(SECRET, T0), out)

    def test_generate_without_secret_is_an_error(self):
        code, _, err = self.run_cli("generate")
        self.assertEqual(code, 2)
        self.assertIn("no secret", err)

    def test_invalid_config_is_an_error(self):
        code, _, err = self.run_cli("generate", "--secret", SECRET, "--digits", "3")
        self.assertEqual(code, 2)
        self.assertIn("digits", err)

    def test_verify_exit_codes_and_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            common = ["--secret", SECRET, "--timestamp", str(T0),
                      "--state-file", f"{tmp}/s.json", "--audit-file", f"{tmp}/a.log"]
            good = TOTP().code_at(SECRET, T0)
            ok, out, _ = self.run_cli("verify", "--code", good, *common)
            self.assertEqual((ok, "success" in out), (0, True))
            replay, out, _ = self.run_cli("verify", "--code", good, *common)
            self.assertEqual((replay, "replay" in out), (1, True))

    def test_vectors_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "v.json"
            code, _, _ = self.run_cli("vectors", "--output", str(path))
            self.assertEqual(code, 0)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(len(data["rfc4226_hotp"]), 10)
            self.assertEqual(len(data["rfc6238_totp"]), 18)

    def test_demo_runs(self):
        code, out, _ = self.run_cli("demo")
        self.assertEqual(code, 0)
        for word in ("SUCCESS", "REPLAY", "INVALID", "LOCKED", "INVALID_INPUT"):
            self.assertIn(word, out)


if __name__ == "__main__":
    unittest.main()