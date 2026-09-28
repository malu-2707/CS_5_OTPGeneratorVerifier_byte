# CS_5_OTPGeneratorVerifier_byte

## Secure OTP Generator & Verifier

A Python-based **Time-Based One-Time Password (TOTP) Generator and Verifier** designed to demonstrate secure OTP generation, verification, replay protection, clock-drift handling, rate limiting, account lockout, persistent security state, and audit logging.

The project uses **HMAC-SHA256** for OTP generation and includes standards-based HOTP and TOTP test vectors.

---

## Features

- Time-Based One-Time Password (TOTP)
- HMAC-SHA256 OTP generation
- HOTP support
- 6, 7, and 8 digit OTPs
- Configurable OTP validity period
- Configurable clock-drift tolerance
- Secure Base32 secret generation
- Secret validation and normalization
- Constant-time OTP comparison
- Replay protection
- Rate limiting
- Account lockout
- Persistent verification state
- JSON audit logging
- Provisioning URI generation
- RFC 4226 HOTP test vectors
- RFC 6238 TOTP test vectors
- Automated test suite
- Command-line interface
- Deterministic demonstration mode
- JSON and CSV test reports

---

## Technology

| Technology | Purpose |
|---|---|
| Python 3 | Application development |
| HMAC | OTP authentication |
| SHA-256 | Cryptographic hashing |
| Base32 | Secret representation |
| TOTP | Time-based OTP |
| HOTP | Counter-based OTP |
| `unittest` | Automated testing |
| JSON | State and test data |
| CSV | Test result reporting |

The project primarily uses the **Python standard library** and does not require external Python packages for its core functionality.

---

## Project Structure

```text
CS_5_OTPGeneratorVerifier_byte/
│
├── otp_system/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── core.py
│   ├── security.py
│   ├── vectors.py
│   └── verifier.py
│
├── reports/
│   ├── test_results.csv
│   ├── test_results.json
│   └── test_vectors.json
│
├── tests/
│   ├── __init__.py
│   └── test_otp.py
│
└── README.md
```

> Runtime audit logs and persistent authentication state should not be committed to a public repository.

---

## Default Configuration

| Parameter | Default |
|---|---:|
| OTP digits | 6 |
| OTP period | 30 seconds |
| Algorithm | HMAC-SHA256 |
| Clock drift | ±1 time window |
| Maximum attempts | 5 |
| Lockout duration | 300 seconds |

With a 30-second period and a drift setting of ±1, the verifier checks the previous, current, and next time counters.

---

## How TOTP Generation Works

The TOTP generation process follows the HOTP/TOTP approach:

```text
Unix Timestamp
      │
      ▼
Time Counter
      │
      ▼
HMAC-SHA256
      │
      ▼
Dynamic Truncation
      │
      ▼
Numeric OTP
```

The generated OTP depends on:

- Secret key
- Time counter
- Hash algorithm
- Configured number of digits

The same secret and time counter produce the same OTP.

---

## OTP Verification Flow

The verification process performs the following steps:

```text
User submits OTP
       │
       ▼
Validate identity
       │
       ▼
Check lockout status
       │
       ▼
Validate OTP format
       │
       ▼
Calculate current time counter
       │
       ▼
Check configured drift window
       │
       ▼
Constant-time comparison
       │
       ▼
Check replay protection
       │
       ▼
Accept or reject OTP
       │
       ▼
Update security state
       │
       ▼
Write audit event
```

---

## Replay Protection

A successfully accepted OTP cannot be reused for the same identity and counter.

Example:

```text
First submission:
OTP → SUCCESS

Same OTP submitted again:
OTP → REPLAY
```

Replay protection prevents a previously accepted OTP from being reused.

Replay state can also be persisted so that protection survives application restarts.

---

## Clock Drift Tolerance

The default configuration uses:

```text
drift = ±1 window
```

With a 30-second period, the verifier checks:

```text
Previous Window
       │
       ▼
Current Window
       │
       ▼
Next Window
```

This allows limited clock differences between the OTP generator and verifier.

An OTP outside the configured verification window is rejected.

---

## Rate Limiting and Account Lockout

The default security policy is:

```text
Maximum attempts: 5
Lockout duration: 300 seconds
```

Example:

```text
Wrong attempt #1 → INVALID
Wrong attempt #2 → INVALID
Wrong attempt #3 → INVALID
Wrong attempt #4 → INVALID
Wrong attempt #5 → INVALID + LOCKED
```

While locked:

```text
Correct OTP → LOCKED
```

After the lockout period expires:

```text
Correct OTP → SUCCESS
```

A successful verification resets the consecutive failure count.

---

## Audit Logging

Security events are recorded using JSON Lines.

The audit system records security-related metadata without storing:

- OTP secrets
- Submitted OTP codes

Example event categories include:

```text
SUCCESS
INVALID
REPLAY
LOCKED
INVALID_INPUT
```

Audit logs are intended for local runtime use and should not contain production credentials or authentication secrets.

---

## Persistent State

The project supports persistent JSON state for security controls such as:

- Replay protection
- Failed-attempt tracking
- Lockout state

Persistent state allows these controls to survive application restarts.

The implementation uses fail-closed behavior when persistent state is corrupt or malformed rather than silently resetting security state.

---

## Command-Line Interface

The project can be executed using Python's module interface.

### Generate a Secret

```powershell
python -m otp_system secret
```

### Generate an OTP

```powershell
python -m otp_system generate --secret <BASE32_SECRET>
```

### Verify an OTP

```powershell
python -m otp_system verify --secret <BASE32_SECRET> --code 123456
```

### Generate a Provisioning URI

```powershell
python -m otp_system uri --secret <BASE32_SECRET>
```

### Run the Security Demonstration

```powershell
python -m otp_system demo
```

### Export Test Vectors

```powershell
python -m otp_system vectors --output test_vectors.json
```

### Interactive Mode

```powershell
python -m otp_system interactive
```

---

## Testing

The project includes an automated test suite covering:

- RFC 4226 HOTP vectors
- RFC 6238 TOTP vectors
- OTP generation
- OTP verification
- Incorrect OTP handling
- Replay protection
- Clock-drift boundaries
- Zero-drift configuration
- Lockout
- Lockout expiration
- Rate limiting
- Secret validation
- Persistent state
- Corrupt state handling
- Audit logging
- CLI behavior
- Vector export
- Identity isolation
- Reset functionality

### Run the Complete Test Suite

```powershell
python -m unittest discover -s tests -v
```

### Test Result

```text
----------------------------------------------------------------------
Ran 44 tests in 0.201s

OK
```

**44/44 tests passed.**

---

## Demonstration

Run the security demonstration with:

```powershell
python -m otp_system demo
```

The demonstration covers:

```text
Correct OTP                  → SUCCESS
Reused OTP                   → REPLAY
Previous time window         → SUCCESS
Older time window            → INVALID
Malformed OTP                → INVALID_INPUT
Repeated incorrect attempts  → LOCKED
OTP during lockout           → LOCKED
OTP after lockout            → SUCCESS
```

The demonstration provides a deterministic way to verify the main security controls without requiring an external authentication service.

---

## Test Reports

Generated test reports can be stored in:

```text
reports/
├── test_results.csv
├── test_results.json
└── test_vectors.json
```

### `test_results.csv`

Contains structured test result information in CSV format.

### `test_results.json`

Contains structured test result information in JSON format.

### `test_vectors.json`

Contains project and standards-based OTP test vectors.

---

## Test Vectors

The project includes regression vectors based on:

- **RFC 4226 — HOTP**
- **RFC 6238 — TOTP**

The test suite validates the implementation against published HOTP and TOTP test vectors.

Generated vectors can be exported using:

```powershell
python -m otp_system vectors --output test_vectors.json
```

The exported vectors are available in:

```text
reports/test_vectors.json
```

The demonstration and published test secrets are for testing purposes only and must **never be reused for real authentication**.

---

## Security Design

### Constant-Time Comparison

OTP verification uses constant-time comparison to reduce timing-based information leakage.

### Replay Protection

Previously accepted OTP counters are tracked per identity.

### Rate Limiting

Repeated incorrect verification attempts are tracked.

### Account Lockout

An identity is temporarily locked after reaching the configured maximum number of failed attempts.

### Persistent Security State

Replay and lockout state can survive application restarts when persistent storage is enabled.

### Fail-Closed State Handling

Corrupt or malformed persistent security state is rejected instead of silently resetting security controls.

### Audit Logging

Security events are logged without recording OTP secrets or submitted OTP values.

---

## Security Considerations

This project is intended for:

- Educational use
- Cybersecurity learning
- Authorized development
- Local security testing

Only use the system with accounts, secrets, systems, and environments that you own or are explicitly authorized to test.

For production authentication systems, additional security controls may be required, including:

- Secure secret storage
- Hardware-backed key protection
- Key management
- Access control
- TLS
- Strong identity management
- Centralized security monitoring
- Distributed rate limiting
- Multi-process state coordination
- Backup and recovery procedures
- Secure deployment configuration

### Never Commit Sensitive Data

Do not commit the following to a public repository:

```text
Real OTP secrets
Passwords
API keys
Private keys
Production credentials
Personal authentication data
Real authentication logs
Production state files
```

---

## Standards and References

The implementation includes compatibility testing against:

- RFC 4226 — HOTP: An HMAC-Based One-Time Password Algorithm
- RFC 6238 — TOTP: Time-Based One-Time Password Algorithm

These standards are used as references for the OTP generation and verification implementation.

---

## Learning Outcomes

This project demonstrates practical understanding of:

- TOTP authentication
- HOTP fundamentals
- HMAC
- SHA-256
- Base32 encoding
- Cryptographic OTP generation
- Authentication security
- Replay attack prevention
- Rate limiting
- Account lockout
- Persistent security state
- Audit logging
- Python package organization
- CLI application development
- Unit testing
- Security test vectors
- Secure coding practices

---

## License
This project is provided for educational and authorized cybersecurity development purposes.

## Author
MALINI S
Cybersecurity Student
