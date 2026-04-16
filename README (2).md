# HMAC-SHA256 Message Authentication System

A Python implementation of a symmetric Message Authentication Code (MAC) scheme using HMAC-SHA256. This project demonstrates how two parties — a **Sender** and a **Receiver** — can authenticate messages over an untrusted channel using a shared secret key.

---

## Project Structure

```
hmac_project/
├── config.py               # Shared constants & secret loader
├── mac.py                  # Core HMAC generate + verify functions
├── secret_setup.py         # Key generation & storage utility
├── sender.py               # Message sender module
├── receiver.py             # Message receiver & verifier module
├── requirements.txt        # Python dependencies
├── .env                    # (optional) Environment variable storage
├── secret.key              # (generated) Raw secret key file — DO NOT COMMIT
└── README.md               # This file
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Shared Secret (S)                        │
│         Pre-shared via secret_setup.py / .env file          │
└────────────────────┬────────────────────┬───────────────────┘
                     │                    │
                     ▼                    ▼
          ┌──────────────────┐   ┌──────────────────┐
          │     SENDER       │   │    RECEIVER       │
          │                  │   │                   │
          │  1. message (M)  │   │  4. receive       │
          │  2. MAC =        │   │     (M ║ MAC)     │
          │  HMAC-SHA256(S,M)│   │  5. recompute     │
          │  3. send         │   │     MAC' =        │
          │     M ║ MAC      │──▶│  HMAC-SHA256(S,M) │
          │                  │   │  6. compare       │
          └──────────────────┘   │     MAC == MAC'?  │
                                 │  ✅ Accept / ❌ Reject
                                 └──────────────────┘
```

### Flow Description

| Step | Actor    | Action                                              |
|------|----------|-----------------------------------------------------|
| 1    | Sender   | Composes plaintext message M                        |
| 2    | Sender   | Computes `MAC = HMAC-SHA256(S, M)`                  |
| 3    | Sender   | Transmits packet `M ║ MAC` over the channel         |
| 4    | Receiver | Receives the packet and splits into M and MAC       |
| 5    | Receiver | Independently recomputes `MAC' = HMAC-SHA256(S, M)` |
| 6    | Receiver | Compares `MAC` and `MAC'` using constant-time compare |
| 7    | Receiver | Accepts M if equal; rejects if not                  |

---

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Generate the shared secret

```bash
python secret_setup.py
```

This creates `secret.key` (owner-readable only, mode 600) and prints the export command:

```
[✓] Secret key saved to 'secret.key' (32 bytes / 256 bits)

export HMAC_SECRET_KEY="a1b2c3..."
```

> **Security note:** In a real deployment both parties must obtain the same secret through a **secure out-of-band channel** (encrypted email, a secrets manager like AWS Secrets Manager / HashiCorp Vault, or a key-agreement protocol like Diffie-Hellman).

### 3. (Optional) Use an environment variable instead of a file

```bash
# Generate and print the export line
python secret_setup.py --env

# Then export it
export HMAC_SECRET_KEY="<hex-key>"
```

Or add it to a `.env` file:

```
HMAC_SECRET_KEY="<hex-key>"
```

---

## Usage

### Send a message

```bash
python sender.py "Hello, this is an authenticated message!"
```

Output:
```
[Sender] Message : Hello, this is an authenticated message!
[Sender] Packet  : Hello, this is an authenticated message!||3f2a...
[Sender] Transmission complete.
```

### Receive and verify

```bash
python receiver.py
```

Output (valid):
```
[Receiver] Raw packet received: Hello...||3f2a...
[Receiver] Message      : Hello, this is an authenticated message!
[Receiver] Received MAC : 3f2a...
[Receiver] ✅ MAC VALID — Message integrity confirmed.
[Receiver] Accepted message: 'Hello, this is an authenticated message!'
```

Output (tampered message):
```
[Receiver] ❌ MAC INVALID — Message may have been tampered with!
[Receiver] Message REJECTED.
```

---

## Using the Core API Directly

```python
from config import load_secret
from mac import generate_mac, verify_mac

secret = load_secret()

# Sender side
mac = generate_mac("my message", secret)
print(mac)  # e.g. 'a3f1b2...' (hex string)

# Receiver side
is_authentic = verify_mac("my message", secret, mac)
print(is_authentic)  # True

# Tampered message
is_authentic = verify_mac("my message TAMPERED", secret, mac)
print(is_authentic)  # False
```

---

## Security Properties

| Property            | Guarantee                                          |
|---------------------|----------------------------------------------------|
| **Integrity**       | Any modification to M changes the MAC              |
| **Authentication**  | Only holders of S can produce a valid MAC          |
| **Timing safety**   | `hmac.compare_digest` prevents timing attacks      |
| **Key strength**    | 256-bit random key from OS CSPRNG (`secrets`)      |
| **Algorithm**       | HMAC-SHA256 — NIST-approved, widely audited        |

### What HMAC does NOT provide

- **Confidentiality** — messages are transmitted in plaintext. Add AES-GCM or TLS for encryption.
- **Replay protection** — add a timestamp or nonce to the message before computing the MAC.
- **Non-repudiation** — symmetric MACs cannot prove *which* party sent the message.

---

## Key Management Options

| Method              | When to use                                 |
|---------------------|---------------------------------------------|
| `secret.key` file   | Local development, single-machine testing   |
| `.env` / env var    | Containerised apps, CI/CD pipelines         |
| Secrets manager     | Production (AWS SM, GCP Secret Manager, …)  |

---

## Running Tests

```bash
python -m pytest tests/ -v       # if tests/ directory is added
```

A quick smoke test:

```bash
python -c "
from mac import generate_mac, verify_mac
s = b'testsecret'
m = 'hello'
mac = generate_mac(m, s)
assert verify_mac(m, s, mac), 'Valid MAC failed!'
assert not verify_mac('tampered', s, mac), 'Tampered MAC accepted!'
print('All checks passed.')
"
```

---

## Dependencies

| Package        | Purpose                                      |
|----------------|----------------------------------------------|
| `hmac`         | HMAC computation (stdlib)                    |
| `hashlib`      | SHA-256 digest (stdlib)                      |
| `secrets`      | Cryptographically secure key generation (stdlib) |
| `os` / `dotenv`| Environment variable & file loading          |
| `python-dotenv`| `.env` file support (third-party)            |
