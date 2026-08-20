# CryptoVault — Minimal Digital Cash System

CryptoVault is a minimal, blockchain-inspired digital cash system built entirely in Python. It demonstrates real cryptographic principles in a working terminal application — ECDSA key pairs, AES-256-CBC wallet encryption, SHA-256 hash chaining, nonce-based replay protection, and a tamper-evident ledger — making it a clear and auditable reference for applied cryptography concepts.

---

## Features

- **secp256k1 ECDSA key generation** — the same elliptic curve used by Bitcoin
- **Wallet address derivation** — SHA-256 of the public key, modulo-truncated to 10 digits with a `CV-` prefix
- **AES-256-CBC encrypted wallet storage** — private keys never touch disk in plaintext; PBKDF2-HMAC-SHA256 key derivation with a random salt
- **Password-protected login with masked input** — passwords echo as `*` using `msvcrt`; wrong passwords are caught at the AES decryption layer
- **Deterministic transaction serialisation** — field order is fixed so signatures are reproducible across sign and verify
- **ECDSA transaction signing and verification** — every transaction is signed by the sender's private key and verified before acceptance
- **Nonce-based replay protection** — each sender nonce is accepted exactly once; replayed transactions are rejected
- **Balance and double-spend protection** — the balance manager validates every transfer before committing it
- **SHA-256 hash-chained tamper-evident ledger** — each ledger entry includes the hash of the previous entry; any modification breaks the chain
- **Attack simulation suite** — five live attack demonstrations with clear output showing each defence in action

---

## Project Structure

```
CryptoVault/
|
+-- attacks/            # Standalone attack simulation script
+-- crypto/             # Key generation, ECDSA signing, AES encryption, hashing
+-- ledger/             # Ledger append, hash-chain integrity verification
+-- payments/           # End-to-end payment pipeline, payment request manager
+-- security/           # Nonce tracker (replay protection) and balance manager
+-- storage/            # Atomic JSON file persistence helpers
+-- transaction/        # Transaction dataclass, serialiser, validator
+-- wallet/             # Wallet dataclass, address derivation, wallet manager
+-- data/               # Runtime data (auto-created): wallets/, ledger/, state/
+-- config.py           # All global constants and file paths
+-- main.py             # Terminal CLI entry point
+-- requirements.txt    # Python dependencies
+-- test_system.py      # End-to-end integration tests
```

---

## Setup & Installation

**1. Clone the repository**

```bash
git clone https://github.com/your-username/CryptoVault.git
cd CryptoVault
```

**2. Create a virtual environment**

```bash
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate  # macOS / Linux
```

**3. Install dependencies**

```bash
pip install -r requirements.txt
```

**4. Delete existing data (first run / after password changes)**

```bash
# Windows
rmdir /s /q data

# macOS / Linux
rm -rf data/
```

**5. Run the application**

```bash
python main.py
```

The `data/` folder and all wallet files are created automatically on the first login.

---

## Default Credentials

| User  | Password   |
|-------|------------|
| alice | @alice2802 |
| bob   | @bob2837   |

> Passwords are never stored in plaintext. Each wallet is AES-256-CBC encrypted on disk using a PBKDF2-HMAC-SHA256 derived key. A wrong password causes decryption to fail before any wallet data is exposed.

---

## How It Works

### Wallet Creation

When a user logs in for the first time, CryptoVault generates an ECDSA key pair on the secp256k1 curve. The public key is hashed with SHA-256 and the result is modulo-truncated to produce a 10-digit numeric address prefixed with `CV-`. The private key is serialised to PEM format, packed into a wallet dictionary, and AES-256-CBC encrypted with the user's password before being written to disk.

### Sending a Transaction

The sender's wallet is decrypted in memory, a `Transaction` object is built with the sender address, receiver address, amount, and the sender's current nonce. The transaction fields are deterministically serialised and SHA-256 hashed to produce the transaction ID. The sender's private key signs that serialisation, producing an ECDSA signature. The transaction then passes through six validation checks — format, address, amount, signature, nonce, and balance — before balances are updated and the entry is appended to the ledger.

### Ledger Integrity

Every ledger entry stores the SHA-256 hash of its transaction data and the hash of the previous entry, forming a hash chain. Running `verify_ledger_integrity()` recomputes every hash from scratch and checks that the chain links correctly end to end. Modifying any entry — even a single byte — produces a different hash and breaks the chain at that index, immediately exposing the tampering.

### Attack Simulation

The simulation in `attacks/attack_simulation.py` runs five live attacks against the running system and shows the exact error message produced by each defence. It uses only the real system modules — no mocking — so the output reflects genuine cryptographic rejection. All internal system print statements are suppressed so only the attack results are displayed.

---

## Running the Attack Simulation

```bash
python attacks/attack_simulation.py
```

| # | Attack | Defence Tested |
|---|--------|----------------|
| 1 | **Replay Attack** | Nonce tracking — a resubmitted transaction is rejected |
| 2 | **Overspend Attack** | Balance validation — spending more than balance is blocked |
| 3 | **Ledger Tampering** | SHA-256 hash chain — modifying `ledger.json` is detected |
| 4 | **Forged Signature** | ECDSA verification — Bob's key cannot sign as Alice |
| 5 | **Negative Amount** | Amount validation — negative transfers are rejected before signing |

> **Note:** Attack 3 saves the original `ledger.json` before tampering and restores it in a `finally` block after the integrity check runs. The main system ledger is left exactly as it was before the attack.

---

## Security Design

| Threat | Defence | Module |
|--------|---------|--------|
| Private key theft | AES-256-CBC encryption + PBKDF2 key derivation | `crypto/encryption.py` |
| Replay attack | Per-sender nonce tracking — each nonce accepted exactly once | `security/replay.py` |
| Double spend | Balance checked and debited atomically before ledger commit | `security/balance.py` |
| Ledger tampering | SHA-256 hash chain — any modification breaks the chain | `ledger/integrity.py` |
| Forged signature | ECDSA signature verified against sender's public key | `crypto/signatures.py` |

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `ecdsa` | secp256k1 key generation, ECDSA signing and verification |
| `cryptography` | AES-256-CBC encryption, PBKDF2-HMAC-SHA256 key derivation |

Install with:

```bash
pip install -r requirements.txt
```

---

## Important Notes

- **Always delete `data/`** after changing `ALICE_PASSWORD` or `BOB_PASSWORD` in `config.py`. The wallet `.enc` files were encrypted with the old password and will fail to decrypt otherwise.
- **The `data/` folder is created automatically** on the first run — you do not need to create it manually.
- **This is a demonstration system.** It is designed for clarity and auditability, not for production use. Do not use it to store real funds or private keys.
