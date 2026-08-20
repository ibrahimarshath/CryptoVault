# CRYPTOVAULT
## Terminal-Based Secure Peer-to-Peer Digital Cash System

---

## 1. Project Name
**CryptoVault** — A terminal-based peer-to-peer digital cash system that demonstrates core cryptographic concepts studied in class.

---

## 2. Project Objective

CryptoVault allows two users (Alice and Bob) to:
- Maintain secure, encrypted digital wallets
- Send and receive digital tokens
- Send and respond to payment requests
- View their complete transaction history
- Verify the integrity of the transaction ledger

Every transaction is **cryptographically signed**, **replay-protected**, and **balance-validated** before it is accepted into a **hash-chained tamper-evident ledger**.

---

## 3. How the System Works

```
USER logs in
    |
    v
WALLET loads from encrypted .enc file (AES-256-CBC)
    |
    v
USER creates a TRANSACTION (sender, receiver, amount, nonce)
    |
    v
Transaction is serialised DETERMINISTICALLY (fixed field order)
    |
    v
SHA-256 hash of serialised bytes = Transaction ID
    |
    v
Private Key signs the serialised bytes = ECDSA Signature
    |
    v
VALIDATION PIPELINE:
    [1] Format check
    [2] Address check
    [3] Amount check
    [4] Signature verification  (AUTHENTICITY)
    [5] Nonce/replay check      (REPLAY PROTECTION)
    [6] Balance check           (DOUBLE-SPEND PROTECTION)
    |
    v (if all pass)
COMMIT:
    - Record nonce
    - Debit sender balance
    - Credit receiver balance
    - Append to hash-chained ledger (INTEGRITY)
    - Re-encrypt and save wallet
```

---

## 4. Architecture

The system is divided into distinct layers, each with a single responsibility:

| Layer         | Responsibility                                     |
|---------------|----------------------------------------------------|
| `crypto/`     | Key generation, hashing, signing, AES encryption   |
| `wallet/`     | Wallet object, address derivation, key management  |
| `transaction/`| Transaction structure, serialisation, validation   |
| `security/`   | Replay protection (nonce), balance/double-spend    |
| `ledger/`     | Hash-chained ledger, tamper detection              |
| `payments/`   | End-to-end payment pipeline, request management   |
| `storage/`    | Atomic JSON file I/O                               |
| `attacks/`    | Security attack demonstrations                     |

---

## 5. Folder Structure

```
cryptovault/
|
+-- main.py                  <- Terminal application entry point
+-- config.py                <- Global constants and file paths
+-- requirements.txt         <- Python dependencies
+-- README.md
+-- fix_unicode.py           <- Utility (run once to fix terminal encoding)
|
+-- crypto/
|   +-- keys.py              <- ECDSA key-pair generation (secp256k1)
|   +-- hashing.py           <- SHA-256, transaction IDs, avalanche effect
|   +-- signatures.py        <- ECDSA sign() and verify()
|   +-- encryption.py        <- AES-256-CBC + PBKDF2 for wallet storage
|
+-- wallet/
|   +-- wallet.py            <- Wallet dataclass (keys, address, balance, nonce)
|   +-- wallet_manager.py    <- Create / load / save wallets (AES-encrypted)
|   +-- address.py           <- Derive wallet address from public key
|
+-- transaction/
|   +-- transaction.py       <- Transaction dataclass
|   +-- serializer.py        <- Deterministic serialisation (fixed field order)
|   +-- validator.py         <- 6-stage validation pipeline
|
+-- ledger/
|   +-- block.py             <- LedgerEntry dataclass
|   +-- ledger.py            <- Append-only hash-chained ledger
|   +-- integrity.py         <- verify_ledger_integrity()
|
+-- payments/
|   +-- payment.py           <- End-to-end payment orchestration
|   +-- requests.py          <- PaymentRequest and RequestManager
|
+-- storage/
|   +-- storage.py           <- Atomic JSON load/save helpers
|
+-- security/
|   +-- replay.py            <- NonceTracker (replay protection)
|   +-- balance.py           <- BalanceManager (double-spend protection)
|
+-- attacks/
|   +-- attack_simulation.py <- 4 attack demonstrations
|
+-- data/
    +-- wallets/
    |   +-- alice_wallet.enc  <- AES-encrypted wallet file
    |   +-- bob_wallet.enc    <- AES-encrypted wallet file
    +-- ledger/
    |   +-- ledger.json       <- Hash-chained transaction ledger
    +-- state/
        +-- nonces.json       <- Used nonces (replay protection)
        +-- balances.json     <- Current balances
        +-- requests.json     <- Payment requests
```

---

## 6. Cryptographic Concepts Used

| Concept                    | Where Used                                              |
|----------------------------|---------------------------------------------------------|
| **Public/Private Keys**    | Each wallet has an ECDSA key pair                       |
| **ECDSA (secp256k1)**      | Signing and verifying transactions                      |
| **Digital Signatures**     | Every transaction is signed before submission           |
| **SHA-256**                | Transaction IDs, ledger entry hashes, address derivation|
| **Avalanche Effect**       | Demonstrated in attack_simulation.py                    |
| **AES-256-CBC**            | Wallet/private-key storage encryption                   |
| **PBKDF2-HMAC-SHA256**     | Deriving AES keys from passwords                        |
| **Hash Chain**             | Tamper-evident ledger (like a blockchain)               |
| **Nonce**                  | Replay attack prevention                               |
| **Balance Tracking**       | Double-spend / overspend prevention                     |

---

## 7. Where AUTHENTICITY Is Used

**File:** `crypto/signatures.py`, `transaction/validator.py`

Every transaction includes an ECDSA signature over its serialised fields.

```
Alice wants to send 20 tokens to Bob:
  1. Alice serialises the transaction (fixed field order)
  2. Alice signs the bytes with her PRIVATE KEY
  3. The signature is attached to the transaction

When the system validates:
  1. Fetch Alice's PUBLIC KEY from her wallet
  2. Re-serialise the same fields in the same order
  3. Call verify_signature(alice_public_key, bytes, signature)
  4. If valid -> AUTHENTIC (Alice signed this)
  5. If invalid -> REJECTED
```

**Question answered:** "Did Alice actually authorise this transaction?"

---

## 8. Where INTEGRITY Is Used

**File:** `ledger/integrity.py`, `crypto/signatures.py`

Two layers of integrity protection:

**Layer 1 — Digital Signature:**
Any modification to a signed transaction makes the signature invalid.
The verifier catches this during the validation pipeline.

**Layer 2 — Hash Chain:**
Each ledger entry stores the hash of the previous entry.
If any transaction is modified after being recorded:
- Its SHA-256 hash changes
- The next entry's `previous_hash` no longer matches
- `verify_ledger_integrity()` detects the mismatch

**Question answered:** "Was any transaction or ledger entry changed after the fact?"

---

## 9. Where SECRECY / CONFIDENTIALITY Is Used

**File:** `crypto/encryption.py`, `wallet/wallet_manager.py`

Private keys are **never stored in plaintext**.

```
Private Key PEM string
    |
    v
AES-256-CBC encrypt (key = PBKDF2(password, random_salt))
    |
    v
Encrypted blob: [16 bytes salt | 16 bytes IV | N bytes ciphertext]
    |
    v
Written to: data/wallets/alice_wallet.enc

To use:
    Read .enc file
    |
    v
AES-256-CBC decrypt (same password + stored salt)
    |
    v
Private key available in memory for signing
```

**XOR note:** AES internally uses XOR in every round (AddRoundKey) and
CBC mode XORs each plaintext block with the previous ciphertext block.
So XOR is foundational to AES, even though it is not called explicitly.

**MAC/HMAC note:** HMAC provides message authentication but requires
both parties to share a secret key — it cannot provide non-repudiation.
Since CryptoVault uses ECDSA digital signatures, HMAC is unnecessary.
Digital signatures provide all three: authenticity, integrity, AND non-repudiation.

**Question answered:** "Can someone read the private key if they steal the wallet file?"

---

## 10. How Replay Protection Works

**File:** `security/replay.py`

Each transaction includes the sender's current **nonce** (sequence number).

```
Alice's nonce starts at 1.

Transaction 1: nonce = 1  -> ACCEPTED  -> nonce recorded
Transaction 2: nonce = 2  -> ACCEPTED  -> nonce recorded

Replay attack: re-send Transaction 1 with nonce = 1:
    NonceTracker.is_replay("alice_address", 1) -> True
    -> REJECTED: "Nonce 1 has already been used"
```

Used nonces are persisted to `data/state/nonces.json` so that replays
are rejected even after the application restarts.

---

## 11. How Balance Protection Works

**File:** `security/balance.py`

Balances are tracked independently of the wallet files.

```
Initial state: Alice = 100, Bob = 100

Alice sends 30:
    check_sufficient(alice_address, 30) -> OK
    -> debit(alice_address, 30)   Alice = 70
    -> credit(bob_address,  30)   Bob   = 130

Alice tries to send 100:
    check_sufficient(alice_address, 100) -> FAIL
    -> "Insufficient balance: has 70.00 but tried to send 100.00"
    -> REJECTED, no balance change
```

A valid ECDSA signature does NOT bypass the balance check.
Both checks are **independent and mandatory**.

---

## 12. How the Hash Chain Works

**Files:** `ledger/block.py`, `ledger/ledger.py`, `ledger/integrity.py`

```
GENESIS_HASH = "0000...0000" (64 zeros)

Entry 0:
  tx_hash      = SHA-256(TX_0_data)
  previous_hash = GENESIS_HASH
  entry_hash   = SHA-256(0 + TX_0_data + GENESIS_HASH)

Entry 1:
  tx_hash      = SHA-256(TX_1_data)
  previous_hash = Entry_0.entry_hash
  entry_hash   = SHA-256(1 + TX_1_data + Entry_0.entry_hash)

Entry 2:
  tx_hash      = SHA-256(TX_2_data)
  previous_hash = Entry_1.entry_hash
  entry_hash   = SHA-256(2 + TX_2_data + Entry_1.entry_hash)
```

If TX_0 is modified:
- `sha256(TX_0_modified)` != stored `tx_hash` of Entry 0
- `verify_ledger_integrity()` catches this immediately

---

## 13. How to Run the Project

### Prerequisites

```bash
# Python 3.12+ required
# Install dependencies
pip install -r requirements.txt
```

### Run the main application

```bash
cd cryptovault
python main.py
```

You will see the main menu:
```
CRYPTOVAULT
Secure Peer-to-Peer Digital Cash System

1.  Login as Alice
2.  Login as Bob
3.  Run Attack Simulations
4.  Exit
```

### First run

On first run, wallets are automatically created for Alice and Bob with
a starting balance of 100 tokens each.

---

## 14. How to Run the Attack Simulations

```bash
cd cryptovault
python attacks/attack_simulation.py
```

Or from the main menu: **Option 3 — Run Attack Simulations**

Expected output:

```
######################################################
  CRYPTOVAULT -- SECURITY ATTACK SIMULATIONS
######################################################

======================================================
  ATTACK 1: REPLAY ATTACK
======================================================
  [1] Original transaction:  ACCEPTED
  [2] Replay attempt:        REJECTED
  Final Result: (OK) PASS [REPLAY PROTECTION]

======================================================
  ATTACK 2: OVERSPENDING / DOUBLE-SPEND
======================================================
  Alice's balance: 50.00
  Attempted amount: 200.00
  Status: REJECTED
  Final Result: (OK) PASS [BALANCE / DOUBLE-SPEND PROTECTION]

======================================================
  ATTACK 3: LEDGER TAMPERING
======================================================
  Before tampering: Integrity OK
  After  tampering: INTEGRITY FAILURE at entry #1
  Final Result: (OK) PASS [LEDGER TAMPERING DETECTION]

======================================================
  ATTACK 4: SIGNATURE FORGERY
======================================================
  Forged signature: REJECTED
  Final Result: (OK) PASS [SIGNATURE FORGERY PROTECTION]

======================================================
  BONUS: AVALANCHE EFFECT -- SHA-256
======================================================
  "Hello, World!"  -> dffd6021bb2bd5b0af676290809ec3a5...
  "hello, World!"  -> 04aa5d2533987c34839e8dbc8d8fcac8...
  (One char change -> completely different hash)
```

---

## Viva Notes

| Question                               | Answer                                          |
|----------------------------------------|-------------------------------------------------|
| What curve does CryptoVault use?        | secp256k1 (same as Bitcoin/Ethereum)            |
| Why deterministic serialisation?       | Same data must always produce the same bytes for signing/verification |
| Why AES and not just hashing?          | Hashing is one-way; AES allows decryption with the correct key |
| Why not use HMAC?                      | HMAC needs a shared secret; ECDSA signatures don't (and give non-repudiation) |
| Why not Diffie-Hellman?                | DH is for key exchange over insecure channels; this app is local |
| Why not TLS?                           | TLS is for network communication; this is a local terminal app |
| How does replay protection work?       | Nonces: each (sender, nonce) pair accepted only once |
| What is the avalanche effect?          | 1-bit input change causes ~50% output bits to change in SHA-256 |
| Where is XOR used?                     | Inside AES: AddRoundKey step XORs round key with data; CBC XORs blocks |
