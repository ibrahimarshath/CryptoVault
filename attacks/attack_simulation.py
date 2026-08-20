"""
attacks/attack_simulation.py -- CryptoVault Security Attack Demonstrations
===========================================================================

Demonstrates 5 attacks against CryptoVault and shows each is blocked:

    Attack 1 -- Replay Attack         (Nonce tracking)
    Attack 2 -- Overspend Attack      (Balance validation)
    Attack 3 -- Ledger Tampering      (SHA-256 hash chain)
    Attack 4 -- Forged Signature      (ECDSA signature verification)
    Attack 5 -- Negative Amount       (Amount format validation)

Run from the project root:
    python attacks/attack_simulation.py
"""

import os
import sys
import json
import io
import contextlib

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from wallet.wallet_manager import get_or_create_wallet, load_wallet
from security.replay import NonceTracker
from security.balance import BalanceManager
from ledger.ledger import Ledger
from ledger.integrity import verify_ledger_integrity
from payments.payment import process_payment
from transaction.transaction import Transaction
from transaction.serializer import serialize_for_signing
from transaction.validator import validate_transaction
from crypto.signatures import sign_data
from crypto.hashing import compute_transaction_id
from config import LEDGER_FILE, DATA_DIR, WALLETS_DIR, LEDGER_DIR, STATE_DIR

LINE = "=" * 58

@contextlib.contextmanager
def silent():
    """Redirect stdout to suppress internal system print statements."""
    with contextlib.redirect_stdout(io.StringIO()):
        yield

def header(title):
    print(f"\n{LINE}")
    print(f"  {title}")
    print(LINE)

def held(msg):
    print(f"  [OK] SYSTEM HELD -- {msg}")

def breached(msg):
    print(f"  [!!] SYSTEM BREACHED -- {msg}")

def init_state():
    for d in (DATA_DIR, WALLETS_DIR, LEDGER_DIR, STATE_DIR):
        os.makedirs(d, exist_ok=True)
    balance_mgr   = BalanceManager()
    nonce_tracker = NonceTracker()
    ledger        = Ledger()
    with silent():
        alice = get_or_create_wallet("alice")
        bob   = get_or_create_wallet("bob")
    balance_mgr.initialise_if_missing(alice.address)
    balance_mgr.initialise_if_missing(bob.address)
    return alice, bob, balance_mgr, nonce_tracker, ledger

# ==========================================================================
# ATTACK 1 -- REPLAY ATTACK
# ==========================================================================
def attack_replay(alice, bob, balance_mgr, nonce_tracker, ledger):
    header("[ATTACK 1]  Replay Attack")

    with silent():
        alice = load_wallet("alice")
        ok, msg, tx = process_payment(alice, bob.address, 10, balance_mgr, nonce_tracker, ledger)

    if not ok:
        print(f"  Setup failed unexpectedly: {msg}")
        return False

    print(f"  Nonce used   : {tx.nonce}")
    print(f"  Alice balance: {balance_mgr.get_balance(alice.address):.2f}  |  Bob balance: {balance_mgr.get_balance(bob.address):.2f}")

    with silent():
        ok_replay, msg_replay = validate_transaction(tx, nonce_tracker, balance_mgr)

    print(f"  Rejected     : {msg_replay}")

    if not ok_replay:
        held("Replay blocked")
        return True
    else:
        breached("Replay succeeded -- nonce protection failed!")
        return False

# ==========================================================================
# ATTACK 2 -- OVERSPEND ATTACK
# ==========================================================================
def attack_overspend(alice, bob, balance_mgr, nonce_tracker, ledger):
    header("[ATTACK 2]  Overspend Attack")

    with silent():
        alice = load_wallet("alice")

    current_balance = balance_mgr.get_balance(alice.address)
    attack_amount   = current_balance + 500.00

    print(f"  Alice balance    : {current_balance:.2f} tokens")
    print(f"  Attempted amount : {attack_amount:.2f} tokens  (balance + 500)")

    with silent():
        ok, msg, _ = process_payment(alice, bob.address, attack_amount, balance_mgr, nonce_tracker, ledger)

    print(f"  Rejected         : {msg}")

    if not ok:
        held("Overspend blocked")
        return True
    else:
        breached("Overspend succeeded -- balance check failed!")
        return False

# ==========================================================================
# ATTACK 3 -- LEDGER TAMPERING ATTACK
# ==========================================================================
def attack_ledger_tamper(alice, bob, balance_mgr, nonce_tracker, ledger):
    header("[ATTACK 3]  Ledger Tampering Attack")

    with silent():
        alice = load_wallet("alice")
        ok, msg, tx = process_payment(alice, bob.address, 5, balance_mgr, nonce_tracker, ledger)

    if not ok:
        print(f"  Setup failed unexpectedly: {msg}")
        return False

    ledger.reload()

    # Save a complete copy of the original file bytes before any tampering
    with open(LEDGER_FILE, "r", encoding="utf-8") as f:
        original_contents = f.read()

    raw = json.loads(original_contents)
    original_amount = raw[0]["tx_dict"]["amount"]

    ok_integrity = False
    integrity_msg = ""
    try:
        # Write the tampered version to disk
        raw[0]["tx_dict"]["amount"] = 9999
        with open(LEDGER_FILE, "w", encoding="utf-8") as f:
            json.dump(raw, f, indent=2)

        print(f"  Entry #0 amount tampered : {original_amount} -> 9999")

        ledger.reload()
        with silent():
            ok_integrity, integrity_msg = verify_ledger_integrity(ledger.get_all_entries())

        first_line = integrity_msg.splitlines()[0]
        print(f"  Integrity check  : {first_line}")

    finally:
        # Always restore the original file, regardless of the check result
        with open(LEDGER_FILE, "w", encoding="utf-8") as f:
            f.write(original_contents)
        ledger.reload()
        print(f"  Ledger restored to original state.")

    if not ok_integrity:
        held("Tampering detected")
        return True
    else:
        breached("Tampering undetected -- hash chain failed!")
        return False

# ==========================================================================
# ATTACK 4 -- FORGED SIGNATURE / WRONG KEY
# ==========================================================================
def attack_forged_signature(alice, bob, balance_mgr, nonce_tracker, ledger):
    header("[ATTACK 4]  Forged Signature / Wrong Key")

    # Load both wallets to access their keys
    with silent():
        alice = load_wallet("alice")
        bob   = load_wallet("bob")

    # Build a transaction that claims Alice is the sender
    tx = Transaction(
        sender=alice.address,
        receiver=bob.address,
        amount=20,
        nonce=alice.nonce,
    )

    signable_bytes = serialize_for_signing(tx)
    tx.tx_id = compute_transaction_id(signable_bytes)

    # Sign with BOB'S private key instead of Alice's
    with silent():
        tx.signature = sign_data(bob.private_key, signable_bytes)

    print(f"  Claimed sender   : Alice  ({alice.address})")
    print(f"  Signature from   : Bob's private key  ({bob.address})")

    with silent():
        ok, msg = validate_transaction(tx, nonce_tracker, balance_mgr)

    print(f"  Rejected         : {msg}")

    if not ok:
        held("Forged signature rejected")
        return True
    else:
        breached("Forged signature accepted -- ECDSA verification failed!")
        return False

# ==========================================================================
# ATTACK 5 -- NEGATIVE AMOUNT
# ==========================================================================
def attack_negative_amount(alice, bob, balance_mgr, nonce_tracker, ledger):
    header("[ATTACK 5]  Negative Amount Attack")

    with silent():
        alice = load_wallet("alice")

    attack_amount = -50.0

    # Build and sign the transaction legitimately with Alice's key
    tx = Transaction(
        sender=alice.address,
        receiver=bob.address,
        amount=attack_amount,
        nonce=alice.nonce,
    )

    signable_bytes = serialize_for_signing(tx)
    tx.tx_id = compute_transaction_id(signable_bytes)

    with silent():
        tx.signature = sign_data(alice.private_key, signable_bytes)

    current_balance = balance_mgr.get_balance(alice.address)
    print(f"  Alice balance    : {current_balance:.2f} tokens")
    print(f"  Attempted amount : {attack_amount:.2f} tokens  (negative -- would steal funds)")

    with silent():
        ok, msg = validate_transaction(tx, nonce_tracker, balance_mgr)

    print(f"  Rejected         : {msg}")

    if not ok:
        held("Negative amount blocked")
        return True
    else:
        breached("Negative amount accepted -- amount validation failed!")
        return False

# ==========================================================================
# MAIN
# ==========================================================================
def main():
    print(f"\n{'#'*58}")
    print("  CRYPTOVAULT -- SECURITY ATTACK SIMULATIONS")
    print(f"{'#'*58}")
    print("""
  5 attacks against CryptoVault and their defences:

    Attack 1: Replay Attack        -> Nonce Tracking
    Attack 2: Overspend Attack     -> Balance Validation
    Attack 3: Ledger Tampering     -> SHA-256 Hash Chain
    Attack 4: Forged Signature     -> ECDSA Verification
    Attack 5: Negative Amount      -> Amount Format Check
""")

    alice, bob, balance_mgr, nonce_tracker, ledger = init_state()

    results = {}
    results["Replay Attack"]       = attack_replay(alice, bob, balance_mgr, nonce_tracker, ledger)
    results["Overspend Attack"]    = attack_overspend(alice, bob, balance_mgr, nonce_tracker, ledger)
    results["Ledger Tampering"]    = attack_ledger_tamper(alice, bob, balance_mgr, nonce_tracker, ledger)
    results["Forged Signature"]    = attack_forged_signature(alice, bob, balance_mgr, nonce_tracker, ledger)
    results["Negative Amount"]     = attack_negative_amount(alice, bob, balance_mgr, nonce_tracker, ledger)

    print(f"\n{'#'*58}")
    print("  SUMMARY")
    print(f"{'#'*58}")
    print(f"\n  {'Attack':<28} {'Result'}")
    print(f"  {'-'*28} {'-'*18}")
    for attack, passed in results.items():
        status = "[OK] BLOCKED" if passed else "[!!] BREACHED"
        print(f"  {attack:<28} {status}")
    print()
    if all(results.values()):
        print("  All 5 attacks blocked. CryptoVault security is working correctly.")
    else:
        print("  WARNING: One or more attacks were NOT blocked!")
    print()

if __name__ == "__main__":
    main()
