"""
attacks/attack_simulation.py -- Security Attack Demonstrations
=============================================================

This module demonstrates FOUR attacks against the CryptoVault system
and shows that each one is successfully defended against.

ATTACK 1 -- REPLAY ATTACK
  Re-submitting a previously accepted signed transaction.
  Expected: REJECTED (nonce already used)

ATTACK 2 -- OVERSPENDING (Double-Spend)
  Trying to send more money than the sender owns.
  Expected: REJECTED (insufficient balance)

ATTACK 3 -- LEDGER TAMPERING
  Modifying a stored transaction in ledger.json.
  Expected: TAMPERING DETECTED (integrity check fails)

ATTACK 4 -- SIGNATURE FORGERY
  Submitting a transaction with a corrupt/forged signature.
  Expected: REJECTED (ECDSA verification fails)

Run this module standalone:
  python attacks/attack_simulation.py

Each attack prints a clearly formatted result block.
"""

import sys
import os
import json
import copy

# -- Path setup ----------------------------------------------------------------
# Add the project root to sys.path so sibling packages can be imported
# when this script is run directly.
_SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SCRIPT_DIR)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from wallet.wallet_manager import get_or_create_wallet, load_wallet
from security.replay import NonceTracker
from security.balance import BalanceManager
from ledger.ledger import Ledger
from ledger.integrity import verify_ledger_integrity
from ledger.block import LedgerEntry
from payments.payment import process_payment
from transaction.transaction import Transaction
from transaction.serializer import serialize_for_signing
from transaction.validator import validate_transaction
from crypto.signatures import sign_data
from crypto.hashing import compute_transaction_id, demonstrate_avalanche_effect
from config import LEDGER_FILE
from storage.storage import load_json, save_json


# -- Helpers -------------------------------------------------------------------

def _header(title: str) -> None:
    width = 54
    print("\n" + "=" * width)
    print(f"  {title}")
    print("=" * width)


def _result(label: str, passed: bool) -> None:
    icon = "(OK)  PASS" if passed else "(X)  FAIL"
    print(f"\n  Final Result: {icon}  [{label}]")
    print("-" * 54)


def _sep() -> None:
    print("-" * 54)


# -- Shared state factory ------------------------------------------------------

def _fresh_state() -> tuple:
    """
    Return a fresh set of shared-state objects for testing.
    Uses the real on-disk wallet files but resets nonce/balance state
    so each attack starts from a known clean slate.
    """
    nonce_tracker = NonceTracker()
    balance_mgr   = BalanceManager()
    ledger        = Ledger()
    return nonce_tracker, balance_mgr, ledger


# ==============================================================================
#  ATTACK 1 -- REPLAY ATTACK
# ==============================================================================

def attack_1_replay() -> None:
    """
    Demonstrate nonce-based replay protection.

    Scenario:
      1. Alice sends 10 tokens to Bob  ->  ACCEPTED
      2. The SAME signed transaction is submitted again  ->  REJECTED

    Defence:
      The nonce tracker records nonce=N after the first acceptance.
      On the second attempt, is_replay() returns True -> REJECTED.
    """
    _header("ATTACK 1: REPLAY ATTACK")
    print("""
  Scenario:
    Alice signs and sends a transaction (nonce = N).
    The attacker copies that exact transaction and re-sends it.
    The signature is STILL VALID -- but the nonce is used up.
    """)

    # Load wallets
    alice = load_wallet("alice")
    bob   = load_wallet("bob")

    # Fresh state with Alice's current address seeded
    nonce_tracker, balance_mgr, ledger = _fresh_state()
    alice_start_nonce = alice.get_next_nonce()

    # -- First submission ----------------------------------------------------
    print("  [1] Original transaction (Alice -> Bob, 10 tokens):")
    ok, msg, tx = process_payment(
        sender_wallet=alice,
        receiver_address=bob.address,
        amount=10,
        balance_mgr=balance_mgr,
        nonce_tracker=nonce_tracker,
        ledger=ledger,
    )
    # Reload alice after save
    alice = load_wallet("alice")
    print(f"      Status  : {'ACCEPTED (OK)' if ok else 'REJECTED (X)'}")
    if tx:
        print(f"      TX-ID   : {tx.tx_id[:32]}...")
        print(f"      Nonce   : {tx.nonce}")

    # -- Replay: re-submit the SAME transaction ------------------------------
    # We manually craft a transaction with the SAME nonce that was already used.
    print("\n  [2] Replay attempt (same nonce, same content):")
    if tx:
        # Rebuild the same transaction with the used nonce
        replay_tx = Transaction(
            sender=tx.sender,
            receiver=tx.receiver,
            amount=tx.amount,
            nonce=alice_start_nonce,           # same nonce as the accepted TX
            timestamp=tx.timestamp,            # same timestamp
        )
        replay_tx.tx_id    = tx.tx_id
        replay_tx.signature = tx.signature     # same valid signature

        valid, error = validate_transaction(replay_tx, nonce_tracker, balance_mgr)
        print(f"      Status  : {'ACCEPTED (OK)' if valid else 'REJECTED (X)'}")
        print(f"      Reason  : {error}")
        _sep()
        _result("REPLAY PROTECTION", not valid)
    else:
        print("  ERROR: Initial transaction failed -- cannot test replay.")
        _result("REPLAY PROTECTION", False)


# ==============================================================================
#  ATTACK 2 -- OVERSPENDING (Double-Spend / Insufficient Balance)
# ==============================================================================

def attack_2_overspend() -> None:
    """
    Demonstrate balance / double-spend protection.

    Scenario:
      Alice's balance is artificially set to 50.
      Alice tries to send 200 tokens  ->  REJECTED.

    Defence:
      check_sufficient() in BalanceManager compares current balance
      against the requested amount before any transfer occurs.
    """
    _header("ATTACK 2: OVERSPENDING / DOUBLE-SPEND")
    print("""
  Scenario:
    Alice's balance is 50 tokens.
    Alice tries to send 200 tokens (more than she owns).
    Even with a valid signature, the transaction must be REJECTED.
    """)

    alice = load_wallet("alice")
    bob   = load_wallet("bob")
    nonce_tracker, balance_mgr, ledger = _fresh_state()

    # Force Alice's balance to a known value for the demonstration
    balance_mgr.set_balance(alice.address, 50.0)
    alice.balance = 50.0

    current_balance = balance_mgr.get_balance(alice.address)
    attempt_amount  = 200.0

    print(f"  Alice's current balance : {current_balance}")
    print(f"  Attempted send amount   : {attempt_amount}")

    ok, msg, tx = process_payment(
        sender_wallet=alice,
        receiver_address=bob.address,
        amount=attempt_amount,
        balance_mgr=balance_mgr,
        nonce_tracker=nonce_tracker,
        ledger=ledger,
    )

    print(f"\n  Status  : {'ACCEPTED (OK)' if ok else 'REJECTED (X)'}")
    print(f"  Reason  : {msg}")
    print(f"\n  Alice's balance after attempt : {balance_mgr.get_balance(alice.address)}")
    print(f"  (Balance unchanged -- transaction was rejected before commit)")
    _sep()
    _result("BALANCE / DOUBLE-SPEND PROTECTION", not ok)


# ==============================================================================
#  ATTACK 3 -- LEDGER TAMPERING
# ==============================================================================

def attack_3_ledger_tamper() -> None:
    """
    Demonstrate tamper-evident ledger via SHA-256 hash chain.

    Scenario:
      1. A legitimate transaction is committed to the ledger.
      2. An attacker directly edits ledger.json and changes the amount.
      3. verify_ledger_integrity() detects the discrepancy.

    Defence:
      Each entry's tx_hash is a SHA-256 of the transaction data.
      Changing any field in tx_dict produces a different hash.
      The entry_hash also changes, breaking the chain link.
      The integrity checker re-computes hashes and catches the mismatch.
    """
    _header("ATTACK 3: LEDGER TAMPERING")
    print("""
  Scenario:
    A transaction (Bob -> Alice, 15 tokens) is committed to the ledger.
    An attacker edits ledger.json and changes the amount to 9999.
    The integrity checker re-computes hashes and catches the mismatch.
    """)

    bob   = load_wallet("bob")
    alice = load_wallet("alice")
    nonce_tracker, balance_mgr, ledger = _fresh_state()

    # Commit a real transaction to make sure the ledger has at least one entry
    ok, msg, tx = process_payment(
        sender_wallet=bob,
        receiver_address=alice.address,
        amount=15,
        balance_mgr=balance_mgr,
        nonce_tracker=nonce_tracker,
        ledger=ledger,
    )
    if not ok:
        print(f"  Could not create test transaction: {msg}")
        _result("LEDGER TAMPERING DETECTION", False)
        return

    print(f"  Legitimate transaction committed.")
    print(f"  Original amount : {tx.amount}")

    # -- Integrity check BEFORE tampering ------------------------------------
    ledger.reload()
    entries_before = ledger.get_all_entries()
    ok_before, msg_before = verify_ledger_integrity(entries_before)
    print(f"\n  Integrity check (before tampering): {'OK (OK)' if ok_before else 'FAIL (X)'}")
    print(f"  Detail: {msg_before}")

    # -- Tamper with ledger.json ----------------------------------------------
    raw_ledger = load_json(LEDGER_FILE, default=[])
    if raw_ledger:
        original_amount = raw_ledger[-1]["tx_dict"]["amount"]
        raw_ledger[-1]["tx_dict"]["amount"] = 9999  # attacker's modification!
        save_json(LEDGER_FILE, raw_ledger)
        print(f"\n  [!] Attacker modified last entry: amount {original_amount} -> 9999")

    # -- Integrity check AFTER tampering -------------------------------------
    ledger.reload()
    entries_after = ledger.get_all_entries()
    ok_after, msg_after = verify_ledger_integrity(entries_after)
    print(f"\n  Integrity check (after  tampering): {'OK (OK)' if ok_after else 'FAIL (X)'}")
    print(f"  Detail: {msg_after}")

    # -- Restore ledger for subsequent tests ---------------------------------
    if raw_ledger:
        raw_ledger[-1]["tx_dict"]["amount"] = original_amount
        save_json(LEDGER_FILE, raw_ledger)
        print("\n  (Ledger restored to original state.)")

    _sep()
    _result("LEDGER TAMPERING DETECTION", not ok_after)


# ==============================================================================
#  ATTACK 4 -- SIGNATURE FORGERY
# ==============================================================================

def attack_4_forge_signature() -> None:
    """
    Demonstrate ECDSA signature forgery protection.

    Scenario:
      An attacker intercepts a transaction and changes the signature
      (or generates a random one).  The verifier catches this.

    Defence:
      verify_signature() uses ECDSA verification -- any change to the
      signature bytes or the transaction data causes verification to fail.
    """
    _header("ATTACK 4: SIGNATURE FORGERY")
    print("""
  Scenario:
    An attacker creates a transaction claiming Alice sent 50 tokens,
    but forges (corrupts) the ECDSA signature.
    Verification must REJECT the transaction.
    """)

    alice = load_wallet("alice")
    bob   = load_wallet("bob")
    nonce_tracker, balance_mgr, ledger = _fresh_state()

    # Build a real transaction and sign it legitimately
    tx = Transaction(
        sender=alice.address,
        receiver=bob.address,
        amount=50,
        nonce=alice.get_next_nonce(),
    )
    signable_bytes  = serialize_for_signing(tx)
    tx.tx_id        = compute_transaction_id(signable_bytes)
    tx.signature    = sign_data(alice.private_key, signable_bytes)

    print(f"  Legitimate signature (first 40 chars): {tx.signature[:40]}...")

    # Corrupt the signature -- simulate an attacker flipping bytes
    corrupted_sig   = "deadbeef" * 16          # obviously wrong bytes
    tx.signature    = corrupted_sig

    print(f"  Forged    signature (first 40 chars): {tx.signature[:40]}...")

    # Attempt to validate with the forged signature
    valid, error = validate_transaction(tx, nonce_tracker, balance_mgr)

    print(f"\n  Validation result : {'ACCEPTED (OK)' if valid else 'REJECTED (X)'}")
    print(f"  Reason            : {error}")
    _sep()
    _result("SIGNATURE FORGERY PROTECTION", not valid)


# ==============================================================================
#  BONUS: AVALANCHE EFFECT DEMONSTRATION
# ==============================================================================

def demonstrate_avalanche() -> None:
    """Show the avalanche effect using transaction-like strings."""
    _header("BONUS: AVALANCHE EFFECT -- SHA-256")
    demonstrate_avalanche_effect()


# ==============================================================================
# ------------------------------------------------------------------------------
#  MAIN
# ------------------------------------------------------------------------------

def run_all_attacks() -> None:
    """Run all attack simulations in sequence."""
    print("\n" + "#" * 54)
    print("  CRYPTOVAULT -- SECURITY ATTACK SIMULATIONS")
    print("#" * 54)
    print("  Initialising wallets ...")

    # Ensure wallets exist before running attacks
    get_or_create_wallet("alice")
    get_or_create_wallet("bob")

    attack_1_replay()
    attack_2_overspend()
    attack_3_ledger_tamper()
    attack_4_forge_signature()
    demonstrate_avalanche()

    print("\n" + "#" * 54)
    print("  ALL ATTACK SIMULATIONS COMPLETE")
    print("#" * 54 + "\n")


if __name__ == "__main__":
    run_all_attacks()
