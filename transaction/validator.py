"""
transaction/validator.py -- Transaction Validation Pipeline
==========================================================

CONCEPT: Validation Pipeline
------------------------------
Every transaction must pass a series of checks BEFORE it enters the
ledger.  A valid ECDSA signature is NECESSARY but NOT SUFFICIENT --
the transaction must also be new (not replayed) and the sender must
have enough balance.

Validation order
----------------
  1. FORMAT CHECK    -- required fields present, correct types
  2. ADDRESS CHECK   -- sender != receiver, addresses look valid
  3. AMOUNT CHECK    -- amount > 0
  4. SIGNATURE CHECK -- ECDSA signature valid  (AUTHENTICITY / INTEGRITY)
  5. REPLAY CHECK    -- nonce not previously used  (REPLAY PROTECTION)
  6. BALANCE CHECK   -- sender has sufficient funds  (DOUBLE-SPEND PROTECTION)

If ANY check fails:
  * Return (False, error_message)
  * Do NOT modify balances or ledger

Only when ALL checks pass:
  * Return (True, "OK")
  * The caller (payment.py) updates balances and adds to ledger
"""

from transaction.transaction import Transaction
from transaction.serializer import serialize_for_signing
from crypto.signatures import verify_signature
from crypto.hashing import compute_transaction_id
from security.replay import NonceTracker
from security.balance import BalanceManager
from wallet.address import is_valid_address
from wallet.wallet_manager import get_public_key_for_address


def validate_transaction(
    tx: Transaction,
    nonce_tracker: NonceTracker,
    balance_mgr: BalanceManager,
) -> tuple[bool, str]:
    """
    Run the full validation pipeline on a transaction.

    Parameters
    ----------
    tx            : Transaction    -- The transaction to validate.
    nonce_tracker : NonceTracker   -- Tracks used nonces for replay protection.
    balance_mgr   : BalanceManager -- Tracks current balances.

    Returns
    -------
    (True,  "OK")               -- Transaction is valid; safe to commit.
    (False, "<error message>")  -- Transaction is invalid; do NOT commit.
    """

    # -- 1. FORMAT CHECK -------------------------------------------------------
    # Ensure all required fields are present and have the right types.
    if not tx.sender or not isinstance(tx.sender, str):
        return False, "FORMAT ERROR: Missing or invalid sender."
    if not tx.receiver or not isinstance(tx.receiver, str):
        return False, "FORMAT ERROR: Missing or invalid receiver."
    if not isinstance(tx.amount, (int, float)):
        return False, "FORMAT ERROR: Amount must be numeric."
    if not isinstance(tx.nonce, int):
        return False, "FORMAT ERROR: Nonce must be an integer."
    if not tx.signature:
        return False, "FORMAT ERROR: Transaction has no signature."

    # -- 2. ADDRESS CHECK ------------------------------------------------------
    if tx.sender == tx.receiver:
        return False, "ADDRESS ERROR: Sender and receiver cannot be the same."
    if not is_valid_address(tx.sender):
        return False, f"ADDRESS ERROR: Invalid sender address '{tx.sender}'."
    if not is_valid_address(tx.receiver):
        return False, f"ADDRESS ERROR: Invalid receiver address '{tx.receiver}'."

    # -- 3. AMOUNT CHECK -------------------------------------------------------
    if tx.amount <= 0:
        return False, f"AMOUNT ERROR: Amount must be positive (got {tx.amount})."

    # -- 4. SIGNATURE CHECK -- AUTHENTICITY ------------------------------------
    #
    # Retrieve the sender's PUBLIC KEY from the wallet store.
    # (The public key is stored in the wallet file; it is not secret.)
    public_key = get_public_key_for_address(tx.sender)
    if public_key is None:
        return False, f"AUTH ERROR: Unknown sender address '{tx.sender}'."

    # Re-serialise the transaction's SIGNABLE fields.
    # This MUST use the same deterministic serialisation as the signer used.
    signable_bytes = serialize_for_signing(tx)

    # Verify the ECDSA signature.
    if not verify_signature(public_key, signable_bytes, tx.signature):
        return False, (
            "SIGNATURE ERROR: Invalid signature -- transaction may have been "
            "tampered with or signed by a different key."
        )

    # -- 5. REPLAY CHECK -- NON-REPUDIATION / REPLAY PROTECTION ----------------
    #
    # A replay attack re-submits a previously accepted, legitimately signed
    # transaction to double-spend or disrupt the system.
    # The nonce must match the expected next nonce exactly to prevent replay and out-of-order attacks.
    used_nonces = nonce_tracker.get_used_nonces(tx.sender)
    expected_nonce = len(used_nonces) + 1
    if tx.nonce != expected_nonce:
        if tx.nonce < expected_nonce:
            return False, (
                f"REPLAY ERROR: Nonce {tx.nonce} has already been used by "
                f"sender {tx.sender[:16]}... Expected next nonce: {expected_nonce}."
            )
        else:
            return False, (
                f"REPLAY ERROR: Invalid future nonce {tx.nonce} for "
                f"sender {tx.sender[:16]}... Expected next nonce: {expected_nonce}."
            )

    # -- 6. BALANCE CHECK -- DOUBLE-SPEND PROTECTION ---------------------------
    #
    # A valid signature does NOT automatically mean the sender has the money.
    # We check the balance independently.
    ok, msg = balance_mgr.check_sufficient(tx.sender, tx.amount)
    if not ok:
        return False, f"BALANCE ERROR: {msg}"

    # -- ALL CHECKS PASSED -----------------------------------------------------
    return True, "OK"
