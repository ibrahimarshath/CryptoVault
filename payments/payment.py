"""
payments/payment.py -- End-to-End Payment Processing Pipeline
============================================================

This module orchestrates the complete payment flow:

  SENDER (private key) signs the transaction
         v
  Deterministic serialisation of core fields
         v
  compute TX-ID (SHA-256 of serialised bytes)
         v
  Transaction validation pipeline (validator.py)
    -> format check
    -> address check
    -> amount check
    -> ECDSA signature verification   (AUTHENTICITY)
    -> replay/nonce check             (REPLAY PROTECTION)
    -> balance check                  (DOUBLE-SPEND PROTECTION)
         v
  If validation passes:
    -> Record nonce                   (marks this nonce as used)
    -> Debit sender balance
    -> Credit receiver balance
    -> Append to ledger               (INTEGRITY via hash chain)
    -> Increment sender's nonce
    -> Re-save sender's wallet
         v
  Return (True, "SUCCESS", transaction)

  If validation fails:
    -> Return (False, error_message, None)
    -> Balances unchanged
    -> Ledger unchanged
"""

from wallet.wallet import Wallet
from wallet.wallet_manager import save_wallet
from transaction.transaction import Transaction
from transaction.serializer import serialize_for_signing
from transaction.validator import validate_transaction
from crypto.signatures import sign_data
from crypto.hashing import compute_transaction_id
from security.replay import NonceTracker
from security.balance import BalanceManager
from ledger.ledger import Ledger


def process_payment(
    sender_wallet: Wallet,
    receiver_address: str,
    amount: float,
    balance_mgr: BalanceManager,
    nonce_tracker: NonceTracker,
    ledger: Ledger,
) -> tuple[bool, str, Transaction | None]:
    """
    Execute the full payment pipeline from signing to ledger commit.

    Parameters
    ----------
    sender_wallet    : Wallet          -- The unlocked wallet of the sender.
                                         (private key available for signing)
    receiver_address : str             -- Wallet address of the recipient.
    amount           : float           -- Tokens to transfer.
    balance_mgr      : BalanceManager  -- Shared balance state.
    nonce_tracker    : NonceTracker    -- Shared nonce/replay state.
    ledger           : Ledger          -- Shared transaction ledger.

    Returns
    -------
    (True,  "SUCCESS", transaction)  -- Payment accepted and committed.
    (False, error_message, None)     -- Payment rejected; nothing changed.
    """

    # -- Step 1: Build unsigned transaction -----------------------------------
    tx = Transaction(
        sender=sender_wallet.address,
        receiver=receiver_address,
        amount=amount,
        nonce=sender_wallet.get_next_nonce(),
    )

    # -- Step 2: Deterministic serialisation of signable fields ---------------
    #
    # CRITICAL: The signer and the verifier must use EXACTLY the same bytes.
    # serialize_for_signing() guarantees a fixed field order and format.
    signable_bytes = serialize_for_signing(tx)

    # -- Step 3: Compute Transaction ID ---------------------------------------
    #
    # The TX-ID is the SHA-256 of the signable bytes.
    # It uniquely identifies this transaction.
    tx.tx_id = compute_transaction_id(signable_bytes)

    # -- Step 4: Sign with sender's PRIVATE KEY --------------------------------
    #
    # AUTHENTICITY: Only the sender (who holds the private key) can produce
    # a valid ECDSA signature over these bytes.
    # NON-REPUDIATION: The signature is mathematically proof that the sender
    # authorised this exact transaction.
    tx.signature = sign_data(sender_wallet.private_key, signable_bytes)

    # -- Step 5: Validate ------------------------------------------------------
    #
    # Runs all 6 checks:  format -> address -> amount -> signature -> nonce -> balance
    valid, error_msg = validate_transaction(tx, nonce_tracker, balance_mgr)

    if not valid:
        return False, error_msg, None

    # -- Step 6: Commit -- all-or-nothing --------------------------------------
    #
    # Only reached if ALL validation checks passed.
    # Order matters: record nonce FIRST, then update balances, then ledger.

    # Record nonce to prevent any future replay of this exact transaction.
    nonce_tracker.record_nonce(tx.sender, tx.nonce)

    # Debit sender, credit receiver.
    balance_mgr.debit(tx.sender, tx.amount)
    balance_mgr.credit(tx.receiver, tx.amount)

    # Append to the tamper-evident hash-chained ledger.
    ledger.append_transaction(tx)

    # Update the sender's in-memory wallet balance and nonce,
    # then re-encrypt and save to disk.
    sender_wallet.balance = balance_mgr.get_balance(tx.sender)
    sender_wallet.increment_nonce()
    save_wallet(sender_wallet)

    return True, "SUCCESS", tx
