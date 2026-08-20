"""
security/replay.py -- Nonce-Based Replay Protection
===================================================

CONCEPT: Replay Attack & Replay Protection
-------------------------------------------
A REPLAY ATTACK occurs when an attacker captures a previously sent,
valid, signed transaction and re-submits it.

Example without protection:
  Alice -> Bob  amount=20  nonce=1  (signed, accepted)
  Attacker copies and re-sends the same message
  -> Bob receives 20 again, Alice loses another 20 -- WRONG!

Even though the signature is valid (it was signed by Alice's key),
the transaction should be REJECTED because it was already processed.

NONCE-BASED PROTECTION
-----------------------
Each wallet maintains a nonce -- a monotonically increasing integer
starting at 1.  Every transaction must include the CURRENT nonce.

Rules:
  1. The nonce must match the sender's expected next nonce.
  2. Once a (sender, nonce) pair is recorded, it is NEVER accepted again.
  3. After acceptance, the sender's nonce increments.

This makes it impossible to replay any previously accepted transaction:
  * Old nonce  ->  REJECTED (already used)
  * Skipped nonce -> REJECTED (out of order)

PERSISTENCE
-----------
Used nonces are saved to  data/state/nonces.json  so they survive
application restarts.  A nonce is recorded ONLY after the full
validation pipeline passes.
"""

import os
from config import NONCE_FILE
from storage.storage import load_json, save_json


class NonceTracker:
    """
    Tracks used (sender_address, nonce) pairs to detect replay attacks.

    State is persisted to NONCE_FILE after every update so that replays
    are detected even across application restarts.

    Data format in nonces.json:
      {
        "<sender_address>": [1, 2, 3, ...],
        ...
      }
    """

    def __init__(self) -> None:
        # Maps sender_address -> sorted list of used nonces
        self._used: dict[str, list[int]] = load_json(NONCE_FILE, default={})

    def is_replay(self, sender_address: str, nonce: int) -> bool:
        """
        Return True if this (sender, nonce) pair was already accepted.

        A True result means the transaction is a REPLAY -- reject it.

        Parameters
        ----------
        sender_address : str -- The sender's wallet address.
        nonce          : int -- The nonce included in the transaction.
        """
        used_nonces = self._used.get(sender_address, [])
        return nonce in used_nonces

    def record_nonce(self, sender_address: str, nonce: int) -> None:
        """
        Record a nonce as used for the given sender.

        Called ONLY after a transaction fully passes validation and is
        committed to the ledger.

        Parameters
        ----------
        sender_address : str -- The sender's wallet address.
        nonce          : int -- The nonce to mark as consumed.
        """
        if sender_address not in self._used:
            self._used[sender_address] = []
        if nonce not in self._used[sender_address]:
            self._used[sender_address].append(nonce)
            self._used[sender_address].sort()
        self._save()

    def get_used_nonces(self, sender_address: str) -> list[int]:
        """Return the list of nonces already used by this sender."""
        return list(self._used.get(sender_address, []))

    def _save(self) -> None:
        """Persist nonce state to disk."""
        save_json(NONCE_FILE, self._used)

    def reset_for_testing(self) -> None:
        """
        Clear all nonce records (used only in attack simulations and tests).
        DO NOT call this in normal operation.
        """
        self._used = {}
        self._save()
