"""
ledger/ledger.py -- Hash-Chained Ledger Management
==================================================

The ledger is the permanent, ordered, tamper-evident record of all
accepted transactions.  It is stored in  data/ledger/ledger.json.

HASH CHAINING
-------------
Each entry's entry_hash is computed from:
  (entry_index, transaction_data, previous_entry_hash)

If any earlier entry is modified:
  -> its entry_hash changes
  -> the NEXT entry's previous_hash no longer matches
  -> verify_ledger_integrity() (ledger/integrity.py) detects the mismatch

This is the same structural principle as a blockchain.
The key security property is INTEGRITY -- history cannot be rewritten.

OPERATIONS
----------
  append_transaction(tx)  -- add a new accepted transaction to the chain
  get_all_entries()       -- return all entries in order
  get_history(address)    -- return entries where sender or receiver = address
  load_ledger()           -- read from disk
  save_ledger()           -- write to disk
"""

import json
import os
from typing import Optional

from config import LEDGER_FILE
from ledger.block import LedgerEntry, GENESIS_HASH
from transaction.transaction import Transaction
from crypto.hashing import sha256_hex, compute_entry_hash
from storage.storage import load_json, save_json


class Ledger:
    """
    Manages the tamper-evident, hash-chained transaction ledger.

    All accepted transactions are appended here.  No entry is ever
    removed or modified after appending (append-only log).
    """

    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []
        self._load()

    # -- Append ----------------------------------------------------------------

    def append_transaction(self, tx: Transaction) -> LedgerEntry:
        """
        Append an accepted transaction to the ledger.

        Computes tx_hash, previous_hash, and entry_hash before saving.

        Parameters
        ----------
        tx : Transaction -- A fully validated and signed transaction.

        Returns
        -------
        LedgerEntry : The new entry that was appended.

        INTEGRITY: The entry's hash chains it to all previous entries.
        Any tampering with this entry or any earlier entry will break
        the chain and be detected by verify_ledger_integrity().
        """
        tx_dict = tx.to_dict()

        # SHA-256 of the transaction data alone (the transaction's fingerprint)
        tx_hash = sha256_hex(json.dumps(tx_dict, sort_keys=True))

        # Hash of the PREVIOUS entry's entry_hash (or GENESIS for the first entry)
        previous_hash = (
            self._entries[-1].entry_hash
            if self._entries
            else GENESIS_HASH
        )

        index = len(self._entries)

        # Combined hash covering index + tx + previous link
        entry_hash = compute_entry_hash(index, tx_dict, previous_hash)

        entry = LedgerEntry(
            index=index,
            tx_dict=tx_dict,
            tx_hash=tx_hash,
            previous_hash=previous_hash,
            entry_hash=entry_hash,
        )

        self._entries.append(entry)
        self._save()
        return entry

    # -- Read ------------------------------------------------------------------

    def get_all_entries(self) -> list[LedgerEntry]:
        """Return all ledger entries in chronological order."""
        return list(self._entries)

    def get_history(self, address: str) -> list[LedgerEntry]:
        """
        Return all ledger entries where the given address is either
        the sender or the receiver.

        Parameters
        ----------
        address : str -- A wallet address (e.g., "CV-3a7f9b2e...").
        """
        return [
            e for e in self._entries
            if e.tx_dict.get("sender")   == address
            or e.tx_dict.get("receiver") == address
        ]

    def is_empty(self) -> bool:
        """Return True if no transactions have been recorded yet."""
        return len(self._entries) == 0

    def entry_count(self) -> int:
        """Return the total number of ledger entries."""
        return len(self._entries)

    # -- Persistence -----------------------------------------------------------

    def _load(self) -> None:
        """Load entries from the JSON ledger file."""
        raw = load_json(LEDGER_FILE, default=[])
        self._entries = [LedgerEntry.from_dict(item) for item in raw]

    def _save(self) -> None:
        """Persist all entries to the JSON ledger file."""
        save_json(LEDGER_FILE, [e.to_dict() for e in self._entries])

    def reload(self) -> None:
        """Re-read the ledger from disk (useful after external modifications)."""
        self._load()
