"""
ledger/block.py -- Ledger Entry (Block) Data Structure
=====================================================

CONCEPT: Hash Chain / Tamper-Evident Ledger
--------------------------------------------
Each ledger entry is a "block" that contains:

  index         -- Position in the ledger (0, 1, 2, ...)
  tx_dict       -- The full transaction dictionary
  tx_hash       -- SHA-256 of the transaction data alone
  previous_hash -- The hash of the PREVIOUS entry (or "GENESIS" for index 0)
  entry_hash    -- SHA-256 of (index + tx_dict + previous_hash) combined

The chain looks like:

  Entry 0 (Genesis)
  ┌----------------------------------+
  | index: 0                         |
  | previous_hash: "GENESIS"         |
  | tx_hash: sha256(TX_0)            |
  | entry_hash: sha256(0+TX_0+GEN)   |
  +----------------------------------+
              | (entry_hash becomes next entry's previous_hash)
              ▼
  Entry 1
  ┌----------------------------------+
  | index: 1                         |
  | previous_hash: entry_hash[0]     |
  | tx_hash: sha256(TX_1)            |
  | entry_hash: sha256(1+TX_1+ph)    |
  +----------------------------------+
              |
              ▼  ...

TAMPER DETECTION (INTEGRITY):
  If an attacker modifies TX_0, its tx_hash changes.
  The entry_hash of entry 0 changes.
  Entry 1's previous_hash no longer matches entry 0's entry_hash.
  The integrity checker detects the mismatch -> TAMPERING DETECTED.
"""

from dataclasses import dataclass


GENESIS_HASH = "0" * 64   # Placeholder previous hash for the first entry


@dataclass
class LedgerEntry:
    """
    Represents a single tamper-evident entry in the CryptoVault ledger.

    Attributes
    ----------
    index         : int  -- Position in the ledger (0-based).
    tx_dict       : dict -- Complete transaction data.
    tx_hash       : str  -- SHA-256 of the transaction data (64-char hex).
    previous_hash : str  -- Hash of the preceding entry's entry_hash.
    entry_hash    : str  -- SHA-256 of (index + tx_dict + previous_hash).
    """
    index:         int
    tx_dict:       dict
    tx_hash:       str
    previous_hash: str
    entry_hash:    str

    def to_dict(self) -> dict:
        """Serialise to a dictionary for JSON storage."""
        return {
            "index":         self.index,
            "tx_dict":       self.tx_dict,
            "tx_hash":       self.tx_hash,
            "previous_hash": self.previous_hash,
            "entry_hash":    self.entry_hash,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LedgerEntry":
        """Reconstruct a LedgerEntry from a stored dictionary."""
        return cls(
            index=data["index"],
            tx_dict=data["tx_dict"],
            tx_hash=data["tx_hash"],
            previous_hash=data["previous_hash"],
            entry_hash=data["entry_hash"],
        )
