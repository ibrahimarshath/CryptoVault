"""
transaction/transaction.py -- Transaction Data Structure
=======================================================

CONCEPT: Transaction
----------------------
A transaction is a signed record of value transfer between two wallets.

Minimum required fields (from spec):
  sender    -- Wallet address of the sender
  receiver  -- Wallet address of the receiver
  amount    -- Value to transfer (must be positive)
  nonce     -- Sequence number (replay protection)

Additional fields added for completeness:
  timestamp      -- ISO-8601 UTC timestamp of creation
  tx_id          -- SHA-256 of the serialised transaction fields
                   (unique fingerprint of the transaction)
  signature      -- ECDSA signature produced by the sender's private key

IMPORTANT: tx_id and signature are derived fields -- they are computed
AFTER the core fields are set, and they cover exactly the core fields.
"""

import time
from dataclasses import dataclass, field
from typing import Optional


def _utc_timestamp() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    import datetime
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Transaction:
    """
    Represents a single CryptoVault transaction.

    Fields
    ------
    sender    : Wallet address of the payer.
    receiver  : Wallet address of the recipient.
    amount    : Number of tokens to transfer (must be > 0).
    nonce     : Sender's transaction sequence number (replay protection).
    timestamp : UTC creation time string.
    tx_id     : SHA-256 hash of the serialised core fields (set after creation).
    signature : Hex-encoded ECDSA signature of the serialised core fields.
    """
    sender:    str
    receiver:  str
    amount:    float
    nonce:     int
    timestamp: str          = field(default_factory=_utc_timestamp)
    tx_id:     str          = ""       # filled by serializer after construction
    signature: str          = ""       # filled by signing step

    def to_dict(self) -> dict:
        """Serialise the full transaction to a dictionary for storage."""
        return {
            "sender":    self.sender,
            "receiver":  self.receiver,
            "amount":    self.amount,
            "nonce":     self.nonce,
            "timestamp": self.timestamp,
            "tx_id":     self.tx_id,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Transaction":
        """Reconstruct a Transaction from a stored dictionary."""
        tx = cls(
            sender=data["sender"],
            receiver=data["receiver"],
            amount=data["amount"],
            nonce=data["nonce"],
            timestamp=data.get("timestamp", ""),
        )
        tx.tx_id     = data.get("tx_id", "")
        tx.signature = data.get("signature", "")
        return tx

    def summary(self) -> str:
        """Human-readable one-line summary for terminal display."""
        return (
            f"[{self.timestamp}] "
            f"{self.sender[:12]}...  ->  {self.receiver[:12]}...  "
            f"| Amount: {self.amount}  | Nonce: {self.nonce} "
            f"| TX: {self.tx_id[:16]}..."
        )
