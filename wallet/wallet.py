"""
wallet/wallet.py -- Wallet Data Class
=====================================

CONCEPT: Wallet
----------------
A wallet is the user's identity in the CryptoVault system.  It holds:

  name         -- Human-readable identifier (Alice / Bob)
  private_key  -- The SECRET signing key (NEVER shown, NEVER stored in plaintext)
  public_key   -- The verification key (shareable)
  address      -- Derived short identifier (fully shareable, like a bank acct no.)
  balance      -- Current token balance (managed by security/balance.py)
  nonce        -- Transaction counter for replay protection (starts at 1)

KEY MANAGEMENT
--------------
The private key lives in memory only during an active session.
Before the session ends, the wallet is re-encrypted with AES and
saved to disk by wallet_manager.py.
"""

from dataclasses import dataclass, field
from ecdsa import SigningKey, VerifyingKey


@dataclass
class Wallet:
    """
    Represents a user's CryptoVault wallet.

    Attributes
    ----------
    name        : str          -- User's name (e.g., "Alice").
    private_key : SigningKey   -- ECDSA private key for signing (SECRET).
    public_key  : VerifyingKey -- ECDSA public key for verification (public).
    address     : str          -- Wallet address derived from public key (public).
    balance     : float        -- Current balance in CryptoVault tokens.
    nonce       : int          -- Next transaction sequence number.
                                 Starts at 1 and increments after each TX.
                                 Used for replay protection.
    """
    name:        str
    private_key: SigningKey
    public_key:  VerifyingKey
    address:     str
    balance:     float
    nonce:       int = 1

    def get_next_nonce(self) -> int:
        """
        Return the current nonce value (to be used in the next transaction).

        REPLAY PROTECTION:
          Each transaction must include this nonce.  The ledger records
          which nonces have been used; a resubmitted transaction with the
          same nonce is rejected immediately.
        """
        return self.nonce

    def increment_nonce(self) -> None:
        """Advance the nonce after a transaction is accepted."""
        self.nonce += 1

    def __repr__(self) -> str:
        """Safe string representation -- never reveals the private key."""
        return (
            f"Wallet(name={self.name!r}, "
            f"address={self.address!r}, "
            f"balance={self.balance})"
        )
