"""
crypto/hashing.py -- SHA-256 Hashing Utilities
==============================================

CONCEPT: Cryptographic Hashing
--------------------------------
A hash function takes an input of ANY size and produces a fixed-size
output (digest) that:
  1. Is deterministic  -- same input always gives the same output
  2. Is one-way        -- you cannot reverse the hash to find the input
  3. Is collision-resistant -- it is infeasible to find two different
                              inputs that produce the same hash
  4. Shows the Avalanche Effect (see below)

SHA-256 (Secure Hash Algorithm 256-bit)
-----------------------------------------
  * Output: always 256 bits = 32 bytes = 64 hex characters
  * Used in: Bitcoin, TLS certificates, digital signatures, git commits

AVALANCHE EFFECT
-----------------
Changing even ONE bit of the input causes ~50% of the output bits to
change -- completely different hash.

Example:
  Input:  "Hello"       -> hash: 185f8db32...
  Input:  "hello"       -> hash: 2cf24dba5...   <- completely different!

This is crucial for:
  * Ledger integrity  -- any change to a transaction changes its hash
  * Transaction IDs   -- uniquely identifies each transaction
  * Hash chaining     -- links ledger entries together
"""

import hashlib
import json
from typing import Union


def sha256_hex(data: Union[str, bytes]) -> str:
    """
    Compute the SHA-256 hash of the given data and return the hex digest.

    Parameters
    ----------
    data : str or bytes
        The input to hash.  Strings are UTF-8 encoded before hashing.

    Returns
    -------
    str : 64-character lowercase hex string.

    Usage
    -----
    Used for:
      - Transaction IDs (unique fingerprint of each transaction)
      - Ledger entry hashes
      - Previous-hash linking in the hash chain
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def compute_transaction_id(serialized_bytes: bytes) -> str:
    """
    Compute a unique Transaction ID from the deterministic serialisation
    of a transaction.

    Why deterministic serialisation matters:
      If we serialise the same transaction in a different field order,
      we get different bytes -> different hash -> different TX ID.
      The serialiser (transaction/serializer.py) always uses the same
      fixed order to guarantee reproducibility.

    Returns a 64-character hex string used as the transaction's unique ID.
    """
    return sha256_hex(serialized_bytes)


def compute_entry_hash(index: int, tx_dict: dict, previous_hash: str) -> str:
    """
    Compute the hash for a single ledger entry.

    The hash covers:
      - The entry index
      - The full transaction dictionary (as canonical JSON)
      - The previous entry's hash

    This chaining means that if any earlier entry is modified, ALL
    subsequent hashes become invalid -- tampering is immediately detected.

    INTEGRITY: This is the core of the tamper-evident ledger.
    """
    content = json.dumps({
        "index":         index,
        "transaction":   tx_dict,
        "previous_hash": previous_hash,
    }, sort_keys=True)
    return sha256_hex(content)


def demonstrate_avalanche_effect() -> None:
    """
    Print a demonstration of the avalanche effect.

    Shows how a tiny change in input (one letter) produces a completely
    different SHA-256 hash -- important for viva explanation.
    """
    inputs = [
        ("Hello, World!",  "Original input"),
        ("hello, World!",  "Changed H -> h  (1 character)"),
        ("Hello, World !", "Added a space   (1 character)"),
    ]

    print("\n" + "=" * 60)
    print("  AVALANCHE EFFECT DEMONSTRATION -- SHA-256")
    print("=" * 60)
    for text, label in inputs:
        digest = sha256_hex(text)
        print(f"\n  Input  : {text!r:<25}  ({label})")
        print(f"  SHA-256: {digest}")
    print("\n  Observation: Tiny input change -> completely different hash.")
    print("=" * 60 + "\n")
