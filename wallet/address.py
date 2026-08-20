"""
wallet/address.py -- Wallet Address Derivation
=============================================

CONCEPT: Wallet Address
------------------------
A wallet address is a SHORT, SHAREABLE identifier derived from the
public key.  It is analogous to a bank account number.

  Private Key  ->  (ECDSA multiply by G)  ->  Public Key
  Public Key   ->  (SHA-256 + truncate)   ->  Wallet Address

The address is NOT secret.  You give it to people who want to send
you money -- just like you give someone your bank account number.

Why not use the public key directly as the address?
  * Public keys are 65 bytes (130 hex chars) -- too long to share easily
  * Addresses are shorter and have a recognisable prefix (CV-)

This derivation is inspired by how Bitcoin derives addresses from
public keys (though Bitcoin adds extra steps like RIPEMD-160 and
Base58Check encoding; we use a simplified form for clarity).
"""

import hashlib
from ecdsa import VerifyingKey
from crypto.keys import get_public_key_hex


def derive_address(public_key: VerifyingKey) -> str:
    """
    Derive a 10-digit wallet address from an ECDSA public key.

    Steps
    -----
    1. Get the compressed-point hex representation of the public key.
    2. SHA-256 hash that hex string.
    3. Convert the hash to a large integer and take modulo 10^10 to yield a 10-digit number.
    4. Format the result as a 10-digit string, left-padded with zeros if needed.
    """
    # Step 1: Compressed-point hex (33 bytes -> 66 hex chars)
    pubkey_hex = get_public_key_hex(public_key)

    # Step 2: SHA-256 hash of the hex string
    digest = hashlib.sha256(pubkey_hex.encode("utf-8")).hexdigest()

    # Step 3 & 4: Convert to int, modulo 10^10, pad to 10 digits, prepend CV- prefix
    num = int(digest, 16)
    return f"CV-{num % (10**10):010d}"


def is_valid_address(address: str) -> bool:
    """
    Validation that an address starts with 'CV-' and has exactly 10 digits after it.
    """
    if not address.startswith("CV-"):
        return False
    body = address[3:]  # strip the 'CV-' prefix
    return len(body) == 10 and body.isdigit()
