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
from config import ADDRESS_PREFIX, ADDRESS_HEX_LENGTH
from crypto.keys import get_public_key_hex


def derive_address(public_key: VerifyingKey) -> str:
    """
    Derive a wallet address from an ECDSA public key.

    Steps
    -----
    1. Get the compressed-point hex representation of the public key
       (33 bytes = 66 hex chars, like Bitcoin's compressed pubkey).
    2. SHA-256 hash that hex string.
    3. Take the first ADDRESS_HEX_LENGTH characters of the digest.
    4. Prepend the "CV-" prefix for recognisability.

    Parameters
    ----------
    public_key : VerifyingKey -- The ECDSA public key of the wallet.

    Returns
    -------
    str : A wallet address, e.g.  "CV-3a7f9b2e1c0d..."

    SECURITY NOTE
    -------------
    This is a ONE-WAY derivation:
      Address -> cannot reverse -> Public Key
      Address -> cannot reverse -> Private Key
    The address is safe to share publicly.
    """
    # Step 1: Compressed-point hex (33 bytes -> 66 hex chars)
    pubkey_hex = get_public_key_hex(public_key)

    # Step 2: SHA-256 hash of the hex string
    digest = hashlib.sha256(pubkey_hex.encode("utf-8")).hexdigest()

    # Step 3: Truncate to ADDRESS_HEX_LENGTH characters
    short_hash = digest[:ADDRESS_HEX_LENGTH]

    # Step 4: Add prefix
    return f"{ADDRESS_PREFIX}{short_hash}"


def is_valid_address(address: str) -> bool:
    """
    Basic validation that an address looks like a CryptoVault address.

    A valid address:
      * Starts with the CV- prefix
      * Has exactly ADDRESS_HEX_LENGTH hex characters after the prefix
      * Contains only valid hex characters

    Parameters
    ----------
    address : str -- The address string to validate.

    Returns
    -------
    bool : True if the address format is valid.
    """
    if not address.startswith(ADDRESS_PREFIX):
        return False
    body = address[len(ADDRESS_PREFIX):]
    if len(body) != ADDRESS_HEX_LENGTH:
        return False
    try:
        int(body, 16)   # ensure it's valid hex
        return True
    except ValueError:
        return False
