"""
crypto/keys.py -- ECDSA Key-Pair Generation and Management
==========================================================

CONCEPT: Public/Private Key Cryptography
-----------------------------------------
Every wallet has TWO mathematically linked keys:

  Private Key  -> kept SECRET by the owner
                 Used to SIGN transactions (proves ownership)

  Public Key   -> shared freely
                 Used to VERIFY signatures (proves the signer owns the private key)

The relationship is one-way:
  Private Key  ->  derive  ->  Public Key   (easy)
  Public Key   ->  reverse ->  Private Key  (computationally infeasible with secp256k1)

CURVE: secp256k1
-----------------
This is the same elliptic curve used by Bitcoin and Ethereum.
It belongs to the Koblitz curve family defined over a prime field.
The security level is approximately 128 bits.

KEY MANAGEMENT
--------------
Private keys are NEVER stored as plaintext.
They are encrypted with AES-256 before being written to disk.
(See crypto/encryption.py and wallet/wallet_manager.py)
"""

import os
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.util import randrange_from_seed__trytryagain
from config import CURVE_NAME


# --- Curve selection ----------------------------------------------------------
# secp256k1 is the Koblitz curve used by Bitcoin/Ethereum.
CURVE = SECP256k1


def generate_key_pair() -> tuple[SigningKey, VerifyingKey]:
    """
    Generate a new ECDSA private/public key pair on secp256k1.

    Returns
    -------
    (private_key, public_key) as ecdsa library objects.

    The private key is a random 256-bit integer.
    The public key is a point on the secp256k1 elliptic curve derived
    by multiplying the generator point G by the private key scalar.
    """
    private_key: SigningKey  = SigningKey.generate(curve=CURVE)
    public_key:  VerifyingKey = private_key.get_verifying_key()
    return private_key, public_key


def private_key_to_pem(private_key: SigningKey) -> str:
    """
    Serialise a private key to PEM format (a base64-encoded string).

    PEM (Privacy-Enhanced Mail) is a standard text format for cryptographic
    objects.  We use it because it is human-readable and easy to store.

    SECURITY: This PEM string is NEVER written to disk in plaintext.
    It is immediately encrypted with AES before storage.
    """
    return private_key.to_pem().decode("utf-8")


def public_key_to_pem(public_key: VerifyingKey) -> str:
    """Serialise a public key to PEM format (shareable, not secret)."""
    return public_key.to_pem().decode("utf-8")


def private_key_from_pem(pem_str: str) -> SigningKey:
    """
    Reconstruct a private key from its PEM string.

    Called after AES decryption of the wallet file, just before signing.
    """
    return SigningKey.from_pem(pem_str.encode("utf-8"))


def public_key_from_pem(pem_str: str) -> VerifyingKey:
    """Reconstruct a public key from its PEM string."""
    return VerifyingKey.from_pem(pem_str.encode("utf-8"))


def get_public_key_hex(public_key: VerifyingKey) -> str:
    """
    Return the compressed-point hex encoding of a public key.

    Used internally for address derivation (wallet/address.py).
    The uncompressed point is 65 bytes; the compressed form is 33 bytes.
    """
    return public_key.to_string("compressed").hex()
