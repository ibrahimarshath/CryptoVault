"""
crypto/encryption.py -- AES-256-CBC Wallet Encryption
=====================================================

CONCEPT: Confidentiality / Secrecy
------------------------------------
Confidentiality means that only authorised parties can read sensitive
information.  Here we use AES-256-CBC to encrypt private wallet data
(especially the private key) before writing it to disk.

AES -- Advanced Encryption Standard
------------------------------------
  * Symmetric cipher: the SAME key is used for encryption AND decryption
  * Block size: 16 bytes (128 bits)
  * Key size:   32 bytes (256 bits) -- we use AES-256
  * Mode:       CBC (Cipher Block Chaining) -- each block's ciphertext
                depends on the previous block, hiding patterns in the data

KEY DERIVATION (PBKDF2)
------------------------
We do NOT use the user's password directly as the AES key.
Instead we use PBKDF2-HMAC-SHA256 (Password-Based Key Derivation
Function 2) to "stretch" the password:

  Password + random Salt
       v
  PBKDF2-HMAC-SHA256 (200,000 iterations)
       v
  256-bit AES key

Benefits:
  * Salt prevents precomputed (rainbow table) attacks
  * High iteration count makes brute-force extremely slow

XOR NOTE
---------
AES internally uses XOR at every step (AddRoundKey operation mixes
the key material with the data block using XOR).  CBC mode also uses
XOR: each plaintext block is XORed with the previous ciphertext block
before encryption.  So XOR is at the heart of AES, even though we
don't call it explicitly.

PADDING
--------
AES requires plaintext length to be a multiple of 16 bytes.
PKCS#7 padding adds 1-16 bytes to fill the last block.
"""

import os
import json
import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from config import KDF_ITERATIONS, KDF_SALT_LENGTH, AES_BLOCK_SIZE


def _derive_aes_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit AES key from a password using PBKDF2-HMAC-SHA256.

    Parameters
    ----------
    password : str  -- The user's wallet password.
    salt     : bytes -- Random bytes (16 bytes) unique to each wallet.

    Returns
    -------
    bytes : 32-byte (256-bit) AES key.

    SECRECY: This key exists only in memory during an active session.
    It is NEVER written to disk.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,                  # 256-bit key
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_wallet(wallet_dict: dict, password: str) -> bytes:
    """
    Encrypt a wallet dictionary to bytes using AES-256-CBC.

    Flow:
      wallet dict -> JSON string -> UTF-8 bytes -> PKCS7 padded
          -> AES-256-CBC encrypt  ->  [ salt | IV | ciphertext ]

    The output bundle format is:
      16 bytes : random salt (for key derivation)
      16 bytes : random IV   (initialisation vector for CBC)
      N bytes  : AES-256-CBC ciphertext (PKCS7-padded JSON)

    Parameters
    ----------
    wallet_dict : dict -- The wallet data (includes private key PEM).
    password    : str  -- The wallet owner's password.

    Returns
    -------
    bytes : Encrypted blob (salt + IV + ciphertext), ready to save to disk.

    CONFIDENTIALITY: Even if someone steals the .enc file, they cannot
    read the private key without the correct password.
    """
    # Step 1: Serialise wallet data to bytes
    plaintext_bytes = json.dumps(wallet_dict).encode("utf-8")

    # Step 2: PKCS7 padding to align to 16-byte AES blocks
    padder = sym_padding.PKCS7(AES_BLOCK_SIZE * 8).padder()
    padded_plaintext = padder.update(plaintext_bytes) + padder.finalize()

    # Step 3: Generate fresh random salt and IV for this encryption
    salt = os.urandom(KDF_SALT_LENGTH)   # 16 random bytes
    iv   = os.urandom(AES_BLOCK_SIZE)    # 16 random bytes (CBC IV)

    # Step 4: Derive AES key from password + salt
    aes_key = _derive_aes_key(password, salt)

    # Step 5: Encrypt with AES-256-CBC
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend(),
    )
    encryptor  = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Step 6: Prepend salt and IV so decryption can reproduce the key and state
    print("\n  [ENCRYPTION] Wallet data encrypted, hashed and kept this secret (using AES-256-CBC and PBKDF2-HMAC-SHA256).")
    return salt + iv + ciphertext


def decrypt_wallet(encrypted_bytes: bytes, password: str) -> dict:
    """
    Decrypt an encrypted wallet blob back to a dictionary.

    Flow:
      encrypted blob -> split [ salt | IV | ciphertext ]
          -> derive AES key  ->  AES-256-CBC decrypt  ->  remove padding
          ->  UTF-8 decode  ->  JSON parse  ->  dict

    Parameters
    ----------
    encrypted_bytes : bytes -- The blob produced by encrypt_wallet().
    password        : str   -- The wallet owner's password.

    Returns
    -------
    dict : The original wallet data (includes private key PEM).

    Raises
    ------
    ValueError : If the password is wrong or the data is corrupted.
    """
    # Step 1: Extract salt, IV, and ciphertext from the blob
    salt       = encrypted_bytes[:KDF_SALT_LENGTH]
    iv         = encrypted_bytes[KDF_SALT_LENGTH: KDF_SALT_LENGTH + AES_BLOCK_SIZE]
    ciphertext = encrypted_bytes[KDF_SALT_LENGTH + AES_BLOCK_SIZE:]

    # Step 2: Re-derive the same AES key using the stored salt
    aes_key = _derive_aes_key(password, salt)

    # Step 3: Decrypt with AES-256-CBC
    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend(),
    )
    decryptor      = cipher.decryptor()
    padded_plain   = decryptor.update(ciphertext) + decryptor.finalize()

    # Step 4: Remove PKCS7 padding
    try:
        unpadder    = sym_padding.PKCS7(AES_BLOCK_SIZE * 8).unpadder()
        plain_bytes = unpadder.update(padded_plain) + unpadder.finalize()
    except Exception:
        raise ValueError("Decryption failed -- wrong password or corrupted file.")

    # Step 5: Deserialise JSON -> dict
    print("\n  [DECRYPTION] Wallet data decrypted successfully (AES-256-CBC verified and JSON unpacked).")
    return json.loads(plain_bytes.decode("utf-8"))


def encrypt_address(address: str, password: str) -> str:
    """
    Encrypt the 10-digit address using AES-256-CBC and return as a hex string.
    """
    plaintext_bytes = address.encode("utf-8")
    padder = sym_padding.PKCS7(AES_BLOCK_SIZE * 8).padder()
    padded_plaintext = padder.update(plaintext_bytes) + padder.finalize()

    salt = os.urandom(KDF_SALT_LENGTH)
    iv = os.urandom(AES_BLOCK_SIZE)

    aes_key = _derive_aes_key(password, salt)

    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    blob = salt + iv + ciphertext
    return blob.hex()


def decrypt_address(encrypted_hex: str, password: str) -> str:
    """
    Decrypt the address hex string back to plaintext.
    """
    blob = bytes.fromhex(encrypted_hex)
    salt = blob[:KDF_SALT_LENGTH]
    iv = blob[KDF_SALT_LENGTH:KDF_SALT_LENGTH + AES_BLOCK_SIZE]
    ciphertext = blob[KDF_SALT_LENGTH + AES_BLOCK_SIZE:]

    aes_key = _derive_aes_key(password, salt)

    cipher = Cipher(
        algorithms.AES(aes_key),
        modes.CBC(iv),
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()
    padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(AES_BLOCK_SIZE * 8).unpadder()
    plain_bytes = unpadder.update(padded_plain) + unpadder.finalize()

    return plain_bytes.decode("utf-8")
