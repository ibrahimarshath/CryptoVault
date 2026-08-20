"""
wallet/wallet_manager.py -- Wallet Creation, Loading, and Saving
===============================================================

CONCEPT: Key Management
------------------------
Key management covers the full lifecycle of cryptographic keys:
  1. GENERATION   -- creating a new key pair (crypto/keys.py)
  2. STORAGE      -- saving the private key securely (AES-encrypted .enc file)
  3. LOADING      -- reading and decrypting the private key when needed
  4. USE          -- signing transactions in memory
  5. PROTECTION   -- never exposing the private key in logs or plaintext files

This module is the single place that handles steps 2-4.

AES ENCRYPTION OF PRIVATE KEYS
--------------------------------
Private keys are NEVER written to disk in plaintext.
Flow:
  generate key pair
       v
  serialise private key to PEM string
       v
  pack into wallet dict
       v
  AES-256-CBC encrypt  (crypto/encryption.py)
       v
  write encrypted bytes to  data/wallets/<name>_wallet.enc

Loading reverses this:
  read .enc file
       v
  AES-256-CBC decrypt with password
       v
  deserialise PEM string  ->  private key object
"""

import os
from ecdsa import SigningKey, VerifyingKey

from config import (
    WALLETS_DIR, INITIAL_BALANCE,
    ALICE_PASSWORD, BOB_PASSWORD,
)
from crypto.keys import (
    generate_key_pair,
    private_key_to_pem, public_key_to_pem,
    private_key_from_pem, public_key_from_pem,
)
from crypto.encryption import encrypt_wallet, decrypt_wallet, encrypt_address, decrypt_address
from crypto.hashing import sha256_hex
from wallet.address import derive_address
from wallet.wallet import Wallet


# --- Password lookup ----------------------------------------------------------
# Maps user names to their wallet passwords (demo only).
# In production this would be collected interactively with getpass().
_PASSWORDS: dict[str, str] = {
    "alice": ALICE_PASSWORD,
    "bob":   BOB_PASSWORD,
}


def _wallet_path(name: str) -> str:
    """Return the file path for a user's encrypted wallet file."""
    return os.path.join(WALLETS_DIR, f"{name.lower()}_wallet.enc")


def wallet_exists(name: str) -> bool:
    """Return True if an encrypted wallet file already exists for this user."""
    return os.path.isfile(_wallet_path(name))


def create_wallet(name: str, password: str | None = None) -> Wallet:
    """
    Generate a new wallet for the given user and save it encrypted to disk.

    Steps
    -----
    1. Generate ECDSA key pair on secp256k1.
    2. Derive wallet address from public key.
    3. Build wallet dictionary (private key stored as PEM string).
    4. AES-256-CBC encrypt the dictionary using the password.
    5. Save encrypted bytes to  data/wallets/<name>_wallet.enc
    6. Return an in-memory Wallet object (private key available for signing).

    Parameters
    ----------
    name     : str -- User's name ("alice" or "bob").
    password : str -- Encryption password (defaults to the demo password).

    Returns
    -------
    Wallet : The newly created, unlocked wallet object.

    SECURITY: The private key is encrypted before any file I/O.
    """
    if password is None:
        password = _PASSWORDS.get(name.lower(), name + "_pass")

    # Step 1: Generate ECDSA key pair
    private_key, public_key = generate_key_pair()

    # Step 2: Derive wallet address
    address = derive_address(public_key)

    # Step 3: Serialise keys to PEM strings for storage
    encrypted_address = encrypt_address(address, password)
    address_hash = sha256_hex(address)
    wallet_dict = {
        "name":              name,
        "private_key":       private_key_to_pem(private_key),   # SECRET
        "public_key":        public_key_to_pem(public_key),
        "encrypted_address": encrypted_address,
        "address_hash":      address_hash,
        "balance":           INITIAL_BALANCE,
        "nonce":             1,
    }

    # Step 4 & 5: Encrypt and save to disk
    encrypted_blob = encrypt_wallet(wallet_dict, password)
    os.makedirs(WALLETS_DIR, exist_ok=True)
    with open(_wallet_path(name), "wb") as f:
        f.write(encrypted_blob)

    # Step 6: Return the in-memory Wallet
    return Wallet(
        name=name,
        private_key=private_key,
        public_key=public_key,
        address=address,
        balance=INITIAL_BALANCE,
        nonce=1,
    )


def load_wallet(name: str, password: str | None = None) -> Wallet:
    """
    Load and decrypt a wallet from disk.

    Steps
    -----
    1. Read encrypted bytes from  data/wallets/<name>_wallet.enc
    2. AES-256-CBC decrypt using the password.
    3. Reconstruct key objects from PEM strings.
    4. Return an unlocked Wallet object.

    Parameters
    ----------
    name     : str -- User's name.
    password : str -- Decryption password.

    Returns
    -------
    Wallet : Unlocked wallet with private key available for signing.

    Raises
    ------
    FileNotFoundError : If no wallet file exists for this user.
    ValueError        : If the password is incorrect.
    """
    if password is None:
        password = _PASSWORDS.get(name.lower(), name + "_pass")

    path = _wallet_path(name)
    if not os.path.isfile(path):
        raise FileNotFoundError(
            f"No wallet found for '{name}'. "
            f"Run initialisation first."
        )

    # Step 1: Read encrypted blob
    with open(path, "rb") as f:
        encrypted_blob = f.read()

    # Step 2: Decrypt -- raises ValueError on wrong password
    wallet_dict = decrypt_wallet(encrypted_blob, password)

    # Verify address integrity
    encrypted_address = wallet_dict["encrypted_address"]
    address_hash = wallet_dict["address_hash"]
    decrypted_address = decrypt_address(encrypted_address, password)
    computed_hash = sha256_hex(decrypted_address)
    if computed_hash != address_hash:
        raise ValueError("INTEGRITY FAILURE: Stored wallet address has been tampered with!")

    # Step 3: Reconstruct key objects from PEM strings
    private_key = private_key_from_pem(wallet_dict["private_key"])
    public_key  = public_key_from_pem(wallet_dict["public_key"])

    # Step 4: Return Wallet object
    return Wallet(
        name=wallet_dict["name"],
        private_key=private_key,
        public_key=public_key,
        address=decrypted_address,
        balance=wallet_dict["balance"],
        nonce=wallet_dict["nonce"],
    )


def save_wallet(wallet: Wallet, password: str | None = None) -> None:
    """
    Re-encrypt and save the wallet back to disk.

    Called after every operation that changes wallet state (balance, nonce).

    SECURITY: Private key is encrypted before any disk write.
    """
    if password is None:
        password = _PASSWORDS.get(wallet.name.lower(), wallet.name + "_pass")

    encrypted_address = encrypt_address(wallet.address, password)
    address_hash = sha256_hex(wallet.address)
    wallet_dict = {
        "name":              wallet.name,
        "private_key":       private_key_to_pem(wallet.private_key),
        "public_key":        public_key_to_pem(wallet.public_key),
        "encrypted_address": encrypted_address,
        "address_hash":      address_hash,
        "balance":           wallet.balance,
        "nonce":             wallet.nonce,
    }

    encrypted_blob = encrypt_wallet(wallet_dict, password)
    with open(_wallet_path(wallet.name), "wb") as f:
        f.write(encrypted_blob)


def get_or_create_wallet(name: str) -> Wallet:
    """
    Convenience: return existing wallet or create a new one.

    Used during system initialisation to set up Alice and Bob.
    """
    if wallet_exists(name):
        return load_wallet(name)
    else:
        return create_wallet(name)


def get_public_key_for_address(address: str) -> VerifyingKey | None:
    """
    Search all known wallets for one whose address matches.

    Returns the public key (VerifyingKey) if found, else None.
    Used by the transaction validator to find the sender's public key.
    """
    for name in ["alice", "bob"]:
        try:
            wallet = load_wallet(name)
            if wallet.address == address:
                return wallet.public_key
        except Exception:
            continue
    return None
