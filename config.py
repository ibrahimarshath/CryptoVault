"""
config.py -- Global configuration constants for CRYPTOVAULT.

All tunable parameters live here so every other module imports
from one place instead of having magic numbers scattered around.
"""

# ---------------------------------------------
#  Elliptic Curve
# ---------------------------------------------
# secp256k1 is the same curve used by Bitcoin and Ethereum.
# It belongs to the Koblitz family and is well-suited for ECDSA.
CURVE_NAME = "SECP256k1"

# ---------------------------------------------
#  Wallet defaults
# ---------------------------------------------
# Starting balance given to every new wallet (demonstration amount).
INITIAL_BALANCE: float = 100.0

# Wallet address prefix -- makes addresses recognisable at a glance.
ADDRESS_PREFIX = "CV-"

# Number of hex characters to keep from the SHA-256 digest when
# creating a short wallet address.
ADDRESS_HEX_LENGTH = 32

# ---------------------------------------------
#  AES / Key-Derivation parameters
# ---------------------------------------------
# PBKDF2-HMAC-SHA256 is used to stretch the user's password into a
# 256-bit AES key.  A high iteration count makes brute-force slower.
KDF_ITERATIONS = 200_000

# Salt length in bytes -- randomly generated per wallet, stored alongside
# the ciphertext so decryption can reproduce the same AES key.
KDF_SALT_LENGTH = 16

# AES block size in bytes (AES-256-CBC uses 16-byte blocks).
AES_BLOCK_SIZE = 16

# ---------------------------------------------
#  Development passwords
# ---------------------------------------------
# These passwords are used automatically when the demo initialises
# wallets for Alice and Bob.  In a real product you would collect the
# password interactively with getpass() and never store it here.
ALICE_PASSWORD = "alice_secure_pass"
BOB_PASSWORD   = "bob_secure_pass"

# ---------------------------------------------
#  File paths
# ---------------------------------------------
import os

# Resolve paths relative to this file so the project works regardless
# of where the user launches Python from.
_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_DIR        = os.path.join(_BASE_DIR, "data")
WALLETS_DIR     = os.path.join(DATA_DIR, "wallets")
LEDGER_DIR      = os.path.join(DATA_DIR, "ledger")
STATE_DIR       = os.path.join(DATA_DIR, "state")

LEDGER_FILE     = os.path.join(LEDGER_DIR, "ledger.json")
NONCE_FILE      = os.path.join(STATE_DIR,  "nonces.json")
BALANCE_FILE    = os.path.join(STATE_DIR,  "balances.json")
REQUESTS_FILE   = os.path.join(STATE_DIR,  "requests.json")
