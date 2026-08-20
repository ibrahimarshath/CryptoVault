"""
crypto/signatures.py -- ECDSA Digital Signatures
================================================

CONCEPT: Digital Signatures
-----------------------------
A digital signature is the cryptographic equivalent of a handwritten
signature -- but much stronger.

Properties:
  AUTHENTICITY      -- Only the holder of the private key can produce
                      a valid signature.  "Alice signed this."
  NON-REPUDIATION   -- Alice cannot later deny having signed it, because
                      only her private key could have produced the signature.
  INTEGRITY         -- If even one byte of the signed data changes,
                      verification fails.  "The data was not tampered with."

HOW ECDSA WORKS (simplified)
------------------------------
  Signing   (done with PRIVATE key):
    1. Hash the message with SHA-256  ->  digest
    2. Generate a random nonce k
    3. Compute a point on the curve:  R = k * G
    4. Compute signature scalar:      s = k⁻¹ (hash + private_key * R.x)
    5. Signature = (R.x, s) -- two large integers

  Verification (done with PUBLIC key):
    1. Hash the received message with SHA-256  ->  digest
    2. Use (R.x, s) to reconstruct the curve point
    3. If the reconstructed point matches R, the signature is VALID

SECURITY
---------
  * The private key is NEVER sent or shared during signing/verification.
  * Even if someone intercepts the signature, they cannot recover the
    private key from it (discrete logarithm problem on elliptic curves).
  * The signature is only valid for the exact bytes that were signed.

NOTE ON MAC/HMAC
-----------------
  HMAC (Hash-based Message Authentication Code) is another integrity
  mechanism, but it requires BOTH parties to share a secret key --
  it cannot provide non-repudiation.  Because we use ECDSA digital
  signatures here, HMAC is NOT needed and NOT used.
"""

import hashlib
from ecdsa import SigningKey, VerifyingKey, BadSignatureError
from ecdsa.util import sigencode_der, sigdecode_der


def sign_data(private_key: SigningKey, data_bytes: bytes) -> str:
    """
    Sign arbitrary bytes with the given ECDSA private key.

    Parameters
    ----------
    private_key : SigningKey
        The signer's ECDSA private key (kept secret).
    data_bytes : bytes
        The exact bytes to sign -- must be the deterministic serialisation
        of the transaction so verification uses the same bytes.

    Returns
    -------
    str : DER-encoded signature as a hex string.

    AUTHENTICITY: This signature proves the private-key holder authorised
    the transaction.  Only they could have produced it.

    NON-REPUDIATION: The signature is mathematically tied to both the
    data AND the private key.  The signer cannot deny having signed it.
    """
    # hashfunc=hashlib.sha256 tells the library to SHA-256 the data
    # before performing the ECDSA signing operation.
    print("\n  [AUTHENTICITY - SIGNING] Generating cryptographic ECDSA signature (secp256k1) using private key to verify owner authorization.")
    signature_bytes: bytes = private_key.sign(
        data_bytes,
        hashfunc=hashlib.sha256,
        sigencode=sigencode_der,
    )
    return signature_bytes.hex()


def verify_signature(
    public_key: VerifyingKey,
    data_bytes: bytes,
    signature_hex: str,
) -> bool:
    """
    Verify that a signature was produced by the private key that
    corresponds to the given public key.

    Parameters
    ----------
    public_key : VerifyingKey
        The sender's public key (not secret -- taken from their wallet).
    data_bytes : bytes
        The exact bytes that were signed (deterministic serialisation).
    signature_hex : str
        The hex-encoded DER signature produced by sign_data().

    Returns
    -------
    bool : True if signature is valid, False otherwise.

    INTEGRITY: If the transaction data was altered after signing,
    the hash changes -> the verification fails -> the transaction is REJECTED.

    AUTHENTICITY: If someone tried to forge a signature without the
    private key, verification fails -> the transaction is REJECTED.
    """
    try:
        signature_bytes = bytes.fromhex(signature_hex)
        print("\n  [AUTHENTICITY - VERIFICATION] Verifying transaction ECDSA signature using sender's public key (proving sender identity and non-repudiation).")
        public_key.verify(
            signature_bytes,
            data_bytes,
            hashfunc=hashlib.sha256,
            sigdecode=sigdecode_der,
        )
        return True
    except (BadSignatureError, Exception):
        # Any exception means the signature is invalid.
        print("\n  [AUTHENTICITY - FAILURE] ECDSA signature verification failed! Signature is invalid or data has been altered.")
        return False
