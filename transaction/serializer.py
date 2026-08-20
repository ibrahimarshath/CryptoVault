"""
transaction/serializer.py -- Deterministic Transaction Serialisation
====================================================================

WHY DETERMINISTIC SERIALISATION IS CRITICAL
---------------------------------------------
Digital signatures work by signing a sequence of BYTES.
If the same transaction could be serialised in different byte orders,
two different parties might get different bytes -> different hashes
-> the signature would not verify.

The rule:
  ALWAYS serialise fields in EXACTLY this order:
    1. sender
    2. receiver
    3. amount
    4. nonce
    5. timestamp

Different serialisation order -> different bytes
-> different SHA-256 hash
-> different ECDSA signature
-> verification fails even for a legitimate transaction

To guarantee canonical output:
  * We use JSON with sort_keys=False (we control the order manually)
  * We use a fixed separator: (",", ":")  -- no extra whitespace
  * Floats are formatted to 10 decimal places for consistency

This approach mirrors how Bitcoin serialises transactions before signing
(though Bitcoin uses a custom binary format; we use JSON for readability).
"""

import json
from transaction.transaction import Transaction


# Fixed field order -- DO NOT CHANGE this order.
_FIELD_ORDER = ("sender", "receiver", "amount", "nonce", "timestamp")


def serialize_for_signing(tx: Transaction) -> bytes:
    """
    Produce the canonical byte representation of a transaction's
    SIGNABLE fields (the fields the signature covers).

    Only the five core fields are included -- NOT tx_id or signature,
    because those are derived from the serialisation and the signature
    itself respectively.

    Parameters
    ----------
    tx : Transaction -- The transaction to serialise.

    Returns
    -------
    bytes : UTF-8 encoded canonical JSON of the core fields.

    Example output (as a string):
      '{"sender":"CV-abc...","receiver":"CV-def...","amount":"20.0000000000","nonce":1,"timestamp":"2025-01-01T00:00:00Z"}'
    """
    # Build an ordered dict with exactly the signable fields
    payload = {
        "sender":    tx.sender,
        "receiver":  tx.receiver,
        "amount":    f"{tx.amount:.10f}",   # fixed precision avoids float drift
        "nonce":     tx.nonce,
        "timestamp": tx.timestamp,
    }

    # Compact JSON with no extra spaces -- deterministic across platforms
    canonical_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    return canonical_json.encode("utf-8")


def serialize_full(tx: Transaction) -> bytes:
    """
    Serialise the complete transaction (all fields, including tx_id and
    signature) for storage in the ledger.

    Field order follows the FIELD_ORDER constant above, with tx_id and
    signature appended after the core fields.

    Parameters
    ----------
    tx : Transaction -- A fully signed transaction.

    Returns
    -------
    bytes : UTF-8 JSON of the complete transaction.
    """
    payload = {
        "sender":    tx.sender,
        "receiver":  tx.receiver,
        "amount":    tx.amount,
        "nonce":     tx.nonce,
        "timestamp": tx.timestamp,
        "tx_id":     tx.tx_id,
        "signature": tx.signature,
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
