"""
ledger/integrity.py -- Ledger Hash-Chain Verification
=====================================================

CONCEPT: Integrity Verification
---------------------------------
The ledger is only useful if we can DETECT tampering.
verify_ledger_integrity() re-computes every entry's hashes from scratch
and checks that the chain is unbroken.

Verification checks (per entry):
  1. Re-compute tx_hash from tx_dict -> must match stored tx_hash
  2. Re-compute entry_hash from (index, tx_dict, previous_hash)
     -> must match stored entry_hash
  3. This entry's previous_hash must equal the PREVIOUS entry's entry_hash

If any check fails:
  -> TAMPERING DETECTED at entry #N

Example of tampering detection:
  Attacker modifies tx_dict of entry 0 (changes amount from 20 to 200).
  Re-computed tx_hash(0) != stored tx_hash(0)  -> FAIL at entry 0.

This demonstrates INTEGRITY -- the property that data has not been
altered since it was created.  Combined with ECDSA signatures,
even the sender cannot deny the original transaction content.
"""

import json
from ledger.block import LedgerEntry, GENESIS_HASH
from crypto.hashing import sha256_hex, compute_entry_hash


def verify_ledger_integrity(entries: list[LedgerEntry]) -> tuple[bool, str]:
    """
    Verify the full integrity of the hash chain.

    For each entry, this function:
      1. Re-computes the transaction hash from the stored tx_dict.
      2. Re-computes the entry hash from (index, tx_dict, previous_hash).
      3. Checks that this entry's previous_hash equals the previous
         entry's entry_hash (or GENESIS_HASH for entry 0).

    Parameters
    ----------
    entries : list[LedgerEntry] -- All ledger entries in order.

    Returns
    -------
    (True,  "Ledger integrity OK -- N entries verified.")
        -- The chain is unbroken; no tampering detected.
    (False, "<description of failure at entry N>")
        -- Tampering or corruption detected.
    """
    if not entries:
        return True, "Ledger is empty -- nothing to verify."

    print("\n  [INTEGRITY - START] Beginning full ledger hash-chain integrity verification...")
    expected_previous_hash = GENESIS_HASH

    for entry in entries:
        print(f"  [INTEGRITY - CHECK] Verifying entry #{entry.index} (re-computing transaction SHA-256 and previous hash links)...")
        # -- Check 1: re-compute tx_hash ---------------------------------------
        recomputed_tx_hash = sha256_hex(
            json.dumps(entry.tx_dict, sort_keys=True)
        )
        if recomputed_tx_hash != entry.tx_hash:
            return False, (
                f"INTEGRITY FAILURE at entry #{entry.index}:\n"
                f"  Transaction data has been TAMPERED WITH.\n"
                f"  Stored    tx_hash: {entry.tx_hash}\n"
                f"  Computed  tx_hash: {recomputed_tx_hash}"
            )

        # -- Check 2: previous_hash linkage ------------------------------------
        if entry.previous_hash != expected_previous_hash:
            return False, (
                f"INTEGRITY FAILURE at entry #{entry.index}:\n"
                f"  previous_hash does not match preceding entry's hash.\n"
                f"  Expected:  {expected_previous_hash}\n"
                f"  Stored:    {entry.previous_hash}"
            )

        # -- Check 3: re-compute entry_hash ------------------------------------
        recomputed_entry_hash = compute_entry_hash(
            entry.index, entry.tx_dict, entry.previous_hash
        )
        if recomputed_entry_hash != entry.entry_hash:
            return False, (
                f"INTEGRITY FAILURE at entry #{entry.index}:\n"
                f"  Entry hash is invalid -- entry data has been altered.\n"
                f"  Stored   entry_hash: {entry.entry_hash}\n"
                f"  Computed entry_hash: {recomputed_entry_hash}"
            )

        # This entry's hash becomes the next entry's expected previous_hash
        expected_previous_hash = entry.entry_hash

    return True, f"Ledger integrity OK -- {len(entries)} entr{'y' if len(entries)==1 else 'ies'} verified."
