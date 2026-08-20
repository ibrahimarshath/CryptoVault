"""End-to-end integration test for CryptoVault."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wallet.wallet_manager import get_or_create_wallet, load_wallet
from security.replay import NonceTracker
from security.balance import BalanceManager
from ledger.ledger import Ledger
from ledger.integrity import verify_ledger_integrity
from payments.payment import process_payment
from payments.requests import RequestManager

print("=== FULL SYSTEM END-TO-END TEST ===")

balance_mgr   = BalanceManager()
nonce_tracker = NonceTracker()
ledger        = Ledger()
req_mgr       = RequestManager()

alice = get_or_create_wallet("alice")
bob   = get_or_create_wallet("bob")

balance_mgr.initialise_if_missing(alice.address)
balance_mgr.initialise_if_missing(bob.address)

print(f"Alice addr: {alice.address}")
print(f"Bob   addr: {bob.address}")
print(f"Alice bal : {balance_mgr.get_balance(alice.address):.2f}")
print(f"Bob   bal : {balance_mgr.get_balance(bob.address):.2f}")

# Test 1: Alice sends to Bob
print()
alice = load_wallet("alice")
ok, msg, tx = process_payment(alice, bob.address, 25, balance_mgr, nonce_tracker, ledger)
alice = load_wallet("alice")
status = "OK" if ok else "FAIL"
print(f"[Test 1] Alice->Bob 25 tokens: {status} | {msg}")
print(f"  Alice bal: {balance_mgr.get_balance(alice.address):.2f}")
print(f"  Bob   bal: {balance_mgr.get_balance(bob.address):.2f}")

# Test 2: Bob sends to Alice
print()
bob = load_wallet("bob")
ok, msg, tx = process_payment(bob, alice.address, 10, balance_mgr, nonce_tracker, ledger)
bob = load_wallet("bob")
status = "OK" if ok else "FAIL"
print(f"[Test 2] Bob->Alice 10 tokens: {status} | {msg}")
print(f"  Alice bal: {balance_mgr.get_balance(alice.address):.2f}")
print(f"  Bob   bal: {balance_mgr.get_balance(bob.address):.2f}")

# Test 3: Payment request flow
print()
req = req_mgr.create_request(alice.address, "Alice", bob.address, "Bob", 30)
print(f"[Test 3] Alice requests 30 from Bob.")
print(f"  Request ID: {req.request_id[:20]}...")
pending = req_mgr.get_pending_for(bob.address)
print(f"  Pending requests for Bob: {len(pending)}")
bob = load_wallet("bob")
ok2, msg2, tx2 = process_payment(bob, alice.address, 30, balance_mgr, nonce_tracker, ledger)
if ok2:
    req_mgr.accept_request(req.request_id)
status2 = "OK" if ok2 else "FAIL"
print(f"  Bob accepts: {status2} | {msg2}")
print(f"  Alice bal: {balance_mgr.get_balance(alice.address):.2f}")
print(f"  Bob   bal: {balance_mgr.get_balance(bob.address):.2f}")

# Test 4: Ledger integrity
print()
ledger.reload()
entries = ledger.get_all_entries()
ok_int, msg_int = verify_ledger_integrity(entries)
integ = "PASS" if ok_int else "FAIL"
print(f"[Test 4] Ledger integrity ({len(entries)} entries): {integ} | {msg_int}")

# Test 5: Transaction history
print()
alice_history = ledger.get_history(alice.address)
print(f"[Test 5] Alice's transaction history: {len(alice_history)} entries")
for e in alice_history:
    tx = e.tx_dict
    direction = "SENT" if tx["sender"] == alice.address else "RECV"
    print(f"  {direction}: amount={tx['amount']}  nonce={tx['nonce']}")

print()
print("=== ALL TESTS COMPLETED ===")
