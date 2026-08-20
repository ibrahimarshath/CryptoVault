"""
main.py -- CryptoVault Terminal Application Entry Point
======================================================

The main interactive CLI for CryptoVault.

Menu structure:
  ┌- Main Menu
  |   1. Login as Alice
  |   2. Login as Bob
  |   3. Run Attack Simulations
  |   4. Exit
  |
  +- Wallet Dashboard (after login)
      1. Send Money
      2. Receive / View Incoming Payments
      3. Send Payment Request
      4. View Payment Requests (Accept / Reject)
      5. View My Transactions
      6. View Wallet Information
      7. Check Ledger Integrity
      8. Logout

All state objects (ledger, balance_mgr, nonce_tracker, request_mgr)
are shared singletons -- simulating a shared server/network backend.
"""

import os
import sys

import msvcrt


def _input_password(prompt: str = "  Password: ") -> str:
    """
    Read a password from the terminal, echoing '*' for each character typed.

    Handles:
      - Printable chars  : append to buffer and print '*'
      - Backspace        : remove last char and erase last '*'
      - Enter            : submit
      - Ctrl+C           : raise KeyboardInterrupt
    """
    print(prompt, end="", flush=True)
    chars = []
    while True:
        ch = msvcrt.getwch()
        if ch in ("\r", "\n"):          # Enter -- submit
            print()
            break
        elif ch == "\x03":               # Ctrl+C -- cancel
            print()
            raise KeyboardInterrupt
        elif ch in ("\x08", "\x7f"):    # Backspace -- erase last char
            if chars:
                chars.pop()
                # Move cursor back, overwrite '*' with space, move back again
                print("\b \b", end="", flush=True)
        elif ch >= " ":                    # Printable character
            chars.append(ch)
            print("*", end="", flush=True)
    return "".join(chars)


# -- Path setup ----------------------------------------------------------------
_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from wallet.wallet import Wallet
from wallet.wallet_manager import get_or_create_wallet, load_wallet, save_wallet
from security.replay import NonceTracker
from security.balance import BalanceManager
from ledger.ledger import Ledger
from ledger.integrity import verify_ledger_integrity
from payments.payment import process_payment
from payments.requests import RequestManager
from crypto.hashing import demonstrate_avalanche_effect


# ==============================================================================
#  Display helpers
# ==============================================================================

def _clear() -> None:
    """Clear the terminal screen (works on Windows and Unix)."""
    os.system("cls" if os.name == "nt" else "clear")


def _banner() -> None:
    print("""
+==================================================+
|                                                  |
|          C R Y P T O V A U L T                   |
|    Secure Peer-to-Peer Digital Cash System       |
|                                                  |
|  - ECDSA Signatures  - SHA-256 Hash Chain -      |
|  - AES-256 Wallet    - Replay Protection  -      |
|                                                  |
+==================================================+""")


def _section(title: str) -> None:
    print(f"\n{'='*52}")
    print(f"  {title}")
    print(f"{'='*52}")


def _ok(msg: str) -> None:
    print(f"\n  (OK)  SUCCESS: {msg}")


def _err(msg: str) -> None:
    print(f"\n  (X)  ERROR: {msg}")


def _info(msg: str) -> None:
    print(f"  i  {msg}")


def _pause() -> None:
    input("\n  [Press ENTER to continue] ")


def _ask(prompt: str) -> str:
    return input(f"\n  {prompt}: ").strip()


# ==============================================================================
#  Initialisation
# ==============================================================================

def initialise_system() -> tuple:
    """
    Initialise all shared system state.

    Returns
    -------
    (balance_mgr, nonce_tracker, ledger, request_mgr)
    """
    balance_mgr   = BalanceManager()
    nonce_tracker = NonceTracker()
    ledger        = Ledger()
    request_mgr   = RequestManager()

    # Ensure both wallets exist
    alice_wallet = get_or_create_wallet("alice")
    bob_wallet   = get_or_create_wallet("bob")

    # Register addresses in balance store if first run
    balance_mgr.initialise_if_missing(alice_wallet.address)
    balance_mgr.initialise_if_missing(bob_wallet.address)

    return balance_mgr, nonce_tracker, ledger, request_mgr


# ==============================================================================
#  Action handlers
# ==============================================================================

def get_peer_wallet(current_user_name: str) -> Wallet:
    """Return the OTHER user's wallet (for address lookup)."""
    peer_name = "bob" if current_user_name.lower() == "alice" else "alice"
    return load_wallet(peer_name)


def action_send_money(
    wallet: Wallet,
    balance_mgr: BalanceManager,
    nonce_tracker: NonceTracker,
    ledger: Ledger,
) -> Wallet:
    """Handle the 'Send Money' flow and return (possibly updated) wallet."""
    _section("SEND MONEY")

    peer = get_peer_wallet(wallet.name)
    current_balance = balance_mgr.get_balance(wallet.address)

    print(f"\n  Your address   : {wallet.address}")
    print(f"  Your balance   : {current_balance:.2f} tokens")
    print(f"  (For convenience, {peer.name}'s address is {peer.address})")

    receiver_address = _ask("Enter receiver's 10-digit wallet address (or 0 to cancel)")
    if receiver_address == "0" or not receiver_address:
        _info("Send cancelled.")
        _pause()
        return wallet

    if receiver_address != peer.address:
        _err(f"Unknown or invalid receiver address '{receiver_address}'. For this demo, please send to {peer.name}'s address: {peer.address}")
        _pause()
        return wallet

    amount_str = _ask("Enter amount to send (or 0 to cancel)")
    try:
        amount = float(amount_str)
    except ValueError:
        _err("Invalid amount -- please enter a number.")
        _pause()
        return wallet

    if amount <= 0:
        _info("Send cancelled.")
        _pause()
        return wallet

    print(f"\n  Sending {amount:.2f} tokens to {peer.name} ({peer.address})")
    print("  Signing transaction with your private key ...")

    ok, msg, tx = process_payment(
        sender_wallet=wallet,
        receiver_address=receiver_address,
        amount=amount,
        balance_mgr=balance_mgr,
        nonce_tracker=nonce_tracker,
        ledger=ledger,
    )

    if ok:
        _ok(f"{amount:.2f} tokens sent to {peer.name}!")
        print(f"\n  Transaction ID : {tx.tx_id}")
        print(f"  Signature      : {tx.signature[:40]}...")
        print(f"  New balance    : {balance_mgr.get_balance(wallet.address):.2f}")
        # Reload wallet to pick up updated balance and nonce
        wallet = load_wallet(wallet.name)
    else:
        _err(msg)

    _pause()
    return wallet


def action_view_incoming(
    wallet: Wallet,
    ledger: Ledger,
    balance_mgr: BalanceManager,
) -> None:
    """Show all transactions where this wallet is the receiver."""
    _section(f"INCOMING PAYMENTS -- {wallet.name.upper()}")

    entries = ledger.get_history(wallet.address)
    incoming = [e for e in entries if e.tx_dict.get("receiver") == wallet.address]

    if not incoming:
        _info("No incoming payments found.")
    else:
        print(f"\n  {'#':<4} {'From (address)':<22} {'Amount':>10}  {'Date':<20}")
        print(f"  {'-'*4} {'-'*22} {'-'*10}  {'-'*20}")
        for i, entry in enumerate(incoming, 1):
            tx  = entry.tx_dict
            sender_short = tx["sender"][:20] + "..."
            print(f"  {i:<4} {sender_short:<22} {tx['amount']:>10.2f}  {tx['timestamp']:<20}")

    print(f"\n  Current balance: {balance_mgr.get_balance(wallet.address):.2f} tokens")
    _pause()


def action_send_request(
    wallet: Wallet,
    request_mgr: RequestManager,
) -> None:
    """Send a payment request to the other user."""
    _section("SEND PAYMENT REQUEST")

    peer = get_peer_wallet(wallet.name)
    print(f"\n  Your address   : {wallet.address}")
    print(f"  (For convenience, {peer.name}'s address is {peer.address})")

    payer_address = _ask("Enter payer's 10-digit wallet address (or 0 to cancel)")
    if payer_address == "0" or not payer_address:
        _info("Request cancelled.")
        _pause()
        return

    if payer_address != peer.address:
        _err(f"Unknown or invalid address '{payer_address}'. For this demo, please request from {peer.name}'s address: {peer.address}")
        _pause()
        return

    amount_str = _ask("Enter amount to request (or 0 to cancel)")
    try:
        amount = float(amount_str)
    except ValueError:
        _err("Invalid amount.")
        _pause()
        return

    if amount <= 0:
        _info("Request cancelled.")
        _pause()
        return

    req = request_mgr.create_request(
        from_address=wallet.address,
        from_name=wallet.name,
        to_address=payer_address,
        to_name=peer.name,
        amount=amount,
    )

    _ok(f"Payment request sent to {peer.name} for {amount:.2f} tokens.")
    print(f"  Request ID : {req.request_id}")
    _pause()


def action_view_requests(
    wallet: Wallet,
    request_mgr: RequestManager,
    balance_mgr: BalanceManager,
    nonce_tracker: NonceTracker,
    ledger: Ledger,
) -> Wallet:
    """View and respond to payment requests addressed to this wallet."""
    _section(f"PAYMENT REQUESTS -- {wallet.name.upper()}")

    pending = request_mgr.get_pending_for(wallet.address)

    if not pending:
        _info("No pending payment requests.")
        _pause()
        return wallet

    print(f"\n  You have {len(pending)} pending request(s):\n")
    for i, req in enumerate(pending, 1):
        print(f"  [{i}] From : {req.from_name} ({req.from_address[:20]}...)")
        print(f"       Amount: {req.amount:.2f} tokens")
        print(f"       ID    : {req.request_id}")
        print()

    choice_str = _ask("Enter request number to respond to (or 0 to go back)")
    try:
        choice = int(choice_str)
    except ValueError:
        _err("Invalid selection.")
        _pause()
        return wallet

    if choice == 0 or choice > len(pending):
        return wallet

    selected_req = pending[choice - 1]

    print(f"\n  Request from {selected_req.from_name}: {selected_req.amount:.2f} tokens")
    print(f"  Your current balance: {balance_mgr.get_balance(wallet.address):.2f} tokens")
    action_str = _ask("1 = Accept   2 = Reject   0 = Cancel")

    if action_str == "1":
        # Accept -> run a full payment from this wallet to the requester
        ok, msg, tx = process_payment(
            sender_wallet=wallet,
            receiver_address=selected_req.from_address,
            amount=selected_req.amount,
            balance_mgr=balance_mgr,
            nonce_tracker=nonce_tracker,
            ledger=ledger,
        )
        if ok:
            request_mgr.accept_request(selected_req.request_id)
            _ok(f"Accepted -- {selected_req.amount:.2f} tokens sent to {selected_req.from_name}!")
            print(f"  TX-ID       : {tx.tx_id}")
            print(f"  New balance : {balance_mgr.get_balance(wallet.address):.2f}")
            wallet = load_wallet(wallet.name, password)
        else:
            _err(f"Payment failed: {msg}")

    elif action_str == "2":
        request_mgr.reject_request(selected_req.request_id)
        _ok(f"Request from {selected_req.from_name} rejected. No funds moved.")

    else:
        _info("Cancelled.")

    _pause()
    return wallet


def action_view_transactions(wallet: Wallet, ledger: Ledger) -> None:
    """Display all transactions involving this wallet."""
    _section(f"MY TRANSACTIONS -- {wallet.name.upper()}")

    entries = ledger.get_history(wallet.address)

    if not entries:
        _info("No transactions found.")
        _pause()
        return

    print(f"\n  Total transactions: {len(entries)}\n")
    print(f"  {'#':<4} {'Type':<8} {'Peer':<22} {'Amount':>10}  {'Date':<20}")
    print(f"  {'-'*4} {'-'*8} {'-'*22} {'-'*10}  {'-'*20}")

    for i, entry in enumerate(entries, 1):
        tx = entry.tx_dict
        if tx["sender"] == wallet.address:
            direction = "SENT"
            peer      = tx["receiver"][:20] + "..."
            amount    = -tx["amount"]
        else:
            direction = "RECV"
            peer      = tx["sender"][:20] + "..."
            amount    = tx["amount"]

        amt_str = f"{amount:+.2f}"
        print(f"  {i:<4} {direction:<8} {peer:<22} {amt_str:>10}  {tx['timestamp']:<20}")

    _pause()


def action_wallet_info(wallet: Wallet, balance_mgr: BalanceManager) -> None:
    """Display detailed wallet information."""
    _section(f"WALLET INFORMATION -- {wallet.name.upper()}")

    balance = balance_mgr.get_balance(wallet.address)

    print(f"""
  ┌-------------------------------------------------+
  |  Name           : {wallet.name:<31}|
  |  Address        : {wallet.address:<31}|
  |  Balance        : {balance:<31.2f}|
  |  Next Nonce     : {wallet.nonce:<31}|
  +-------------------------------------------------+
  |  Public Key     : (available for verification)  |
  |  Private Key    : *** AES-256 ENCRYPTED ***     |
  |                   (never displayed)             |
  +-------------------------------------------------+

  SECURITY NOTES:
  * Private key is stored AES-256-CBC encrypted on disk.
  * Private key exists in memory ONLY during this session.
  * Your address is derived from your public key via SHA-256.
  * Each transaction is signed with your private key (ECDSA).
""")
    _pause()


def action_check_integrity(ledger: Ledger) -> None:
    """Run the ledger integrity check and display results."""
    _section("LEDGER INTEGRITY CHECK")

    ledger.reload()
    entries = ledger.get_all_entries()

    print(f"\n  Total ledger entries : {len(entries)}")
    print("  Running hash-chain verification ...\n")

    ok, msg = verify_ledger_integrity(entries)

    if ok:
        print(f"  (OK)  {msg}")
    else:
        print(f"  (X)  INTEGRITY FAILURE DETECTED!\n")
        print(f"     {msg}")

    _pause()


# ==============================================================================
#  Wallet Dashboard
# ==============================================================================


def action_change_password(wallet: Wallet, current_password: str) -> str:
    """Prompt for current and new password, re-encrypt wallet if valid."""
    _section("CHANGE PASSWORD")

    verify_pwd = _input_password("  Current password: ")
    try:
        load_wallet(wallet.name, verify_pwd)
    except (ValueError, FileNotFoundError):
        _err("Incorrect current password.")
        _pause()
        return current_password

    new_pwd     = _input_password("  New password: ")
    confirm_pwd = _input_password("  Confirm new password: ")

    if new_pwd != confirm_pwd:
        _err("Passwords do not match.")
        _pause()
        return current_password

    save_wallet(wallet, new_pwd)
    _ok("Password changed successfully.")
    _pause()
    return new_pwd


def wallet_dashboard(
    user_name: str,
    password: str,
    balance_mgr: BalanceManager,
    nonce_tracker: NonceTracker,
    ledger: Ledger,
    request_mgr: RequestManager,
) -> None:
    """
    Main wallet dashboard loop for a logged-in user.

    Runs until the user selects "Logout".
    """
    wallet = load_wallet(user_name, password)
    balance_mgr.initialise_if_missing(wallet.address)

    while True:
        _clear()
        _banner()
        balance = balance_mgr.get_balance(wallet.address)
        pending_count = len(request_mgr.get_pending_for(wallet.address))

        print(f"""
  +==================================================+
  |  Logged in as : {wallet.name:<33}|
  |  Address      : {wallet.address[:33]:<33}|
  |  Balance      : {balance:<33.2f}|
  +==================================================+

  1.  Send Money
  2.  Receive / View Incoming Payments
  3.  Send Payment Request
  4.  View Payment Requests ({pending_count} pending)
  5.  View My Transactions
  6.  View Wallet Information
  7.  Check Ledger Integrity
  8.  Change Password
  9.  Logout
""")

        choice = _ask("Select option")

        if choice == "1":
            wallet = action_send_money(wallet, balance_mgr, nonce_tracker, ledger)

        elif choice == "2":
            action_view_incoming(wallet, ledger, balance_mgr)

        elif choice == "3":
            action_send_request(wallet, request_mgr)

        elif choice == "4":
            wallet = action_view_requests(
                wallet, request_mgr, balance_mgr, nonce_tracker, ledger
            )

        elif choice == "5":
            action_view_transactions(wallet, ledger)

        elif choice == "6":
            action_wallet_info(wallet, balance_mgr)

        elif choice == "7":
            action_check_integrity(ledger)

        elif choice == "8":
            password = action_change_password(wallet, password)

        elif choice == "9":
            _info(f"Goodbye, {wallet.name}!")
            break

        else:
            _err("Invalid option -- please enter 1-9.")
            _pause()


# ==============================================================================
#  Main Menu
# ==============================================================================

def main_menu(
    balance_mgr: BalanceManager,
    nonce_tracker: NonceTracker,
    ledger: Ledger,
    request_mgr: RequestManager,
) -> None:
    """Display and handle the main login menu."""

    while True:
        _clear()
        _banner()
        print("""
  --------------------------------------------------
  Login by typing your username (e.g. Alice, Bob)
  or type 'exit' to quit.
  --------------------------------------------------
""")

        username = _ask("Enter username").strip().lower()

        if username == "exit":
            print("\n  Goodbye!\n")
            sys.exit(0)

        elif username in ("alice", "bob"):
            password = _input_password("  Password: ")
            try:
                load_wallet(username, password)
            except (ValueError, FileNotFoundError):
                _err("Incorrect password. Access denied.")
                _pause()
                continue
            try:
                wallet_dashboard(username, password, balance_mgr, nonce_tracker, ledger, request_mgr)
            except Exception as e:
                _err(f"Session error: {e}")
                _pause()

        else:
            _err(f"Invalid username '{username}'. Please enter Alice or Bob (or 'exit' to quit).")
            _pause()


# ==============================================================================
#  Entry point
# ==============================================================================

if __name__ == "__main__":
    # Ensure data directories exist
    from config import DATA_DIR, WALLETS_DIR, LEDGER_DIR, STATE_DIR
    for d in (DATA_DIR, WALLETS_DIR, LEDGER_DIR, STATE_DIR):
        os.makedirs(d, exist_ok=True)

    print("  Initialising CryptoVault system ...")
    balance_mgr, nonce_tracker, ledger, request_mgr = initialise_system()
    print("  System ready.\n")

    main_menu(balance_mgr, nonce_tracker, ledger, request_mgr)
