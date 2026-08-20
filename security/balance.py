"""
security/balance.py -- Balance Tracking & Double-Spend Protection
================================================================

CONCEPT: Double-Spend Protection
----------------------------------
In any digital cash system, it must be impossible for a user to spend
the same money twice.  Unlike physical cash (which changes hands),
digital data can be copied.

CRYPTOVAULT prevents double-spending by:
  1. Maintaining an authoritative balance record for each address.
  2. Checking the balance BEFORE accepting any transaction.
  3. Only committing a balance change AFTER ALL validation passes.

A valid ECDSA signature does NOT mean the sender has enough money.
Balance check is a SEPARATE, INDEPENDENT validation step.

Example:
  Alice = 100
  Alice sends 30 -> ACCEPTED   Alice = 70, Bob = 130
  Alice sends 80 -> REJECTED   (70 < 80)   balances unchanged

PERSISTENCE
-----------
Balances are saved to  data/state/balances.json  after every change.

Data format:
  {
    "<wallet_address>": 100.0,
    ...
  }
"""

from config import BALANCE_FILE, INITIAL_BALANCE
from storage.storage import load_json, save_json


class BalanceManager:
    """
    Manages token balances for all wallet addresses.

    Balances are loaded from disk on initialisation and persisted
    after every change (debit or credit).
    """

    def __init__(self) -> None:
        # Maps wallet_address -> float balance
        self._balances: dict[str, float] = load_json(BALANCE_FILE, default={})

    # -- Read operations --------------------------------------------------------

    def get_balance(self, address: str) -> float:
        """
        Return the current balance for the given wallet address.

        If the address is not yet in the balance store (new wallet),
        return INITIAL_BALANCE so new wallets automatically start funded.
        """
        return self._balances.get(address, INITIAL_BALANCE)

    def check_sufficient(self, address: str, amount: float) -> tuple[bool, str]:
        """
        Check whether the wallet at `address` has at least `amount` tokens.

        Returns
        -------
        (True,  "OK")         -- sufficient balance
        (False, "<message>")  -- insufficient balance

        DOUBLE-SPEND PROTECTION: This is the guard against overdraft.
        """
        current = self.get_balance(address)
        if current < amount:
            return False, (
                f"Insufficient balance: address {address[:16]}... "
                f"has {current:.2f} but tried to send {amount:.2f}."
            )
        return True, "OK"

    # -- Write operations -------------------------------------------------------

    def debit(self, address: str, amount: float) -> None:
        """
        Subtract `amount` from the wallet's balance.

        Called ONLY after full validation passes -- never before.

        Parameters
        ----------
        address : str   -- Sender's wallet address.
        amount  : float -- Amount to subtract (must be positive).
        """
        current = self.get_balance(address)
        self._balances[address] = round(current - amount, 10)
        self._save()

    def credit(self, address: str, amount: float) -> None:
        """
        Add `amount` to the wallet's balance.

        Called for the receiver after a transaction is accepted.

        Parameters
        ----------
        address : str   -- Receiver's wallet address.
        amount  : float -- Amount to add.
        """
        current = self.get_balance(address)
        self._balances[address] = round(current + amount, 10)
        self._save()

    def initialise_if_missing(self, address: str) -> None:
        """
        Ensure a wallet address has an entry in the balance store.

        Called when a new wallet is created so the address appears
        explicitly in the JSON file (easier to inspect for debugging).
        """
        if address not in self._balances:
            self._balances[address] = INITIAL_BALANCE
            self._save()

    def set_balance(self, address: str, amount: float) -> None:
        """
        Directly set a balance -- used ONLY in attack simulations and tests.
        DO NOT call this in normal payment flow.
        """
        self._balances[address] = amount
        self._save()

    def _save(self) -> None:
        """Persist balance state to disk."""
        save_json(BALANCE_FILE, self._balances)
