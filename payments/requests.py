"""
payments/requests.py -- Payment Request System
=============================================

A payment request is a message from one user asking another to send
money.  It is NOT a transaction -- it does not move any funds by itself.

Flow:
  Alice creates a request to Bob (amount = 20)
         v
  Request saved to  data/state/requests.json
         v
  Bob logs in and views pending requests
         v
  Bob chooses ACCEPT or REJECT
         v
  ACCEPT -> calls process_payment() with Bob as sender, Alice as receiver
  REJECT -> request marked rejected, no funds moved

Key point:
  A request only results in a real transaction when the REQUESTED PARTY
  (Bob) explicitly accepts it AND the full payment pipeline validates.
  Bob must have sufficient balance, a valid key, etc.
"""

import uuid
import datetime
from dataclasses import dataclass, field
from typing import Optional

from config import REQUESTS_FILE
from storage.storage import load_json, save_json


@dataclass
class PaymentRequest:
    """
    Represents a payment request between two wallets.

    Attributes
    ----------
    request_id      : str -- Unique UUID for this request.
    from_address    : str -- Address of the user requesting payment (payee).
    from_name       : str -- Human-readable name of the requester.
    to_address      : str -- Address of the user being asked to pay (payer).
    to_name         : str -- Human-readable name of the payer.
    amount          : float -- Amount requested.
    status          : str -- "pending", "accepted", or "rejected".
    created_at      : str -- ISO-8601 UTC timestamp.
    """
    request_id:   str
    from_address: str
    from_name:    str
    to_address:   str
    to_name:      str
    amount:       float
    status:       str = "pending"
    created_at:   str = field(default_factory=lambda: datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))

    def to_dict(self) -> dict:
        return {
            "request_id":   self.request_id,
            "from_address": self.from_address,
            "from_name":    self.from_name,
            "to_address":   self.to_address,
            "to_name":      self.to_name,
            "amount":       self.amount,
            "status":       self.status,
            "created_at":   self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PaymentRequest":
        return cls(
            request_id=data["request_id"],
            from_address=data["from_address"],
            from_name=data["from_name"],
            to_address=data["to_address"],
            to_name=data["to_name"],
            amount=data["amount"],
            status=data.get("status", "pending"),
            created_at=data.get("created_at", ""),
        )


class RequestManager:
    """
    Manages the lifecycle of payment requests.

    Requests are persisted to  data/state/requests.json.
    """

    def __init__(self) -> None:
        self._requests: list[PaymentRequest] = []
        self._load()

    # -- Create ----------------------------------------------------------------

    def create_request(
        self,
        from_address: str,
        from_name: str,
        to_address: str,
        to_name: str,
        amount: float,
    ) -> PaymentRequest:
        """
        Create and persist a new payment request.

        Parameters
        ----------
        from_address : str   -- Requester's wallet address (wants to receive).
        from_name    : str   -- Requester's name.
        to_address   : str   -- Payer's wallet address (being asked to send).
        to_name      : str   -- Payer's name.
        amount       : float -- Amount requested.

        Returns
        -------
        PaymentRequest : The newly created request.
        """
        req = PaymentRequest(
            request_id=str(uuid.uuid4()),
            from_address=from_address,
            from_name=from_name,
            to_address=to_address,
            to_name=to_name,
            amount=amount,
        )
        self._requests.append(req)
        self._save()
        return req

    # -- Query -----------------------------------------------------------------

    def get_pending_for(self, address: str) -> list[PaymentRequest]:
        """
        Return all pending requests where `address` is the payer (to_address).

        These are the requests this user needs to respond to.
        """
        return [
            r for r in self._requests
            if r.to_address == address and r.status == "pending"
        ]

    def get_sent_by(self, address: str) -> list[PaymentRequest]:
        """Return all requests created by this address (from_address)."""
        return [r for r in self._requests if r.from_address == address]

    def get_by_id(self, request_id: str) -> Optional[PaymentRequest]:
        """Find a request by its UUID."""
        for r in self._requests:
            if r.request_id == request_id:
                return r
        return None

    # -- Update status ---------------------------------------------------------

    def accept_request(self, request_id: str) -> bool:
        """
        Mark a request as accepted.

        NOTE: This only updates the status flag.  The actual payment
        (balance change, ledger entry) is done by the caller using
        process_payment() BEFORE calling this method.

        Returns True if the request was found and updated.
        """
        return self._update_status(request_id, "accepted")

    def reject_request(self, request_id: str) -> bool:
        """
        Mark a request as rejected.  No funds are moved.

        Returns True if the request was found and updated.
        """
        return self._update_status(request_id, "rejected")

    def _update_status(self, request_id: str, new_status: str) -> bool:
        for req in self._requests:
            if req.request_id == request_id:
                req.status = new_status
                self._save()
                return True
        return False

    # -- Persistence -----------------------------------------------------------

    def _load(self) -> None:
        raw = load_json(REQUESTS_FILE, default=[])
        self._requests = [PaymentRequest.from_dict(r) for r in raw]

    def _save(self) -> None:
        save_json(REQUESTS_FILE, [r.to_dict() for r in self._requests])
