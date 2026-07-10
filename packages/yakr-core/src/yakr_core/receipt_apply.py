"""Inbound delivery receipt handling."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from yakr_core.message import InnerMessage
    from yakr_core.store import LocalStore


def has_outbound_pending(store: "LocalStore", contact_name: str, message_id: str) -> bool:
    return any(mid == message_id for mid, _seq, _body in store.list_outbound_pending(contact_name))


def apply_inbound_delivery_receipt(
    store: "LocalStore",
    contact_name: str,
    inner: "InnerMessage",
) -> bool:
    """Apply a decrypted receipt inner message.

  Returns True when an ``outbound_pending`` row was removed. Unknown ``message_id``
  values return False and MUST NOT affect unrelated pending rows.

  Callers MUST have already run ``Session.decrypt_outer`` so ``last_recv_seq`` reflects
  the receipt — stale or forged receipts still consume the sender's ``seq`` slot.
    """
    if inner.type != "receipt" or not inner.message_id:
        return False
    return store.mark_outbound_delivered(contact_name, inner.message_id)
