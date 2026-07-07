from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass


def current_epoch(*, epoch_secs: int = 3600) -> int:
    return int(time.time()) // epoch_secs


@dataclass(frozen=True)
class MailboxTag:
    tag: bytes
    epoch: int
    direction: str

    @property
    def tag_b64(self) -> str:
        import base64

        return base64.urlsafe_b64encode(self.tag).decode("ascii").rstrip("=")


class MailboxTagDeriver:
    def __init__(self, mailbox_secret: bytes, *, epoch_secs: int = 3600) -> None:
        self._secret = mailbox_secret
        self._epoch_secs = epoch_secs

    def derive(self, direction: str, *, epoch: int | None = None) -> MailboxTag:
        epoch_value = current_epoch(epoch_secs=self._epoch_secs) if epoch is None else epoch
        material = f"{direction}|{epoch_value}".encode("utf-8")
        tag = hmac.new(self._secret, material, hashlib.sha256).digest()
        return MailboxTag(tag=tag, epoch=epoch_value, direction=direction)

    def candidate_epochs(self, direction: str, *, lookback: int = 2) -> list[MailboxTag]:
        now = current_epoch(epoch_secs=self._epoch_secs)
        return [self.derive(direction, epoch=now - offset) for offset in range(lookback + 1)]
