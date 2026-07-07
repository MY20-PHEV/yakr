from __future__ import annotations


class YakrError(Exception):
    """Base error for Yakr operations."""

    code: str = "YAKR_ERR_UNKNOWN"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code


class RelayError(YakrError):
    code = "YAKR_ERR_RELAY_OFFLINE"


class UnauthorizedError(YakrError):
    code = "YAKR_ERR_RELAY_UNAUTHORIZED"


class BlobExpiredError(YakrError):
    code = "YAKR_ERR_BLOB_EXPIRED"


class DecryptError(YakrError):
    code = "YAKR_ERR_DECRYPT_FAILED"


class DuplicateSeqError(YakrError):
    code = "YAKR_ERR_DUPLICATE_SEQ"


class ContactNotFoundError(YakrError):
    code = "YAKR_ERR_CONTACT_NOT_FOUND"
