from __future__ import annotations

import io

import qrcode


def url_to_qr_png(url: str) -> bytes:
    image = qrcode.make(url)
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()
