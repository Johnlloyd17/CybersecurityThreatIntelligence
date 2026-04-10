"""Streaming helpers for future SSE/websocket output."""

from __future__ import annotations

import json
from typing import Any


def to_sse(event_name: str, payload: dict[str, Any]) -> bytes:
    body = f"event: {event_name}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"
    return body.encode("utf-8")

