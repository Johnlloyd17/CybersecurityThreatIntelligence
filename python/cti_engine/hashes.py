"""Deterministic hashing helpers for CTI engine entities."""

from __future__ import annotations

import hashlib
from typing import Any, Iterable


def canonicalize_text(value: Any) -> str:
    """Convert arbitrary values into a deterministic normalized string."""
    text = str(value if value is not None else "").strip().lower()
    return " ".join(text.split())


def stable_digest(parts: Iterable[Any]) -> str:
    """Build a stable SHA-256 digest from a sequence of values."""
    normalized = [canonicalize_text(part) for part in parts]
    joined = "|".join(normalized)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def build_event_id(
    event_type: str,
    value: str,
    source_module: str,
    parent_event_id: str | None,
    root_target: str,
) -> str:
    """Build a deterministic event id for deduplication and lineage."""
    return stable_digest([
        event_type,
        value,
        source_module,
        parent_event_id or "ROOT",
        root_target,
    ])

