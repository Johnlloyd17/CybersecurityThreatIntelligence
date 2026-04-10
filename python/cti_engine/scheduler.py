"""Simple scheduling helpers for the first engine slice."""

from __future__ import annotations


def normalize_concurrency_limit(raw_value: int | str | None, default: int = 3) -> int:
    try:
        value = int(raw_value) if raw_value is not None else default
    except (TypeError, ValueError):
        value = default
    return max(1, value)

