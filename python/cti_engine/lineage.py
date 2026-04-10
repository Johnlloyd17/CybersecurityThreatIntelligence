"""Lineage helpers for projected event graphs."""

from __future__ import annotations

from collections import defaultdict

from .events import ScanEvent


def build_parent_child_index(events: list[ScanEvent]) -> dict[str | None, list[str]]:
    index: dict[str | None, list[str]] = defaultdict(list)
    for event in events:
        index[event.parent_event_id].append(event.event_id)
    return dict(index)

