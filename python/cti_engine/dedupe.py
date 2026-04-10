"""Simple dedupe helpers for the CTI engine."""

from __future__ import annotations


class DedupeIndex:
    """Track seen event ids to prevent repeated queue work."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def add(self, event_id: str) -> bool:
        if event_id in self._seen:
            return False
        self._seen.add(event_id)
        return True

    def __contains__(self, event_id: str) -> bool:
        return event_id in self._seen

    def __len__(self) -> int:
        return len(self._seen)

