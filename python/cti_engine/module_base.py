"""Base module contract for the first-party CTI engine."""

from __future__ import annotations

from typing import AsyncIterator

from .events import ScanEvent


class BaseModule:
    """Base class for all CTI engine modules."""

    slug = "base"
    name = "Base Module"
    watched_types: set[str] = set()
    produced_types: set[str] = set()
    requires_key = False

    async def setup(self, ctx) -> None:
        """Optional module setup hook."""
        return None

    async def handle(self, event: ScanEvent, ctx) -> AsyncIterator[ScanEvent]:
        """Process an event and yield zero or more child events."""
        if False:
            yield event
        return

