"""Queue backend abstraction placeholder."""

from __future__ import annotations

from .jobs import JobManager


def build_queue_backend(max_workers: int = 4) -> JobManager:
    return JobManager(max_workers=max_workers)

