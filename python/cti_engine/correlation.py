"""Minimal correlation logic for the first engine slice."""

from __future__ import annotations

from typing import Any

from .events import ScanEvent


def run_simple_correlations(events: list[ScanEvent]) -> list[dict[str, Any]]:
    """Return simple high-level findings from engine events.

    This is intentionally small for the first implementation slice.
    """
    findings: list[dict[str, Any]] = []
    malicious = [event for event in events if event.event_type.startswith("malicious_")]
    if malicious:
        findings.append({
            "rule_name": "MALICIOUS_EVENT_PRESENT",
            "severity": "high",
            "title": "Malicious event(s) were identified",
            "detail": f"{len(malicious)} malicious event(s) were produced during the scan.",
            "linked_event_ids": [event.event_id for event in malicious],
        })
    return findings

