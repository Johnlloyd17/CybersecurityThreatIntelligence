"""Core event and log data models for the CTI engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .hashes import build_event_id


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class ScanEvent:
    """Normalized internal event emitted and consumed by engine modules."""

    event_type: str
    value: str
    source_module: str
    root_target: str
    parent_event_id: str | None = None
    confidence: int = 100
    visibility: int = 100
    risk_score: int = 0
    severity: str = "info"
    false_positive: bool = False
    tags: list[str] = field(default_factory=list)
    raw_payload: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=utc_now)
    event_id: str = field(init=False)

    def __post_init__(self) -> None:
        self.event_type = str(self.event_type or "").strip().lower()
        self.value = str(self.value or "").strip()
        self.source_module = str(self.source_module or "").strip().lower() or "unknown"
        self.root_target = str(self.root_target or "").strip()
        if not self.event_type:
            raise ValueError("event_type cannot be blank")
        if not self.value:
            raise ValueError("value cannot be blank")
        if not self.root_target:
            raise ValueError("root_target cannot be blank")

        self.confidence = max(0, min(100, int(self.confidence)))
        self.visibility = max(0, min(100, int(self.visibility)))
        self.risk_score = max(0, min(100, int(self.risk_score)))
        self.severity = str(self.severity or "info").strip().lower()
        self.event_id = build_event_id(
            self.event_type,
            self.value,
            self.source_module,
            self.parent_event_id,
            self.root_target,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "value": self.value,
            "source_module": self.source_module,
            "parent_event_id": self.parent_event_id,
            "root_target": self.root_target,
            "confidence": self.confidence,
            "visibility": self.visibility,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "false_positive": self.false_positive,
            "tags": list(self.tags),
            "raw_payload": dict(self.raw_payload),
            "created_at": self.created_at.isoformat(),
        }


@dataclass(slots=True)
class ScanLogEntry:
    """Structured log entry emitted by engine components."""

    level: str
    message: str
    module: str | None = None
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        self.level = str(self.level or "info").strip().lower()
        self.message = str(self.message or "").strip()
        self.module = None if self.module is None else str(self.module).strip().lower()

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "message": self.message,
            "module": self.module,
            "created_at": self.created_at.isoformat(),
        }

