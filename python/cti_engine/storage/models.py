"""Projected row models for CTI-compatible persistence."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class ProjectedResultRow:
    row_id: int
    query_type: str
    query_value: str
    api_source: str
    data_type: str
    result_summary: str
    risk_score: int
    status: str
    source_ref: str
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ProjectedEventRow:
    event_id: str
    event_type: str
    value: str
    source_module: str
    parent_event_id: str | None
    risk_score: int
    confidence: int
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ProjectedLogRow:
    level: str
    message: str
    module: str | None
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ProjectedScan:
    scan_id: int
    scan_name: str
    root_target: str
    status: str
    result_rows: list[ProjectedResultRow] = field(default_factory=list)
    event_rows: list[ProjectedEventRow] = field(default_factory=list)
    log_rows: list[ProjectedLogRow] = field(default_factory=list)
    correlations: list[dict[str, Any]] = field(default_factory=list)
    type_counts: dict[str, int] = field(default_factory=dict)
    parent_child_index: dict[str | None, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "scan_name": self.scan_name,
            "root_target": self.root_target,
            "status": self.status,
            "results": [row.to_dict() for row in self.result_rows],
            "events": [row.to_dict() for row in self.event_rows],
            "logs": [row.to_dict() for row in self.log_rows],
            "correlations": list(self.correlations),
            "type_counts": dict(self.type_counts),
            "parent_child_index": dict(self.parent_child_index),
        }

