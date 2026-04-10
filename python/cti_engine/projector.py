"""Project engine runs into CTI-friendly read models."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .events import ScanEvent
from .lineage import build_parent_child_index
from .storage.models import ProjectedEventRow, ProjectedLogRow, ProjectedResultRow, ProjectedScan


def _display_type(event: ScanEvent) -> str:
    return event.event_type.replace("_", " ").title()


def _result_summary(event: ScanEvent) -> str:
    return f"{_display_type(event)}: {event.value}"


def _projected_seed_type(event: ScanEvent) -> str | None:
    if event.source_module != "seed":
        return None
    if event.event_type == "domain":
        return "internet_name"
    return None


def project_scan(
    scan_id: int,
    scan_name: str,
    root_target: str,
    status: str,
    events: list[ScanEvent],
    logs: list[dict[str, Any]],
    correlations: list[dict[str, Any]],
) -> ProjectedScan:
    result_rows: list[ProjectedResultRow] = []
    event_rows: list[ProjectedEventRow] = []
    log_rows: list[ProjectedLogRow] = []

    for index, event in enumerate(events, start=1):
        projected_event_type = _projected_seed_type(event) or event.event_type
        projected_event = event
        if projected_event_type != event.event_type:
            projected_event = ScanEvent(
                event_type=projected_event_type,
                value=event.value,
                source_module=event.source_module,
                root_target=event.root_target,
                parent_event_id=event.parent_event_id,
                confidence=event.confidence,
                visibility=event.visibility,
                risk_score=event.risk_score,
                severity=event.severity,
                false_positive=event.false_positive,
                tags=list(event.tags),
                raw_payload=dict(event.raw_payload),
                created_at=event.created_at,
            )
        elif event.source_module == "seed":
            continue

        result_rows.append(ProjectedResultRow(
            row_id=index,
            query_type=projected_event.event_type,
            query_value=projected_event.value,
            api_source=projected_event.source_module,
            data_type=_display_type(projected_event),
            result_summary=_result_summary(projected_event),
            risk_score=projected_event.risk_score,
            status="completed",
            source_ref=projected_event.parent_event_id or "ROOT",
            created_at=projected_event.created_at.isoformat(),
        ))

        event_rows.append(ProjectedEventRow(
            event_id=projected_event.event_id,
            event_type=projected_event.event_type,
            value=projected_event.value,
            source_module=projected_event.source_module,
            parent_event_id=projected_event.parent_event_id,
            risk_score=projected_event.risk_score,
            confidence=projected_event.confidence,
            created_at=projected_event.created_at.isoformat(),
        ))

    for log in logs:
        log_rows.append(ProjectedLogRow(
            level=str(log.get("level", "info")),
            message=str(log.get("message", "")),
            module=log.get("module"),
            created_at=str(log.get("created_at", "")),
        ))

    counts = Counter(row.data_type for row in result_rows)
    parent_child = build_parent_child_index(events)

    return ProjectedScan(
        scan_id=scan_id,
        scan_name=scan_name,
        root_target=root_target,
        status=status,
        result_rows=result_rows,
        event_rows=event_rows,
        log_rows=log_rows,
        correlations=correlations,
        type_counts=dict(counts),
        parent_child_index=parent_child,
    )
