"""Event queue engine."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any

from .context import ScanContext
from .correlation import run_simple_correlations
from .dedupe import DedupeIndex
from .events import ScanEvent
from .registry import ModuleRegistry
from .scoring import severity_from_risk


@dataclass(slots=True)
class EngineRunResult:
    status: str
    events: list[ScanEvent]
    logs: list[dict[str, Any]]
    correlations: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "events": [event.to_dict() for event in self.events],
            "logs": list(self.logs),
            "correlations": list(self.correlations),
        }


class ScanQueueEngine:
    """Simple event-driven scan queue for the first implementation slice."""

    def __init__(self, registry: ModuleRegistry) -> None:
        self.registry = registry

    async def run(self, ctx: ScanContext) -> EngineRunResult:
        selected_instances = self.registry.create_selected(ctx.request.selected_modules)
        if not selected_instances:
            raise ValueError("No selected modules are available in the registry")

        for module in selected_instances.values():
            await module.setup(ctx)

        seed_event = ScanEvent(
            event_type=ctx.request.target.target_type,
            value=ctx.request.target.normalized,
            source_module="seed",
            root_target=ctx.request.target.normalized,
            parent_event_id=None,
            severity="info",
        )

        ctx.events.append(seed_event)
        ctx.info(
            f"Engine seed created for {ctx.request.target.normalized} ({ctx.request.target.target_type}).",
            "engine",
        )

        queue: deque[ScanEvent] = deque([seed_event])
        seen = DedupeIndex()
        seen.add(seed_event.event_id)
        logged_unhandled_types: set[str] = set()

        while queue:
            if ctx.is_cancelled():
                ctx.warning("Termination requested; stopping queue execution.", "engine")
                correlations = run_simple_correlations(ctx.events)
                return EngineRunResult(
                    status="aborted",
                    events=list(ctx.events),
                    logs=[entry.to_dict() for entry in ctx.logs],
                    correlations=correlations,
                )

            current = queue.popleft()
            watchers = self.registry.watchers_for(current.event_type, selected_instances)
            if not watchers:
                if current.event_type not in logged_unhandled_types:
                    logged_unhandled_types.add(current.event_type)
                    ctx.debug(
                        f"No modules registered for event type '{current.event_type}'.",
                        "engine",
                    )
                continue

            for module in watchers:
                if ctx.is_cancelled():
                    break
                ctx.debug(
                    f"Dispatching event '{current.event_type}' to module '{module.slug}'.",
                    module.slug,
                )
                async for child in module.handle(current, ctx):
                    child.severity = severity_from_risk(child.risk_score)
                    if seen.add(child.event_id):
                        ctx.events.append(child)
                        queue.append(child)

        correlations = run_simple_correlations(ctx.events)
        ctx.info(
            f"Engine completed with {len(ctx.events)} event(s) and {len(correlations)} correlation(s).",
            "engine",
        )

        return EngineRunResult(
            status="finished",
            events=list(ctx.events),
            logs=[entry.to_dict() for entry in ctx.logs],
            correlations=correlations,
        )
