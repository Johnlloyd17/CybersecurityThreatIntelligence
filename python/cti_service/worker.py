"""Background worker helpers for the CTI engine service."""

from __future__ import annotations

import asyncio

from ..cti_engine.context import ScanContext
from ..cti_engine.projector import project_scan
from ..cti_engine.queue import ScanQueueEngine
from ..cti_engine.registry import ModuleRegistry
from ..cti_engine.modules import register_builtin_modules
from .schemas import CreateScanRequest


def build_default_registry() -> ModuleRegistry:
    registry = ModuleRegistry()
    register_builtin_modules(registry)
    return registry


def run_scan_job(request: CreateScanRequest, cancel_event=None):
    engine_request = request.to_engine_request()
    ctx = ScanContext(request=engine_request, cancel_event=cancel_event)
    registry = build_default_registry()
    engine = ScanQueueEngine(registry)
    result = asyncio.run(engine.run(ctx))
    return project_scan(
        scan_id=engine_request.scan_id,
        scan_name=engine_request.scan_name,
        root_target=engine_request.target.normalized,
        status=result.status,
        events=result.events,
        logs=result.logs,
        correlations=result.correlations,
    )
