"""Execution context and frozen request model."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .events import ScanEvent, ScanLogEntry
from .settings import SettingsSnapshot
from .targets import NormalizedTarget


@dataclass(slots=True)
class ScanRequest:
    scan_id: int
    user_id: int
    scan_name: str
    target: NormalizedTarget
    selected_modules: list[str]
    settings: SettingsSnapshot = field(default_factory=SettingsSnapshot)


@dataclass(slots=True)
class ScanContext:
    request: ScanRequest
    logs: list[ScanLogEntry] = field(default_factory=list)
    events: list[ScanEvent] = field(default_factory=list)
    cancel_event: Any | None = None

    def log(self, level: str, message: str, module: str | None = None) -> None:
        self.logs.append(ScanLogEntry(level=level, message=message, module=module))

    def debug(self, message: str, module: str | None = None) -> None:
        self.log("debug", message, module)

    def info(self, message: str, module: str | None = None) -> None:
        self.log("info", message, module)

    def warning(self, message: str, module: str | None = None) -> None:
        self.log("warning", message, module)

    def error(self, message: str, module: str | None = None) -> None:
        self.log("error", message, module)

    def module_settings_for(self, slug: str) -> dict[str, Any]:
        return self.request.settings.module_settings_for(slug)

    def api_config_for(self, slug: str) -> dict[str, Any]:
        return self.request.settings.api_config_for(slug)

    @property
    def root_target(self) -> str:
        return self.request.target.normalized

    def is_cancelled(self) -> bool:
        return bool(self.cancel_event and getattr(self.cancel_event, "is_set", lambda: False)())
