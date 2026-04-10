"""Settings snapshot helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class SettingsSnapshot:
    global_settings: dict[str, Any] = field(default_factory=dict)
    module_settings: dict[str, dict[str, Any]] = field(default_factory=dict)
    api_configs_snapshot: dict[str, dict[str, Any]] = field(default_factory=dict)

    def module_settings_for(self, slug: str) -> dict[str, Any]:
        return dict(self.module_settings.get(str(slug).strip().lower(), {}))

    def api_config_for(self, slug: str) -> dict[str, Any]:
        return dict(self.api_configs_snapshot.get(str(slug).strip().lower(), {}))

