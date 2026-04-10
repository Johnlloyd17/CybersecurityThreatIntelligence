"""Request/response schemas for the CTI service shell."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..cti_engine.context import ScanRequest
from ..cti_engine.settings import SettingsSnapshot
from ..cti_engine.targets import normalize_target


@dataclass(slots=True)
class CreateScanRequest:
    scan_id: int
    user_id: int
    scan_name: str
    query_type: str
    query_value: str
    selected_modules: list[str]
    global_settings: dict[str, Any]
    module_settings: dict[str, dict[str, Any]]
    api_configs_snapshot: dict[str, dict[str, Any]]

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "CreateScanRequest":
        return cls(
            scan_id=int(payload.get("scan_id", 0) or 0),
            user_id=int(payload.get("user_id", 0) or 0),
            scan_name=str(payload.get("scan_name", "CTI Engine Scan") or "CTI Engine Scan"),
            query_type=str(payload.get("query_type", "") or ""),
            query_value=str(payload.get("query_value", "") or ""),
            selected_modules=[
                str(item).strip().lower()
                for item in (payload.get("selected_modules") or payload.get("apis") or [])
                if str(item).strip()
            ],
            global_settings=dict(payload.get("global_settings") or {}),
            module_settings=dict(payload.get("module_settings") or {}),
            api_configs_snapshot=dict(payload.get("api_configs_snapshot") or {}),
        )

    def to_engine_request(self) -> ScanRequest:
        target = normalize_target(self.query_value, self.query_type or None)
        settings = SettingsSnapshot(
            global_settings=self.global_settings,
            module_settings=self.module_settings,
            api_configs_snapshot=self.api_configs_snapshot,
        )
        return ScanRequest(
            scan_id=self.scan_id,
            user_id=self.user_id,
            scan_name=self.scan_name,
            target=target,
            selected_modules=list(self.selected_modules),
            settings=settings,
        )

