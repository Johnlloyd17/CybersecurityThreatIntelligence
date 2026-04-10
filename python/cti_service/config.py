"""Service configuration."""

from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(slots=True)
class ServiceConfig:
    host: str = "127.0.0.1"
    port: int = 8765
    max_workers: int = 4

    @classmethod
    def from_env(cls) -> "ServiceConfig":
        return cls(
            host=os.environ.get("CTI_ENGINE_HOST", "127.0.0.1"),
            port=int(os.environ.get("CTI_ENGINE_PORT", "8765")),
            max_workers=int(os.environ.get("CTI_ENGINE_MAX_WORKERS", "4")),
        )

