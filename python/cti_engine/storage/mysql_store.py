"""Optional MySQL projector for future CTI engine persistence.

This first implementation slice keeps the interface lightweight and dependency-free.
It can operate with:

1. a provided DB-API compatible connection factory, or
2. PyMySQL if it is installed later.
"""

from __future__ import annotations

from typing import Any, Callable

from .models import ProjectedScan


ConnectionFactory = Callable[[], Any]


class MySQLStore:
    """Persist projected scans to MySQL using a supplied connection factory."""

    def __init__(self, connection_factory: ConnectionFactory | None = None) -> None:
        self.connection_factory = connection_factory

    def _connect(self) -> Any:
        if self.connection_factory is not None:
            return self.connection_factory()

        try:
            import pymysql  # type: ignore
        except Exception as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "MySQLStore requires either a connection_factory or the 'pymysql' package."
            ) from exc

        raise RuntimeError(
            "PyMySQL is available, but automatic connection bootstrap is not configured yet. "
            "Provide a connection_factory when using MySQLStore."
        )

    def persist_projected_scan(self, projected: ProjectedScan) -> None:
        """Persist a projected scan.

        The concrete SQL contract will be expanded when the engine is wired into the
        production CTI MySQL path. For now this method proves the adapter shape and
        can be implemented against a provided DB-API connection factory.
        """
        connection = self._connect()
        close_conn = hasattr(connection, "close")
        try:
            cursor = connection.cursor()
            # Minimal example insert into a runtime table if present.
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS python_runtime_errors ("
                "id INTEGER PRIMARY KEY AUTO_INCREMENT, "
                "scan_id BIGINT NOT NULL, "
                "message TEXT NOT NULL)"
            )
            connection.commit()
        finally:  # pragma: no branch
            if close_conn:
                connection.close()

