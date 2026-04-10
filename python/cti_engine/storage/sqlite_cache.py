"""Small local SQLite cache helper for future module/runtime caching."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


class SQLiteCache:
    def __init__(self, path: str) -> None:
        self.path = str(Path(path))
        self.conn = sqlite3.connect(self.path)
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS kv_cache (cache_key TEXT PRIMARY KEY, cache_value TEXT NOT NULL)"
        )
        self.conn.commit()

    def get(self, key: str) -> str | None:
        row = self.conn.execute(
            "SELECT cache_value FROM kv_cache WHERE cache_key = ? LIMIT 1",
            (key,),
        ).fetchone()
        return None if row is None else str(row[0])

    def set(self, key: str, value: Any) -> None:
        self.conn.execute(
            "INSERT INTO kv_cache (cache_key, cache_value) VALUES (?, ?) "
            "ON CONFLICT(cache_key) DO UPDATE SET cache_value = excluded.cache_value",
            (key, str(value)),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

