"""
Lightweight, zero-dependency local disk cache using standard library sqlite3.
"""

from __future__ import annotations
import sqlite3
import json
import time
from pathlib import Path
from typing import Optional, Any
from vulnhound.enricher import get_cache_dir


class QueryCache:
    """
    SQLite-backed local cache with time-to-live (TTL) expiration.
    """

    def __init__(self, db_filename: str = "query_cache.db", default_ttl: int = 14400):
        self.db_path = get_cache_dir() / db_filename
        self.default_ttl = default_ttl  # 4 hours
        self._init_db()

    def _init_db(self) -> None:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cache (
                        key TEXT PRIMARY KEY,
                        data TEXT NOT NULL,
                        expires_at REAL NOT NULL
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_expires ON cache(expires_at)")
                conn.commit()
        except Exception:
            pass

    def get(self, key: str) -> Optional[Any]:
        try:
            now = time.time()
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT data FROM cache WHERE key = ? AND expires_at > ?",
                    (key, now),
                )
                row = cursor.fetchone()
                if row:
                    return json.loads(row[0])
        except Exception:
            return None
        return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        try:
            ttl_sec = ttl if ttl is not None else self.default_ttl
            expires_at = time.time() + ttl_sec
            raw = json.dumps(value)
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO cache (key, data, expires_at) VALUES (?, ?, ?)",
                    (key, raw, expires_at),
                )
                conn.commit()
        except Exception:
            pass

    def clear(self) -> int:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM cache")
                conn.commit()
                return cursor.rowcount
        except Exception:
            return 0

    def purge_expired(self) -> None:
        try:
            now = time.time()
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM cache WHERE expires_at <= ?", (now,))
                conn.commit()
        except Exception:
            pass
