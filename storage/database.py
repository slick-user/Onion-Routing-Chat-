"""SQLite persistence for messages, operational events and replay state."""

from __future__ import annotations

import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    """Small SQLite wrapper.

    A fresh connection is opened per operation, which keeps the wrapper safe
    for FastAPI's threadpool without sharing a connection across threads.
    WAL mode and a busy timeout make short concurrent writes reliable.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        if not self.path.exists():
            fd = os.open(self.path, os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        self._secure_files()
        self._initialize()

    def _secure_files(self) -> None:
        """Keep the database and SQLite WAL/SHM sidecars owner-only."""
        for suffix in ("", "-wal", "-shm"):
            candidate = Path(f"{self.path}{suffix}")
            if candidate.exists():
                try:
                    os.chmod(candidate, 0o600)
                except OSError:
                    pass

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=10000")
        self._secure_files()
        return connection

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()
            self._secure_files()

    def _initialize(self) -> None:
        with self._session() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    service_id TEXT NOT NULL,
                    service_type TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    duration_ms REAL,
                    error_category TEXT,
                    detail TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_events_service_time
                    ON events (service_id, timestamp);

                CREATE INDEX IF NOT EXISTS idx_events_type
                    ON events (event_type);

                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    receiver_id TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    sender_hint TEXT,
                    message TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_messages_receiver_time
                    ON messages (receiver_id, received_at);

                CREATE TABLE IF NOT EXISTS replay_cache (
                    relay_id TEXT NOT NULL,
                    packet_digest TEXT NOT NULL,
                    first_seen REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (relay_id, packet_digest)
                );

                CREATE INDEX IF NOT EXISTS idx_replay_expiry
                    ON replay_cache (expires_at);
                """
            )

    # ------------------------------------------------------------------
    # Events / observability
    # ------------------------------------------------------------------
    def insert_event(
        self,
        *,
        service_id: str,
        service_type: str,
        event_type: str,
        status: str,
        duration_ms: float | None = None,
        error_category: str | None = None,
        detail: str | None = None,
    ) -> str:
        event_id = str(uuid.uuid4())
        with self._session() as connection:
            connection.execute(
                """
                INSERT INTO events (
                    event_id, timestamp, service_id, service_type, event_type,
                    status, duration_ms, error_category, detail
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    utc_now_iso(),
                    service_id,
                    service_type,
                    event_type,
                    status,
                    duration_ms,
                    error_category,
                    detail,
                ),
            )
        return event_id

    def recent_events(
        self,
        *,
        service_id: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM events"
        params: list[Any] = []
        if service_id is not None:
            query += " WHERE service_id = ?"
            params.append(service_id)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(max(1, min(limit, 500)))
        with self._session() as connection:
            rows = connection.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def count_events(
        self,
        *,
        service_id: str,
        event_type: str | None = None,
        status: str | None = None,
    ) -> int:
        query = "SELECT COUNT(*) AS total FROM events WHERE service_id = ?"
        params: list[Any] = [service_id]
        if event_type is not None:
            query += " AND event_type = ?"
            params.append(event_type)
        if status is not None:
            query += " AND status = ?"
            params.append(status)
        with self._session() as connection:
            row = connection.execute(query, params).fetchone()
        return int(row["total"]) if row else 0

    # ------------------------------------------------------------------
    # Receiver messages
    # ------------------------------------------------------------------
    def insert_message(
        self,
        *,
        receiver_id: str,
        message: str,
        sender_hint: str | None = None,
    ) -> int:
        with self._session() as connection:
            cursor = connection.execute(
                """
                INSERT INTO messages (receiver_id, received_at, sender_hint, message)
                VALUES (?, ?, ?, ?)
                """,
                (receiver_id, utc_now_iso(), sender_hint, message),
            )
            return int(cursor.lastrowid)

    def latest_message(self, *, receiver_id: str | None = None) -> dict[str, Any] | None:
        query = "SELECT * FROM messages"
        params: list[Any] = []
        if receiver_id is not None:
            query += " WHERE receiver_id = ?"
            params.append(receiver_id)
        query += " ORDER BY id DESC LIMIT 1"
        with self._session() as connection:
            row = connection.execute(query, params).fetchone()
        return dict(row) if row else None

    def count_messages(self, *, receiver_id: str | None = None) -> int:
        query = "SELECT COUNT(*) AS total FROM messages"
        params: list[Any] = []
        if receiver_id is not None:
            query += " WHERE receiver_id = ?"
            params.append(receiver_id)
        with self._session() as connection:
            row = connection.execute(query, params).fetchone()
        return int(row["total"]) if row else 0

    # ------------------------------------------------------------------
    # Replay protection
    # ------------------------------------------------------------------
    def purge_expired_replays(self, *, now: float | None = None) -> int:
        current = time.time() if now is None else now
        with self._session() as connection:
            cursor = connection.execute(
                "DELETE FROM replay_cache WHERE expires_at <= ?",
                (current,),
            )
            return cursor.rowcount

    def replay_exists(self, *, relay_id: str, packet_digest: str, now: float | None = None) -> bool:
        current = time.time() if now is None else now
        with self._session() as connection:
            row = connection.execute(
                """
                SELECT 1 FROM replay_cache
                WHERE relay_id = ? AND packet_digest = ? AND expires_at > ?
                """,
                (relay_id, packet_digest, current),
            ).fetchone()
        return row is not None

    def record_replay(
        self,
        *,
        relay_id: str,
        packet_digest: str,
        ttl_seconds: int,
        now: float | None = None,
    ) -> bool:
        """Persist an accepted packet digest.

        Returns ``False`` when the digest already exists (a duplicate), making
        the operation safe against concurrent submissions.
        """
        current = time.time() if now is None else now
        self.purge_expired_replays(now=current)
        with self._session() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO replay_cache
                    (relay_id, packet_digest, first_seen, expires_at)
                VALUES (?, ?, ?, ?)
                """,
                (relay_id, packet_digest, current, current + ttl_seconds),
            )
            return cursor.rowcount == 1

    def replay_count(self, *, relay_id: str) -> int:
        with self._session() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS total FROM replay_cache WHERE relay_id = ?",
                (relay_id,),
            ).fetchone()
        return int(row["total"]) if row else 0

    def iter_events(self, *, service_id: str | None = None) -> Iterable[dict[str, Any]]:
        yield from self.recent_events(service_id=service_id, limit=500)
