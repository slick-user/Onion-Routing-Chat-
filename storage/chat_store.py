"""SQLite storage for chat users and their mailboxes.

Only public data is stored about users; mailbox tokens are saved as SHA-256
hashes. Mailboxes hold encrypted messages the server cannot read.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

MAX_USERS = 200
MAX_MESSAGES_PER_USER = 200


class ChatStoreError(Exception):
    """Base class for chat storage errors."""


class DirectoryFullError(ChatStoreError):
    """The demo directory reached its user limit."""


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class ChatStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._session() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id        TEXT PRIMARY KEY,
                    name           TEXT NOT NULL,
                    key_id         TEXT NOT NULL UNIQUE,
                    public_key_pem TEXT NOT NULL,
                    token_hash     TEXT NOT NULL,
                    created_at     REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS mailbox (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id     TEXT NOT NULL,
                    envelope    TEXT NOT NULL,
                    received_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS mailbox_user ON mailbox(user_id, id);
                """
            )

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            connection = sqlite3.connect(self.path)
            connection.row_factory = sqlite3.Row
            try:
                yield connection
                connection.commit()
            finally:
                connection.close()

    # Directory
    def register(self, *, name: str, key_id: str, public_key_pem: str, user_id: str) -> str:
        """Add a user. Returns the secret mailbox token (shown to the user once)."""
        token = secrets.token_urlsafe(32)
        with self._session() as db:
            count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if count >= MAX_USERS:
                raise DirectoryFullError("directory is full")
            db.execute(
                "INSERT INTO users (user_id, name, key_id, public_key_pem, token_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, name, key_id, public_key_pem, hash_token(token), time.time()),
            )
        return token

    def users(self) -> list[dict[str, Any]]:
        with self._session() as db:
            rows = db.execute(
                "SELECT user_id, name, key_id, public_key_pem, created_at FROM users ORDER BY created_at"
            ).fetchall()
        return [dict(row) for row in rows]

    def user_by_key_id(self, key_id: str) -> dict[str, Any] | None:
        with self._session() as db:
            row = db.execute("SELECT user_id, name, key_id FROM users WHERE key_id = ?", (key_id,)).fetchone()
        return dict(row) if row else None

    def authenticate(self, user_id: str, token: str) -> bool:
        """Check a mailbox token in constant time (no timing side channel)."""
        with self._session() as db:
            row = db.execute("SELECT token_hash FROM users WHERE user_id = ?", (user_id,)).fetchone()
        expected = row["token_hash"] if row else hash_token(secrets.token_urlsafe(32))
        # compare_digest takes the same time whether the first or last
        # character differs, so an attacker cannot guess the token byte by byte.
        return hmac.compare_digest(expected, hash_token(token)) and row is not None

    # Mailbox
    def store(self, *, user_id: str, envelope: dict[str, Any]) -> dict[str, Any]:
        received_at = time.time()
        with self._session() as db:
            cursor = db.execute(
                "INSERT INTO mailbox (user_id, envelope, received_at) VALUES (?, ?, ?)",
                (user_id, json.dumps(envelope, sort_keys=True), received_at),
            )
            message_id = cursor.lastrowid
            # Keep each mailbox bounded.
            db.execute(
                "DELETE FROM mailbox WHERE user_id = ? AND id NOT IN "
                "(SELECT id FROM mailbox WHERE user_id = ? ORDER BY id DESC LIMIT ?)",
                (user_id, user_id, MAX_MESSAGES_PER_USER),
            )
        return {"id": message_id, "envelope": envelope, "received_at": received_at}

    def inbox(self, *, user_id: str, after_id: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        with self._session() as db:
            rows = db.execute(
                "SELECT id, envelope, received_at FROM mailbox WHERE user_id = ? AND id > ? ORDER BY id LIMIT ?",
                (user_id, after_id, limit),
            ).fetchall()
        return [
            {"id": row["id"], "envelope": json.loads(row["envelope"]), "received_at": row["received_at"]}
            for row in rows
        ]

    def counts(self) -> dict[str, int]:
        with self._session() as db:
            users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            messages = db.execute("SELECT COUNT(*) FROM mailbox").fetchone()[0]
        return {"users": users, "stored_messages": messages}

    def clear(self) -> None:
        with self._session() as db:
            db.execute("DELETE FROM mailbox")
            db.execute("DELETE FROM users")


__all__ = ["ChatStore", "ChatStoreError", "DirectoryFullError", "MAX_USERS", "hash_token"]
