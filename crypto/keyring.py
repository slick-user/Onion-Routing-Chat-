"""Key rings: each service keeps a small history of its RSA keys.

Key states:
  active  - current key, used by senders
  retired - replaced by a rotation, still accepted during the grace period
  expired - grace period over, private key deleted
  revoked - withdrawn immediately (e.g. stolen), private key deleted

The active key keeps the old file names (<service>_private.pem) and the state
is saved in <service>_keyring.json, which never contains key material.
"""

from __future__ import annotations

import json
import os
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from Crypto.PublicKey import RSA

from crypto.keys import (
    DEFAULT_BITS,
    MIN_BITS,
    KeyStoreError,
    _write_atomic,
    export_private_key,
    export_public_key,
    key_fingerprint,
    load_private_key,
    load_public_key,
)

MANIFEST_VERSION = 1
DEFAULT_GRACE_SECONDS = 300
DEFAULT_MAX_RECORDS = 12


class KeyStatus(str, Enum):
    ACTIVE = "active"
    RETIRED = "retired"
    EXPIRED = "expired"
    REVOKED = "revoked"


class KeyRingError(Exception):
    """Base class for key ring failures."""


class UnknownKeyError(KeyRingError):
    """The key identifier was never issued by this service."""


class KeyRevokedError(KeyRingError):
    """The key was explicitly revoked and must never be used again."""


class KeyExpiredError(KeyRingError):
    """The key was rotated out and its grace period has ended."""


@dataclass
class KeyRecord:
    key_id: str
    fingerprint: str
    status: str
    bits: int
    created_at: float
    retired_at: float | None = None
    expires_at: float | None = None
    revoked_at: float | None = None
    reason: str | None = None

    def to_public_dict(self, now: float) -> dict[str, Any]:
        data = asdict(self)
        if self.status == KeyStatus.RETIRED.value and self.expires_at is not None:
            data["grace_remaining_seconds"] = max(0, round(self.expires_at - now))
        else:
            data["grace_remaining_seconds"] = None
        data["accepts_packets"] = self.status in {KeyStatus.ACTIVE.value, KeyStatus.RETIRED.value}
        return data


def make_key_id(service_id: str, public_key: RSA.RsaKey) -> str:
    """Derive a short, unique, non-secret key identifier from the public key."""
    return f"{service_id}-{key_fingerprint(public_key)[:8]}"


def keyring_manifest_path(keys_dir: str | Path, service_id: str) -> Path:
    return Path(keys_dir) / f"{service_id}_keyring.json"


def reset_keyring_files(keys_dir: str | Path, service_id: str) -> None:
    """Remove the manifest and archived keys for a service (used by ``init-keys --force``)."""
    directory = Path(keys_dir)
    for path in directory.glob(f"{service_id}__*.pem"):
        _destroy_file(path)
    manifest = keyring_manifest_path(directory, service_id)
    if manifest.exists():
        manifest.unlink()


def _destroy_file(path: Path) -> None:
    """Overwrite a key file with zeros, then delete it."""
    try:
        size = path.stat().st_size
        with open(path, "r+b") as handle:
            handle.write(b"\x00" * size)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError:
        pass
    try:
        path.unlink()
    except OSError:
        pass


class KeyRing:
    """Thread-safe key ring for one service, persisted to disk or held in memory."""

    def __init__(
        self,
        service_id: str,
        keys_dir: str | Path | None = None,
        *,
        grace_seconds: int = DEFAULT_GRACE_SECONDS,
        max_records: int = DEFAULT_MAX_RECORDS,
        clock: Callable[[], float] = time.time,
    ):
        if grace_seconds < 0:
            raise ValueError("grace period must not be negative")
        self.service_id = service_id
        self.keys_dir = Path(keys_dir) if keys_dir is not None else None
        self.grace_seconds = grace_seconds
        self.max_records = max(2, max_records)
        self._clock = clock
        self._lock = threading.RLock()
        self._records: list[KeyRecord] = []
        self._private: dict[str, RSA.RsaKey] = {}
        self._public: dict[str, RSA.RsaKey] = {}
        self._manifest_mtime: float | None = None

    # Construction
    @classmethod
    def static(cls, service_id: str, key_id: str, private_key: RSA.RsaKey, **kwargs: Any) -> "KeyRing":
        """In-memory ring with a single active key (tests and legacy callers)."""
        ring = cls(service_id, None, **kwargs)
        ring._install_active(key_id, private_key, created_at=ring._clock())
        return ring

    @classmethod
    def open(
        cls,
        service_id: str,
        keys_dir: str | Path,
        *,
        default_key_id: str,
        **kwargs: Any,
    ) -> "KeyRing":
        """Load a key ring from disk, creating its manifest from the old key files if needed."""
        ring = cls(service_id, keys_dir, **kwargs)
        with ring._lock:
            if ring._manifest_path.exists():
                ring._load()
            else:
                ring._bootstrap_from_legacy(default_key_id)
        return ring

    # Paths and persistence
    @property
    def persistent(self) -> bool:
        return self.keys_dir is not None

    @property
    def _manifest_path(self) -> Path:
        assert self.keys_dir is not None
        return keyring_manifest_path(self.keys_dir, self.service_id)

    def _active_private_path(self) -> Path:
        assert self.keys_dir is not None
        return self.keys_dir / f"{self.service_id}_private.pem"

    def _active_public_path(self) -> Path:
        assert self.keys_dir is not None
        return self.keys_dir / f"{self.service_id}_public.pem"

    def _archive_private_path(self, key_id: str) -> Path:
        assert self.keys_dir is not None
        return self.keys_dir / f"{self.service_id}__{key_id}_private.pem"

    def _archive_public_path(self, key_id: str) -> Path:
        assert self.keys_dir is not None
        return self.keys_dir / f"{self.service_id}__{key_id}_public.pem"

    def _bootstrap_from_legacy(self, default_key_id: str) -> None:
        private_path = self._active_private_path()
        if not private_path.exists():
            raise KeyStoreError(f"Missing key file: {private_path.name}")
        private_key = load_private_key(private_path)
        try:
            created_at = private_path.stat().st_mtime
        except OSError:
            created_at = self._clock()
        self._install_active(default_key_id, private_key, created_at=created_at)
        self._save()

    def _load(self) -> None:
        try:
            raw = json.loads(self._manifest_path.read_text(encoding="utf-8"))
            records = [KeyRecord(**entry) for entry in raw["keys"]]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise KeyStoreError(f"Unable to load key ring for {self.service_id}") from exc

        private: dict[str, RSA.RsaKey] = {}
        public: dict[str, RSA.RsaKey] = {}
        for record in records:
            if record.status == KeyStatus.ACTIVE.value:
                key = load_private_key(self._active_private_path())
                if key_fingerprint(key) != record.fingerprint:
                    raise KeyStoreError(f"Active key file does not match the {self.service_id} manifest")
                private[record.key_id] = key
                public[record.key_id] = key.publickey()
                continue
            if record.status == KeyStatus.RETIRED.value:
                archived = self._archive_private_path(record.key_id)
                if archived.exists():
                    key = load_private_key(archived)
                    private[record.key_id] = key
                    public[record.key_id] = key.publickey()
                    continue
                # Private key already destroyed by another process: treat as expired.
                record.status = KeyStatus.EXPIRED.value
            public_path = self._archive_public_path(record.key_id)
            if public_path.exists():
                public[record.key_id] = load_public_key(public_path)

        if sum(1 for record in records if record.status == KeyStatus.ACTIVE.value) != 1:
            raise KeyStoreError(f"Key ring for {self.service_id} must have exactly one active key")

        self._records = records
        self._private = private
        self._public = public
        self._manifest_mtime = self._manifest_path.stat().st_mtime

    def _save(self) -> None:
        if not self.persistent:
            return
        payload = {
            "service_id": self.service_id,
            "version": MANIFEST_VERSION,
            "keys": [asdict(record) for record in self._records],
        }
        data = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        _write_atomic(self._manifest_path, data, 0o644)
        self._manifest_mtime = self._manifest_path.stat().st_mtime

    def refresh(self) -> None:
        """Reload the manifest if another process (e.g. the CLI) changed it."""
        if not self.persistent:
            return
        with self._lock:
            try:
                mtime = self._manifest_path.stat().st_mtime
            except OSError:
                return
            if mtime != self._manifest_mtime:
                self._load()

    # Internal state helpers
    def _find(self, key_id: str) -> KeyRecord | None:
        for record in self._records:
            if record.key_id == key_id:
                return record
        return None

    def _active_record(self) -> KeyRecord:
        for record in self._records:
            if record.status == KeyStatus.ACTIVE.value:
                return record
        raise KeyRingError("key ring has no active key")

    def _install_active(self, key_id: str, private_key: RSA.RsaKey, *, created_at: float) -> KeyRecord:
        record = KeyRecord(
            key_id=key_id,
            fingerprint=key_fingerprint(private_key),
            status=KeyStatus.ACTIVE.value,
            bits=private_key.size_in_bits(),
            created_at=created_at,
        )
        self._records.append(record)
        self._private[key_id] = private_key
        self._public[key_id] = private_key.publickey()
        return record

    def _drop_private(self, record: KeyRecord) -> None:
        self._private.pop(record.key_id, None)
        if self.persistent:
            archived = self._archive_private_path(record.key_id)
            if archived.exists():
                _destroy_file(archived)

    def _expire_due(self) -> bool:
        """Move retired keys whose grace period ended to ``expired``."""
        now = self._clock()
        changed = False
        for record in self._records:
            if (
                record.status == KeyStatus.RETIRED.value
                and record.expires_at is not None
                and record.expires_at <= now
            ):
                record.status = KeyStatus.EXPIRED.value
                self._drop_private(record)
                changed = True
        return changed

    def _prune(self) -> None:
        """Keep the manifest bounded by forgetting the oldest dead keys."""
        while len(self._records) > self.max_records:
            dead = [
                record
                for record in self._records
                if record.status in {KeyStatus.EXPIRED.value, KeyStatus.REVOKED.value}
            ]
            if not dead:
                return
            oldest = min(dead, key=lambda record: record.created_at)
            self._records.remove(oldest)
            self._public.pop(oldest.key_id, None)
            if self.persistent:
                public_path = self._archive_public_path(oldest.key_id)
                if public_path.exists():
                    public_path.unlink()

    def _sync(self) -> None:
        self.refresh()
        if self._expire_due():
            self._save()

    # Public API
    @property
    def active_key_id(self) -> str:
        with self._lock:
            self._sync()
            return self._active_record().key_id

    @property
    def active_public_key(self) -> RSA.RsaKey:
        with self._lock:
            self._sync()
            return self._public[self._active_record().key_id]

    @property
    def active_private_key(self) -> RSA.RsaKey:
        with self._lock:
            self._sync()
            return self._private[self._active_record().key_id]

    def resolve(self, key_id: str) -> RSA.RsaKey:
        """Return the private key for an incoming packet, enforcing key status."""
        with self._lock:
            self._sync()
            record = self._find(key_id)
            if record is None:
                raise UnknownKeyError("unknown key identifier")
            if record.status == KeyStatus.REVOKED.value:
                raise KeyRevokedError("key has been revoked")
            if record.status == KeyStatus.EXPIRED.value:
                raise KeyExpiredError("key grace period has ended")
            return self._private[key_id]

    def status_of(self, key_id: str) -> str | None:
        with self._lock:
            self._sync()
            record = self._find(key_id)
            return record.status if record else None

    def public_key(self, key_id: str) -> RSA.RsaKey:
        """Public key for any issued key (used to demonstrate stale-key rejection)."""
        with self._lock:
            self._sync()
            if key_id not in self._public:
                raise UnknownKeyError("unknown key identifier")
            return self._public[key_id]

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            self._sync()
            now = self._clock()
            return [record.to_public_dict(now) for record in reversed(self._records)]

    def rotate(self, bits: int | None = None) -> KeyRecord:
        """Generate a new active key; the previous one enters its grace period."""
        with self._lock:
            self._sync()
            current = self._active_record()
            size = bits or current.bits or DEFAULT_BITS
            if size < MIN_BITS:
                raise ValueError(f"RSA key size must be at least {MIN_BITS} bits")
            new_key = RSA.generate(size)
            return self._rotate_to(new_key, current)

    def rotate_to(self, private_key: RSA.RsaKey) -> KeyRecord:
        """Rotate to a caller-supplied key (lets the web demo generate keys off the event loop)."""
        with self._lock:
            self._sync()
            return self._rotate_to(private_key, self._active_record())

    def _rotate_to(self, new_key: RSA.RsaKey, current: KeyRecord) -> KeyRecord:
        if not new_key.has_private():
            raise ValueError("rotation requires a private key")
        if new_key.size_in_bits() < MIN_BITS:
            raise ValueError(f"RSA key size must be at least {MIN_BITS} bits")
        new_id = make_key_id(self.service_id, new_key)
        if self._find(new_id) is not None:
            raise KeyRingError("generated key collides with an existing key id")

        now = self._clock()
        old_private = self._private[current.key_id]
        current.retired_at = now
        current.expires_at = now + self.grace_seconds
        current.status = KeyStatus.RETIRED.value

        if self.persistent:
            # Archive the outgoing key first, then replace the active files.
            _write_atomic(self._archive_public_path(current.key_id), export_public_key(old_private), 0o644)
            _write_atomic(self._archive_private_path(current.key_id), export_private_key(old_private), 0o600)
            _write_atomic(self._active_private_path(), export_private_key(new_key), 0o600)
            _write_atomic(self._active_public_path(), export_public_key(new_key), 0o644)

        record = self._install_active(new_id, new_key, created_at=now)
        if self.grace_seconds == 0:
            current.status = KeyStatus.EXPIRED.value
            self._drop_private(current)
        self._prune()
        self._save()
        return record

    def revoke(
        self, key_id: str, reason: str = "manual revocation", *, replacement: RSA.RsaKey | None = None
    ) -> dict[str, Any]:
        """Revoke a key immediately. Revoking the active key rotates in a replacement."""
        with self._lock:
            self._sync()
            record = self._find(key_id)
            if record is None:
                raise UnknownKeyError("unknown key identifier")
            if record.status == KeyStatus.REVOKED.value:
                raise KeyRingError("key is already revoked")

            new_record: KeyRecord | None = None
            if record.status == KeyStatus.ACTIVE.value:
                new_key = replacement or RSA.generate(record.bits or DEFAULT_BITS)
                new_record = self._rotate_to(new_key, record)

            if self.persistent and key_id in self._public and not self._archive_public_path(key_id).exists():
                _write_atomic(
                    self._archive_public_path(key_id), export_public_key(self._public[key_id]), 0o644
                )
            record.status = KeyStatus.REVOKED.value
            record.revoked_at = self._clock()
            record.expires_at = record.revoked_at
            record.reason = (reason or "manual revocation")[:120]
            self._drop_private(record)
            self._save()
            return {
                "revoked": record.to_public_dict(self._clock()),
                "replacement": new_record.to_public_dict(self._clock()) if new_record else None,
            }


__all__ = [
    "DEFAULT_GRACE_SECONDS",
    "KeyExpiredError",
    "KeyRecord",
    "KeyRevokedError",
    "KeyRing",
    "KeyRingError",
    "KeyStatus",
    "UnknownKeyError",
    "keyring_manifest_path",
    "make_key_id",
    "reset_keyring_files",
]
