from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)))
    except ValueError:
        return default


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(_env("ONIONCHAT_DATA_DIR", str(BASE_DIR / "data")))
KEYS_DIR = Path(_env("ONIONCHAT_KEYS_DIR", str(DATA_DIR / "keys")))
DB_DIR = Path(_env("ONIONCHAT_DB_DIR", str(DATA_DIR / "db")))


@dataclass(frozen=True)
class ServiceEndpoint:
    service_id: str
    host: str
    port: int

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


@dataclass
class Settings:
    base_dir: Path = BASE_DIR
    data_dir: Path = DATA_DIR
    keys_dir: Path = KEYS_DIR
    db_dir: Path = DB_DIR

    relay_a: ServiceEndpoint = field(
        default_factory=lambda: ServiceEndpoint(
            "relay-a", _env("RELAY_A_HOST", "127.0.0.1"), _env_int("RELAY_A_PORT", 8001)
        )
    )
    relay_b: ServiceEndpoint = field(
        default_factory=lambda: ServiceEndpoint(
            "relay-b", _env("RELAY_B_HOST", "127.0.0.1"), _env_int("RELAY_B_PORT", 8002)
        )
    )
    relay_c: ServiceEndpoint = field(
        default_factory=lambda: ServiceEndpoint(
            "relay-c", _env("RELAY_C_HOST", "127.0.0.1"), _env_int("RELAY_C_PORT", 8003)
        )
    )
    receiver: ServiceEndpoint = field(
        default_factory=lambda: ServiceEndpoint(
            "receiver-bob", _env("RECEIVER_HOST", "127.0.0.1"), _env_int("RECEIVER_PORT", 9000)
        )
    )

    relay_key_ids: dict[str, str] = field(
        default_factory=lambda: {
            "relay-a": "relay-a-key",
            "relay-b": "relay-b-key",
            "relay-c": "relay-c-key",
        }
    )
    receiver_key_id: str = "receiver-bob-key"

    request_timeout_seconds: float = field(
        default_factory=lambda: _env_float("ONIONCHAT_TIMEOUT_SECONDS", 10.0)
    )
    max_packet_bytes: int = field(default_factory=lambda: _env_int("ONIONCHAT_MAX_PACKET_BYTES", 256 * 1024))
    max_field_chars: int = field(default_factory=lambda: _env_int("ONIONCHAT_MAX_FIELD_CHARS", 200_000))
    replay_ttl_seconds: int = field(default_factory=lambda: _env_int("ONIONCHAT_REPLAY_TTL_SECONDS", 300))
    db_path: Path = field(default_factory=lambda: DB_DIR / "onionchat.db")
    # Key lifecycle: how long a rotated-out key is still accepted, and the
    # minimum gap between rotations/revocations triggered from the web demo.
    key_grace_seconds: int = field(default_factory=lambda: _env_int("ONIONCHAT_KEY_GRACE_SECONDS", 120))
    key_action_cooldown_seconds: float = field(
        default_factory=lambda: _env_float("ONIONCHAT_KEY_COOLDOWN_SECONDS", 2.0)
    )

    def ensure_dirs(self) -> None:
        self.keys_dir.mkdir(parents=True, exist_ok=True)
        self.db_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.keys_dir, 0o700)
            os.chmod(self.db_dir, 0o700)
        except OSError:
            pass

    def relay_endpoint(self, relay_id: str) -> ServiceEndpoint:
        mapping = {
            "relay-a": self.relay_a,
            "relay-b": self.relay_b,
            "relay-c": self.relay_c,
        }
        if relay_id not in mapping:
            raise KeyError(f"Unknown relay id: {relay_id}")
        return mapping[relay_id]

    def relay_role(self, relay_id: str) -> str:
        mapping = {"relay-a": "entry", "relay-b": "middle", "relay-c": "exit"}
        if relay_id not in mapping:
            raise KeyError(f"Unknown relay id: {relay_id}")
        return mapping[relay_id]

    def default_key_id(self, service_id: str) -> str:
        """Key identifier used for the very first (pre-rotation) key of a service."""
        if service_id == self.receiver.service_id:
            return self.receiver_key_id
        if service_id in self.relay_key_ids:
            return self.relay_key_ids[service_id]
        raise KeyError(f"Unknown service id: {service_id}")

    def database_path(self, service_id: str) -> Path:
        return self.db_dir / f"{service_id}.db"

    def private_key_path(self, service_id: str) -> Path:
        return self.keys_dir / f"{service_id}_private.pem"

    def public_key_path(self, service_id: str) -> Path:
        return self.keys_dir / f"{service_id}_public.pem"


settings = Settings()
settings.ensure_dirs()
