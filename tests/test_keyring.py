"""Key lifecycle: rotation, grace period, expiry, revocation and persistence."""

from __future__ import annotations

import asyncio
import json
import os

import httpx
import pytest
from Crypto.PublicKey import RSA

from crypto.keyring import (
    KeyExpiredError,
    KeyRevokedError,
    KeyRing,
    KeyRingError,
    KeyStatus,
    UnknownKeyError,
    keyring_manifest_path,
)
from crypto.keys import generate_service_keys
from web.app import create_web_app
from web.runtime import WebRuntime

BITS = 2048


class FakeClock:
    def __init__(self, start: float = 1_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture(scope="module")
def spare_keys():
    """Pre-generated keys so tests do not pay for RSA generation repeatedly."""
    return [RSA.generate(BITS) for _ in range(4)]


@pytest.fixture()
def disk_ring(tmp_path, spare_keys):
    generate_service_keys(tmp_path, {"relay-x": "relay-x-key"}, bits=BITS)
    clock = FakeClock()
    ring = KeyRing.open("relay-x", tmp_path, default_key_id="relay-x-key", grace_seconds=60, clock=clock)
    return ring, clock, tmp_path


# Unit behaviour
def test_bootstrap_keeps_legacy_key_id(disk_ring):
    ring, _, keys_dir = disk_ring
    assert ring.active_key_id == "relay-x-key"
    manifest = json.loads(keyring_manifest_path(keys_dir, "relay-x").read_text())
    assert [entry["status"] for entry in manifest["keys"]] == ["active"]
    # The manifest never contains key material.
    assert "PRIVATE" not in keyring_manifest_path(keys_dir, "relay-x").read_text()


def test_rotation_keeps_old_key_during_grace_then_expires(disk_ring, spare_keys):
    ring, clock, keys_dir = disk_ring
    old_private = ring.resolve("relay-x-key")

    record = ring.rotate_to(spare_keys[0])
    assert ring.active_key_id == record.key_id != "relay-x-key"
    assert ring.status_of("relay-x-key") == KeyStatus.RETIRED.value
    # In-flight packets for the old key are still accepted inside the grace window.
    assert ring.resolve("relay-x-key").n == old_private.n
    assert (keys_dir / "relay-x__relay-x-key_private.pem").exists()

    clock.advance(61)
    with pytest.raises(KeyExpiredError):
        ring.resolve("relay-x-key")
    assert ring.status_of("relay-x-key") == KeyStatus.EXPIRED.value
    # The old private key is destroyed once the grace period ends.
    assert not (keys_dir / "relay-x__relay-x-key_private.pem").exists()
    assert (keys_dir / "relay-x__relay-x-key_public.pem").exists()


def test_revoking_active_key_rotates_and_destroys_private_key(disk_ring, spare_keys):
    ring, _, keys_dir = disk_ring
    result = ring.revoke("relay-x-key", reason="laptop stolen", replacement=spare_keys[1])

    assert result["revoked"]["status"] == "revoked"
    assert result["revoked"]["reason"] == "laptop stolen"
    assert result["replacement"]["key_id"] == ring.active_key_id
    with pytest.raises(KeyRevokedError):
        ring.resolve("relay-x-key")
    assert not (keys_dir / "relay-x__relay-x-key_private.pem").exists()
    # The new active key works.
    assert ring.resolve(ring.active_key_id).n == spare_keys[1].n


def test_revoking_retired_key_ends_grace_immediately(disk_ring, spare_keys):
    ring, _, _ = disk_ring
    ring.rotate_to(spare_keys[2])
    assert ring.resolve("relay-x-key") is not None
    result = ring.revoke("relay-x-key", reason="compromised")
    assert result["replacement"] is None
    with pytest.raises(KeyRevokedError):
        ring.resolve("relay-x-key")
    with pytest.raises(KeyRingError):
        ring.revoke("relay-x-key")


def test_unknown_key_is_rejected(disk_ring):
    ring, _, _ = disk_ring
    with pytest.raises(UnknownKeyError):
        ring.resolve("relay-x-deadbeef")


def test_other_process_sees_rotation(disk_ring, spare_keys):
    ring, clock, keys_dir = disk_ring
    other = KeyRing.open("relay-x", keys_dir, default_key_id="relay-x-key", grace_seconds=60, clock=clock)
    record = ring.rotate_to(spare_keys[3])
    # Force a different mtime even on coarse-grained file systems.
    manifest = keyring_manifest_path(keys_dir, "relay-x")
    stat = manifest.stat()
    os.utime(manifest, (stat.st_atime, stat.st_mtime + 5))
    assert other.active_key_id == record.key_id


def test_static_ring_behaves_like_single_key(spare_keys):
    ring = KeyRing.static("relay-y", "relay-y-key", spare_keys[0])
    assert ring.active_key_id == "relay-y-key"
    assert ring.resolve("relay-y-key").n == spare_keys[0].n
    with pytest.raises(UnknownKeyError):
        ring.resolve("relay-z-key")


def test_private_key_files_stay_0600(disk_ring, spare_keys):
    ring, _, keys_dir = disk_ring
    ring.rotate_to(spare_keys[0])
    for path in keys_dir.glob("*_private.pem"):
        assert path.stat().st_mode & 0o777 == 0o600


# Through the real relays (web API)
@pytest.fixture()
def lifecycle_app(tmp_path, monkeypatch):
    from config.settings import settings

    monkeypatch.setattr(settings, "key_action_cooldown_seconds", 0.0)
    runtime = WebRuntime.build(keys_dir=tmp_path / "keys", db_dir=tmp_path / "db", key_bits=BITS)
    return create_web_app(runtime), runtime


def call(app, method, path, payload=None):
    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://web.test") as client:
            return await client.request(method, path, json=payload)

    return asyncio.run(run())


def test_api_rotate_then_probe_old_key_is_accepted_in_grace(lifecycle_app):
    app, _ = lifecycle_app
    before = call(app, "GET", "/api/keys").json()
    old_key = next(s for s in before["services"] if s["service_id"] == "relay-b")["active_key_id"]

    rotated = call(app, "POST", "/api/keys/rotate", {"service_id": "relay-b"})
    assert rotated.status_code == 200
    assert rotated.json()["active"]["key_id"] != old_key

    # Normal sends use the new key automatically.
    sent = call(app, "POST", "/api/send", {"message": "after rotation"})
    assert sent.status_code == 200
    assert sent.json()["message_id"] is not None

    probe = call(app, "POST", "/api/keys/probe", {"service_id": "relay-b", "key_id": old_key})
    body = probe.json()
    assert body["key_status"] == "retired"
    assert body["delivered"] is True
    decrypted = [
        e for e in body["trace"] if e.get("service_id") == "relay-b" and e.get("stage") == "decrypted"
    ]
    assert decrypted and decrypted[0]["key_status"] == "retired"


def test_api_revoked_key_is_rejected_at_its_hop(lifecycle_app):
    app, _ = lifecycle_app
    old_key = call(app, "GET", "/api/keys").json()["services"][1]["active_key_id"]
    revoked = call(
        app, "POST", "/api/keys/revoke", {"service_id": "relay-b", "key_id": old_key, "reason": "stolen"}
    )
    assert revoked.status_code == 200
    assert revoked.json()["replacement"] is not None

    probe = call(app, "POST", "/api/keys/probe", {"service_id": "relay-b", "key_id": old_key}).json()
    assert probe["delivered"] is False
    assert probe["rejected_by"] == "relay-b"
    assert probe["error_category"] == "key_revoked"

    # The circuit keeps working with the replacement key.
    assert call(app, "POST", "/api/send", {"message": "still works"}).status_code == 200

    again = call(app, "POST", "/api/keys/revoke", {"service_id": "relay-b", "key_id": old_key})
    assert again.status_code == 409


def test_api_revoked_receiver_key_is_rejected_by_bob(lifecycle_app):
    app, _ = lifecycle_app
    bob = call(app, "GET", "/api/keys").json()["services"][3]
    call(app, "POST", "/api/keys/revoke", {"service_id": bob["service_id"], "key_id": bob["active_key_id"]})
    probe = call(
        app, "POST", "/api/keys/probe", {"service_id": bob["service_id"], "key_id": bob["active_key_id"]}
    ).json()
    assert probe["delivered"] is False
    assert probe["rejected_by"] == bob["service_id"]
    assert probe["error_category"] == "key_revoked"


def test_api_validates_input_and_rate_limits(lifecycle_app, monkeypatch):
    app, _ = lifecycle_app
    assert call(app, "POST", "/api/keys/rotate", {"service_id": "relay-z"}).status_code == 404
    assert call(app, "POST", "/api/keys/rotate", {"service_id": "../etc"}).status_code == 422
    assert (
        call(app, "POST", "/api/keys/probe", {"service_id": "relay-a", "key_id": "relay-a-nope"}).status_code
        == 404
    )

    from config.settings import settings

    monkeypatch.setattr(settings, "key_action_cooldown_seconds", 60.0)
    assert call(app, "POST", "/api/keys/rotate", {"service_id": "relay-a"}).status_code == 200
    assert call(app, "POST", "/api/keys/rotate", {"service_id": "relay-a"}).status_code == 429


def test_api_keys_never_expose_private_material(lifecycle_app):
    app, _ = lifecycle_app
    text = call(app, "GET", "/api/keys").text
    assert "PRIVATE" not in text and "BEGIN" not in text
