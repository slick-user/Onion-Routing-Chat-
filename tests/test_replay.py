from __future__ import annotations

from storage.database import Database


def test_replay_record_and_detect(tmp_path):
    db = Database(tmp_path / "relay.db")
    assert db.record_replay(relay_id="relay-a", packet_digest="abc", ttl_seconds=300) is True
    assert db.replay_exists(relay_id="relay-a", packet_digest="abc") is True
    assert db.record_replay(relay_id="relay-a", packet_digest="abc", ttl_seconds=300) is False


def test_replay_state_is_relay_scoped(tmp_path):
    db = Database(tmp_path / "relay.db")
    db.record_replay(relay_id="relay-a", packet_digest="abc", ttl_seconds=300)

    assert db.replay_exists(relay_id="relay-a", packet_digest="abc") is True
    assert db.replay_exists(relay_id="relay-b", packet_digest="abc") is False


def test_replay_persists_across_database_instances(tmp_path):
    path = tmp_path / "relay.db"
    first = Database(path)
    first.record_replay(relay_id="relay-a", packet_digest="persisted", ttl_seconds=300)

    second = Database(path)
    assert second.replay_exists(relay_id="relay-a", packet_digest="persisted") is True
    assert second.replay_count(relay_id="relay-a") == 1


def test_replay_entries_expire(tmp_path):
    db = Database(tmp_path / "relay.db")
    now = 1_000_000.0
    db.record_replay(relay_id="relay-a", packet_digest="expiring", ttl_seconds=10, now=now)

    assert db.replay_exists(relay_id="relay-a", packet_digest="expiring", now=now + 5) is True
    assert db.replay_exists(relay_id="relay-a", packet_digest="expiring", now=now + 11) is False

    removed = db.purge_expired_replays(now=now + 11)
    assert removed == 1
    assert db.replay_count(relay_id="relay-a") == 0


def test_expired_digest_can_be_reused(tmp_path):
    db = Database(tmp_path / "relay.db")
    now = 1_000_000.0
    db.record_replay(relay_id="relay-a", packet_digest="reuse", ttl_seconds=10, now=now)

    assert (
        db.record_replay(
            relay_id="relay-a",
            packet_digest="reuse",
            ttl_seconds=10,
            now=now + 20,
        )
        is True
    )
