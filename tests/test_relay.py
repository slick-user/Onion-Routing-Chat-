from __future__ import annotations

import asyncio
import json

from config.settings import settings
from crypto.keys import generate_keypair, import_private_key
from crypto.onion import build_onion, peel_layer, seal_layer
from networking.transport import TransportError
from observability.events import EventType
from relay.node import create_relay_app
from relay.registry import PeerRegistry
from relay.router import RelayRole
from storage.database import Database
from tests.helpers import RELAY_BASE_URLS, RELAY_IDS, RECEIVER_BASE_URL, RECEIVER_ID, apost, aget

MESSAGE = "Hello Bob! This is an OnionChat test."
REGISTRY = PeerRegistry(
    relay_urls=dict(RELAY_BASE_URLS),
    receiver_urls={RECEIVER_ID: RECEIVER_BASE_URL},
)


class RecordingForwarder:
    def __init__(self, response=None, error=None):
        self.calls = []
        self.response = response or {"status": "forwarded"}
        self.error = error

    async def post_json(self, url, payload):
        self.calls.append((url, payload))
        if self.error is not None:
            raise self.error
        return self.response


def _onion(key_material, *, path=None, receiver_id=RECEIVER_ID):
    _, public_keys = key_material
    return build_onion(
        message=MESSAGE,
        receiver_id=receiver_id,
        receiver_key_id=settings.receiver_key_id,
        receiver_public_key=public_keys[RECEIVER_ID],
        relay_path=path or list(RELAY_IDS),
        relay_public_keys={relay_id: public_keys[relay_id] for relay_id in RELAY_IDS},
        relay_key_ids={relay_id: settings.relay_key_ids[relay_id] for relay_id in RELAY_IDS},
    )


def _make_app(key_material, tmp_path, forwarder, *, relay_id="relay-a", role=RelayRole.ENTRY, registry=REGISTRY):
    private_keys, _ = key_material
    db = Database(tmp_path / f"{relay_id}.db")
    app = create_relay_app(
        relay_id=relay_id,
        role=role,
        private_key=private_keys[relay_id],
        key_id=settings.relay_key_ids[relay_id],
        registry=registry,
        db=db,
        forwarder=forwarder,
    )
    return app, db


def test_relay_forwards_one_layer(key_material, tmp_path):
    forwarder = RecordingForwarder()
    app, db = _make_app(key_material, tmp_path, forwarder)
    envelope = _onion(key_material)

    response = asyncio.run(apost(app, "/relay", envelope))
    assert response.status_code == 200
    assert response.json()["status"] == "forwarded"

    assert len(forwarder.calls) == 1
    url, payload = forwarder.calls[0]
    assert url == "http://relay-b.internal/relay"
    assert payload["recipient_key_id"] == settings.relay_key_ids["relay-b"]
    assert MESSAGE not in json.dumps(payload)

    event_types = {event["event_type"] for event in db.recent_events(service_id="relay-a")}
    assert EventType.PACKET_RECEIVED.value in event_types
    assert EventType.VALIDATION_SUCCESS.value in event_types
    assert EventType.DECRYPTION_SUCCESS.value in event_types
    assert EventType.PACKET_FORWARDED.value in event_types


def test_replayed_packet_is_rejected(key_material, tmp_path):
    forwarder = RecordingForwarder()
    app, db = _make_app(key_material, tmp_path, forwarder)
    envelope = _onion(key_material)

    first = asyncio.run(apost(app, "/relay", envelope))
    second = asyncio.run(apost(app, "/relay", envelope))

    assert first.status_code == 200
    assert second.status_code == 409
    assert len(forwarder.calls) == 1
    assert db.replay_count(relay_id="relay-a") == 1
    assert db.count_events(service_id="relay-a", event_type=EventType.REPLAY_DETECTED.value) == 1


def test_wrong_recipient_key_id_is_rejected(key_material, tmp_path):
    forwarder = RecordingForwarder()
    app, db = _make_app(key_material, tmp_path, forwarder)
    envelope = dict(_onion(key_material))
    envelope["recipient_key_id"] = settings.relay_key_ids["relay-b"]

    response = asyncio.run(apost(app, "/relay", envelope))
    assert response.status_code == 400
    assert forwarder.calls == []
    assert db.count_events(service_id="relay-a", event_type=EventType.VALIDATION_FAILURE.value) == 1


def test_tampered_packet_is_rejected_without_forwarding(key_material, tmp_path):
    forwarder = RecordingForwarder()
    app, db = _make_app(key_material, tmp_path, forwarder)
    envelope = dict(_onion(key_material))
    envelope["ciphertext"] = envelope["ciphertext"][:-4] + "AAAA"

    response = asyncio.run(apost(app, "/relay", envelope))
    assert response.status_code == 400
    assert forwarder.calls == []
    assert db.count_events(service_id="relay-a", event_type=EventType.AUTHENTICATION_FAILURE.value) == 1


def test_unknown_next_hop_is_rejected(key_material, tmp_path):
    rogue_private = import_private_key(generate_keypair(2048)["private_key"])
    _, public_keys = key_material
    expanded_public = {**public_keys, "relay-rogue": rogue_private.publickey()}
    expanded_ids = {**settings.relay_key_ids, "relay-rogue": "relay-rogue-key"}

    envelope = build_onion(
        message=MESSAGE,
        receiver_id=RECEIVER_ID,
        receiver_key_id=settings.receiver_key_id,
        receiver_public_key=public_keys[RECEIVER_ID],
        relay_path=["relay-a", "relay-rogue"],
        relay_public_keys=expanded_public,
        relay_key_ids=expanded_ids,
    )

    forwarder = RecordingForwarder()
    app, db = _make_app(key_material, tmp_path, forwarder)
    response = asyncio.run(apost(app, "/relay", envelope))

    assert response.status_code == 400
    assert forwarder.calls == []
    events = db.recent_events(service_id="relay-a")
    assert any(event["error_category"] == "unknown_peer" for event in events)


def test_non_exit_relay_rejects_exit_instruction(key_material, tmp_path):
    forwarder = RecordingForwarder()
    app, db = _make_app(key_material, tmp_path, forwarder)
    envelope = _onion(key_material, path=["relay-a"])

    response = asyncio.run(apost(app, "/relay", envelope))
    assert response.status_code == 400
    assert forwarder.calls == []
    assert db.count_events(service_id="relay-a", event_type=EventType.VALIDATION_FAILURE.value) == 1


def test_exit_relay_rejects_unknown_receiver(key_material, tmp_path):
    forwarder = RecordingForwarder(response={"status": "delivered"})
    app, db = _make_app(
        key_material,
        tmp_path,
        forwarder,
        relay_id="relay-c",
        role=RelayRole.EXIT,
    )
    # Entry/middle are peeled here so Relay C receives its own outer layer.
    private_keys, _ = key_material
    envelope_unknown = _onion(key_material, receiver_id="mallory")
    instruction_a = peel_layer(envelope_unknown, private_keys["relay-a"], settings.relay_key_ids["relay-a"])
    instruction_b = peel_layer(
        instruction_a["envelope"], private_keys["relay-b"], settings.relay_key_ids["relay-b"]
    )

    response = asyncio.run(apost(app, "/relay", instruction_b["envelope"]))
    assert response.status_code == 400
    assert forwarder.calls == []
    events = db.recent_events(service_id="relay-c")
    assert any(event["error_category"] == "unknown_peer" for event in events)


def test_forwarding_failure_is_reported_and_recorded(key_material, tmp_path):
    forwarder = RecordingForwarder(error=TransportError("down"))
    app, db = _make_app(key_material, tmp_path, forwarder)
    envelope = _onion(key_material)

    response = asyncio.run(apost(app, "/relay", envelope))
    assert response.status_code == 502
    assert db.count_events(service_id="relay-a", event_type=EventType.DELIVERY_FAILURE.value) == 1
    assert db.count_events(service_id="relay-a", event_type=EventType.PACKET_FORWARDED.value) == 0


def test_status_reports_operational_counts(key_material, tmp_path):
    forwarder = RecordingForwarder()
    app, db = _make_app(key_material, tmp_path, forwarder)
    asyncio.run(apost(app, "/relay", _onion(key_material)))

    response = asyncio.run(aget(app, "/status"))
    assert response.status_code == 200
    body = response.json()
    assert body["service_id"] == "relay-a"
    assert body["packets_received"] == 1
    assert body["packets_forwarded"] == 1
    assert body["packets_failed"] == 0
    assert body["replays_detected"] == 0


def test_oversized_packet_is_rejected(key_material, tmp_path):
    forwarder = RecordingForwarder()
    app, _ = _make_app(key_material, tmp_path, forwarder)
    envelope = dict(_onion(key_material))
    envelope["ciphertext"] = "A" * (settings.max_packet_bytes + 1000)

    response = asyncio.run(apost(app, "/relay", envelope))
    assert response.status_code == 413
    assert forwarder.calls == []


def test_malformed_packet_is_rejected(key_material, tmp_path):
    forwarder = RecordingForwarder()
    app, _ = _make_app(key_material, tmp_path, forwarder)
    envelope = dict(_onion(key_material))
    envelope["nonce"] = "not-valid-base64!!!"

    response = asyncio.run(apost(app, "/relay", envelope))
    assert response.status_code in {400, 422}
    assert forwarder.calls == []


def test_packet_supplied_url_is_not_forwarded(key_material, tmp_path):
    _, public_keys = key_material
    inner_envelope = _onion(key_material, path=["relay-b", "relay-c"])
    malicious_layer = seal_layer(
        {
            "next_hop_id": "http://attacker.example/steal",
            "envelope": inner_envelope,
        },
        recipient_key_id=settings.relay_key_ids["relay-a"],
        public_key=public_keys["relay-a"],
    )

    forwarder = RecordingForwarder()
    app, db = _make_app(key_material, tmp_path, forwarder)
    response = asyncio.run(apost(app, "/relay", malicious_layer))

    assert response.status_code == 400
    assert forwarder.calls == []
    assert any(
        event["error_category"] == "unknown_peer"
        for event in db.recent_events(service_id="relay-a")
    )


def test_replay_state_survives_relay_restart(key_material, tmp_path):
    forwarder = RecordingForwarder()
    first_app, _ = _make_app(key_material, tmp_path, forwarder)
    envelope = _onion(key_material)

    first = asyncio.run(apost(first_app, "/relay", envelope))
    assert first.status_code == 200

    # Simulate a process restart with the same on-disk relay database.
    private_keys, _ = key_material
    restarted_app = create_relay_app(
        relay_id="relay-a",
        role=RelayRole.ENTRY,
        private_key=private_keys["relay-a"],
        key_id=settings.relay_key_ids["relay-a"],
        registry=REGISTRY,
        db=Database(tmp_path / "relay-a.db"),
        forwarder=forwarder,
    )
    second = asyncio.run(apost(restarted_app, "/relay", envelope))

    assert second.status_code == 409
    assert len(forwarder.calls) == 1
