from __future__ import annotations

import asyncio
import json

from config.settings import settings
from crypto.encryption import CryptoError, decrypt_message_e2e
from crypto.onion import peel_layer
from networking.schemas import SendResult
from observability.events import EventType
from tests.helpers import (
    RECEIVER_ID,
    RELAY_IDS,
    aget,
    apost,
    build_sender,
)

MESSAGE = "Hello Bob! This is an OnionChat test."


def test_end_to_end_delivery_through_three_relays(stack):
    sender = build_sender(stack)
    result = asyncio.run(sender.send(MESSAGE))

    assert result.status == "sent"
    latest = stack["dbs"][RECEIVER_ID].latest_message(receiver_id=RECEIVER_ID)
    assert latest is not None
    assert latest["message"] == MESSAGE

    for relay_id in ("relay-a", "relay-b"):
        assert stack["dbs"][relay_id].count_events(
            service_id=relay_id, event_type=EventType.PACKET_FORWARDED.value
        ) == 1
    assert stack["dbs"]["relay-c"].count_events(
        service_id="relay-c", event_type=EventType.DELIVERY_SUCCESS.value
    ) == 1
    assert stack["dbs"][RECEIVER_ID].count_messages(receiver_id=RECEIVER_ID) == 1


def test_relay_events_never_contain_plaintext_or_packet_data(stack):
    sender = build_sender(stack)
    asyncio.run(sender.send(MESSAGE))

    for service_id, db in stack["dbs"].items():
        for event in db.recent_events(service_id=service_id):
            serialized = json.dumps(event)
            assert MESSAGE not in serialized
            assert "wrapped_key" not in serialized
            assert "ciphertext" not in serialized
            assert "nonce" not in serialized


def test_no_relay_can_decrypt_the_message_plaintext(stack):
    sender = build_sender(stack)
    envelope = sender.build_packet(MESSAGE)
    private_keys = stack["private_keys"]

    instruction_a = peel_layer(envelope, private_keys["relay-a"], settings.relay_key_ids["relay-a"])
    assert MESSAGE not in json.dumps(instruction_a)
    instruction_b = peel_layer(
        instruction_a["envelope"], private_keys["relay-b"], settings.relay_key_ids["relay-b"]
    )
    assert MESSAGE not in json.dumps(instruction_b)
    instruction_c = peel_layer(
        instruction_b["envelope"], private_keys["relay-c"], settings.relay_key_ids["relay-c"]
    )
    assert MESSAGE not in json.dumps(instruction_c)

    for relay_id in RELAY_IDS:
        try:
            decrypt_message_e2e(
                instruction_c["message"],
                private_keys[relay_id],
                settings.receiver_key_id,
            )
        except CryptoError:
            continue
        raise AssertionError(f"{relay_id} was able to decrypt the end-to-end message")


def test_tampered_packet_is_rejected_end_to_end(stack):
    sender = build_sender(stack)
    envelope = sender.build_packet(MESSAGE)
    tampered = dict(envelope)
    tampered["ciphertext"] = tampered["ciphertext"][:-4] + "AAAA"

    response = asyncio.run(apost(stack["apps"]["relay-a"], "/relay", tampered))
    assert response.status_code == 400
    assert stack["dbs"][RECEIVER_ID].count_messages(receiver_id=RECEIVER_ID) == 0
    assert stack["dbs"]["relay-a"].count_events(
        service_id="relay-a", event_type=EventType.AUTHENTICATION_FAILURE.value
    ) == 1


def test_replayed_packet_is_rejected_end_to_end(stack):
    sender = build_sender(stack)
    envelope = sender.build_packet(MESSAGE)

    first = asyncio.run(apost(stack["apps"]["relay-a"], "/relay", envelope))
    second = asyncio.run(apost(stack["apps"]["relay-a"], "/relay", envelope))

    assert first.status_code == 200
    assert second.status_code == 409
    assert stack["dbs"][RECEIVER_ID].count_messages(receiver_id=RECEIVER_ID) == 1
    assert stack["dbs"]["relay-a"].count_events(
        service_id="relay-a", event_type=EventType.REPLAY_DETECTED.value
    ) == 1


def test_receiver_rejects_tampered_end_to_end_envelope(stack):
    sender = build_sender(stack)
    envelope = sender.build_packet(MESSAGE)
    # Peel the onion locally to reach the receiver envelope, then tamper with it.
    private_keys = stack["private_keys"]
    instruction_a = peel_layer(envelope, private_keys["relay-a"], settings.relay_key_ids["relay-a"])
    instruction_b = peel_layer(
        instruction_a["envelope"], private_keys["relay-b"], settings.relay_key_ids["relay-b"]
    )
    instruction_c = peel_layer(
        instruction_b["envelope"], private_keys["relay-c"], settings.relay_key_ids["relay-c"]
    )
    e2e = dict(instruction_c["message"])
    e2e["tag"] = "AAAAAAAAAAAAAAAAAAAAAA=="

    response = asyncio.run(apost(stack["apps"][RECEIVER_ID], "/receive", e2e))
    assert response.status_code == 400
    assert stack["dbs"][RECEIVER_ID].count_messages(receiver_id=RECEIVER_ID) == 0
    assert stack["dbs"][RECEIVER_ID].count_events(
        service_id=RECEIVER_ID, event_type=EventType.AUTHENTICATION_FAILURE.value
    ) == 1


def test_sender_reports_unavailable_entry_relay(stack):
    sender = build_sender(stack, entry_url="http://missing.internal")
    result = asyncio.run(sender.send(MESSAGE))

    assert isinstance(result, SendResult)
    assert result.status == "failed"
    assert stack["dbs"][RECEIVER_ID].count_messages(receiver_id=RECEIVER_ID) == 0


def test_sender_rejects_empty_message(stack):
    sender = build_sender(stack)
    result = asyncio.run(sender.send(""))
    assert result.status == "failed"


def test_health_and_status_endpoints(stack):
    sender = build_sender(stack)
    assert asyncio.run(sender.send(MESSAGE)).status == "sent"

    for relay_id in RELAY_IDS:
        health = asyncio.run(aget(stack["apps"][relay_id], "/health"))
        assert health.status_code == 200
        assert health.json() == {"status": "healthy", "service_id": relay_id, "service_type": "relay"}

        status = asyncio.run(aget(stack["apps"][relay_id], "/status"))
        assert status.status_code == 200
        body = status.json()
        assert body["service_id"] == relay_id
        assert body["packets_received"] == 1
        if relay_id in {"relay-a", "relay-b"}:
            assert body["packets_forwarded"] == 1
        else:
            assert body["packets_delivered"] == 1

    receiver_health = asyncio.run(aget(stack["apps"][RECEIVER_ID], "/health"))
    assert receiver_health.status_code == 200
    assert receiver_health.json() == {
        "status": "healthy",
        "service_id": RECEIVER_ID,
        "service_type": "receiver",
    }
    receiver_status = asyncio.run(aget(stack["apps"][RECEIVER_ID], "/status"))
    assert receiver_status.json()["messages_received"] == 1
