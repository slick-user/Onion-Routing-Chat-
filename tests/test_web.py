from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from web.app import create_web_app
from web.runtime import ATTACK_NAMES, WebRuntime

MESSAGE = "Web demo plaintext that must never reach an event log."

EVENT_KEYS = {
    "event_id",
    "timestamp",
    "service_id",
    "service_type",
    "event_type",
    "status",
    "duration_ms",
    "error_category",
    "detail",
}

KEY_KEYS = {
    "service_id",
    "service_type",
    "role",
    "key_id",
    "algorithm",
    "fingerprint",
    "private_key_mode",
}

ATTACK_STATUS = {
    "tamper": 400,
    "replay": 409,
    "wrong_key": 400,
    "wrong_layer": 400,
    "unknown_next_hop": 400,
    "unknown_receiver": 400,
    "oversized": 413,
}


@pytest.fixture(scope="module")
def web_key_dir(tmp_path_factory):
    # Generate the four RSA-2048 test keys once for the whole module; each test
    # still gets its own databases so mutations cannot leak between tests.
    return tmp_path_factory.mktemp("web-keys")


@pytest.fixture()
def web_app(tmp_path, web_key_dir):
    runtime = WebRuntime.build(
        keys_dir=web_key_dir,
        db_dir=tmp_path / "db",
        key_bits=2048,
    )
    return create_web_app(runtime)


def request(app, method: str, path: str, payload: dict | None = None) -> httpx.Response:
    async def run() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://web.test") as client:
            return await client.request(method, path, json=payload)

    return asyncio.run(run())


def get(app, path: str) -> httpx.Response:
    return request(app, "GET", path)


def post(app, path: str, payload: dict | None = None) -> httpx.Response:
    return request(app, "POST", path, payload)


# Page and assets
def test_index_renders_interactive_ui_and_security_headers(web_app):
    response = get(web_app, "/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    body = response.text

    for marker in (
        "OnionChat",
        'name="viewport"',
        'role="tablist"',
        "Guided tour",
        "Seal &amp; send onion",
        "Security lab",
        "What each hop can see",
        "Bob's inbox",
        "data-tip=",
        'id="tour"',
    ):
        assert marker in body

    for attack in ATTACK_NAMES:
        assert f'data-attack="{attack}"' in body

    assert "{{" not in body
    assert "BEGIN PRIVATE KEY" not in body
    assert "BEGIN RSA PRIVATE KEY" not in body

    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert "'unsafe-inline'" not in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["cross-origin-opener-policy"] == "same-origin"
    assert "camera=()" in response.headers["permissions-policy"]


def test_static_assets_are_served_locally(web_app):
    css = get(web_app, "/static/css/app.css")
    assert css.status_code == 200
    assert "--accent" in css.text
    assert "prefers-reduced-motion" in css.text

    js = get(web_app, "/static/js/app.js")
    assert js.status_code == 200
    assert "function playTrace" in js.text
    assert "tour" in js.text


def test_health_endpoint(web_app):
    response = get(web_app, "/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["relays"] == 3


# Sending and tracing
def test_send_returns_hop_trace_and_delivers_message(web_app):
    response = post(web_app, "/api/send", {"message": MESSAGE})
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "sent"
    assert isinstance(data["message_id"], int)
    trace = data["trace"]
    assert isinstance(trace, list) and trace
    assert {event["service_id"] for event in trace} == {
        "relay-a",
        "relay-b",
        "relay-c",
        "receiver-bob",
    }
    assert any(event["stage"] == "stored" for event in trace)
    assert any(event["stage"] == "delivered" for event in trace)

    # The trace is metadata only: no plaintext and no raw packet fields.
    serialized = json.dumps(data)
    assert MESSAGE not in serialized
    assert "wrapped_key" not in serialized
    assert "ciphertext" not in serialized
    assert "nonce" not in serialized

    inbox = get(web_app, "/api/messages")
    assert inbox.status_code == 200
    assert inbox.json()["total"] == 1
    messages = inbox.json()["messages"]
    assert len(messages) == 1
    assert messages[0]["message"] == MESSAGE
    assert messages[0]["receiver_id"] == "receiver-bob"


def test_hop_trace_reveals_only_neighbour_information(web_app):
    trace = post(web_app, "/api/send", {"message": MESSAGE}).json()["trace"]
    decrypted = {
        event["service_id"]: event
        for event in trace
        if event.get("stage") == "decrypted" and event.get("service_type") == "relay"
    }

    assert decrypted["relay-a"]["next_hop_id"] == "relay-b"
    assert "receiver_id" not in decrypted["relay-a"]
    assert decrypted["relay-b"]["next_hop_id"] == "relay-c"
    assert decrypted["relay-c"]["receiver_id"] == "receiver-bob"
    for event in trace:
        assert MESSAGE not in json.dumps(event)


def test_empty_and_oversized_messages_are_rejected(web_app):
    whitespace = post(web_app, "/api/send", {"message": "   "})
    assert whitespace.status_code == 400

    empty = post(web_app, "/api/send", {"message": ""})
    assert empty.status_code == 422

    too_long = post(web_app, "/api/send", {"message": "A" * 4001})
    assert too_long.status_code == 422


# Security lab
def test_every_attack_is_blocked_with_the_expected_status(web_app):
    for attack in ATTACK_NAMES:
        response = post(web_app, "/api/attack", {"attack": attack})
        assert response.status_code == 200, attack
        data = response.json()

        assert data["attack"] == attack
        assert data["status_code"] == ATTACK_STATUS[attack], attack
        assert data["expected"] == ATTACK_STATUS[attack], attack
        assert data["blocked"] is True, attack
        assert data["title"]
        assert data["explanation"]
        assert isinstance(data["trace"], list)
        assert isinstance(data["events"], list)

        if attack == "replay":
            assert data["first_status_code"] == 200
            assert len(data["trace"]) > 2
        if attack == "oversized":
            assert data["trace"] == []


def test_attack_traces_never_contain_plaintext(web_app):
    for attack in ("tamper", "replay", "wrong_key", "wrong_layer", "unknown_next_hop", "unknown_receiver"):
        data = post(web_app, "/api/attack", {"attack": attack}).json()
        serialized = json.dumps(data)
        assert MESSAGE not in serialized
        assert '"wrapped_key":' not in serialized
        assert '"ciphertext":' not in serialized
        assert '"nonce":' not in serialized


def test_unknown_attack_is_rejected(web_app):
    response = post(web_app, "/api/attack", {"attack": "definitely_not_real"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Unknown attack"


# Keys, events and overview
def test_overview_exposes_only_public_key_metadata(web_app):
    post(web_app, "/api/send", {"message": MESSAGE})
    response = get(web_app, "/api/overview")
    assert response.status_code == 200
    data = response.json()

    assert data["counts"]["messages"] == 1
    assert len(data["keys"]) == 4
    for key in data["keys"]:
        assert set(key) == KEY_KEYS
        assert key["algorithm"].startswith("RSA-")
        assert "OAEP-SHA256" in key["algorithm"]
        assert key["fingerprint"]
        assert key["private_key_mode"] == "0o600"

    serialized = json.dumps(data)
    assert "BEGIN PRIVATE KEY" not in serialized
    assert "BEGIN RSA PRIVATE KEY" not in serialized
    assert "wrapped_key" not in serialized
    assert MESSAGE not in serialized


def test_events_are_aggregated_and_sanitized(web_app):
    post(web_app, "/api/send", {"message": MESSAGE})
    response = get(web_app, "/api/events")
    assert response.status_code == 200
    events = response.json()["events"]
    assert events

    assert {event["service_id"] for event in events} == {
        "relay-a",
        "relay-b",
        "relay-c",
        "receiver-bob",
    }
    for event in events:
        assert set(event) <= EVENT_KEYS
        serialized = json.dumps(event)
        assert MESSAGE not in serialized
        assert "wrapped_key" not in serialized
        assert "ciphertext" not in serialized
        assert "nonce" not in serialized

    filtered = get(web_app, "/api/events?service=relay-b")
    assert filtered.status_code == 200
    assert filtered.json()["events"]
    assert {event["service_id"] for event in filtered.json()["events"]} == {"relay-b"}

    unknown = get(web_app, "/api/events?service=mallory")
    assert unknown.status_code == 400


# Reset
def test_reset_clears_messages_events_and_replays(web_app):
    post(web_app, "/api/send", {"message": MESSAGE})
    post(web_app, "/api/attack", {"attack": "replay"})

    before = get(web_app, "/api/overview").json()
    # The send delivers once and the replay experiment delivers once before the
    # duplicate is rejected, so two messages exist at this point.
    assert before["counts"]["messages"] == 2

    response = post(web_app, "/api/reset")
    assert response.status_code == 200
    cleared = response.json()["cleared"]
    assert cleared["messages"] >= 1
    assert cleared["events"] > 0
    assert cleared["replays"] >= 3

    assert get(web_app, "/api/messages").json()["messages"] == []
    assert get(web_app, "/api/events").json()["events"] == []
    assert get(web_app, "/api/overview").json()["counts"]["messages"] == 0
