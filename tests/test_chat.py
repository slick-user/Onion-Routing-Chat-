"""Two-way chat: directory, registration, sending, mailbox, WebSocket, browser interop."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from Crypto.PublicKey import RSA
from fastapi.testclient import TestClient

from crypto.encryption import decrypt_message_e2e, encrypt_message_e2e
from crypto.keys import export_private_key, export_public_key, import_public_key
from crypto.onion import build_onion
from networking.traffic_policy import pad_to_cell
from web.app import create_web_app
from web.runtime import WebRuntime

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def keys_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("chat-keys")


@pytest.fixture(scope="module")
def user_keys():
    return {"alice": RSA.generate(2048), "bob": RSA.generate(2048)}


@pytest.fixture()
def chat(tmp_path, keys_dir):
    runtime = WebRuntime.build(keys_dir=keys_dir, db_dir=tmp_path / "db", key_bits=2048)
    return TestClient(create_web_app(runtime)), runtime


def register(client, name, key):
    response = client.post(
        "/api/chat/register", json={"name": name, "public_key_pem": export_public_key(key).decode()}
    )
    assert response.status_code == 200, response.text
    return response.json()


def python_chat_packet(directory, sender, recipient, text):
    """Do in Python what onion-client.js does in the browser."""
    relays = directory["relays"]
    to = next(user for user in directory["users"] if user["user_id"] == recipient["user_id"])
    payload = json.dumps(
        {"type": "chat", "from": sender["user_id"], "from_name": sender["name"], "text": text}
    )
    packet = build_onion(
        message=payload,
        receiver_id=directory["mailbox_id"],
        receiver_key_id=to["key_id"],
        receiver_public_key=import_public_key(to["public_key_pem"]),
        relay_path=[relay["id"] for relay in relays],
        relay_public_keys={relay["id"]: import_public_key(relay["public_key_pem"]) for relay in relays},
        relay_key_ids={relay["id"]: relay["key_id"] for relay in relays},
    )
    return pad_to_cell(packet, directory["cell_bytes"]) if directory["cell_bytes"] else packet


def auth(user):
    return {"Authorization": f"Bearer {user['token']}"}


# Directory and registration
def test_register_publishes_only_public_information(chat, user_keys):
    client, _ = chat
    alice = register(client, "Alice", user_keys["alice"])
    directory = client.get("/api/chat/directory").json()

    assert [user["name"] for user in directory["users"]] == ["Alice"]
    assert len(directory["relays"]) == 3 and directory["mailbox_id"] == "mailbox"
    text = json.dumps(directory)
    assert alice["token"] not in text
    assert "PRIVATE KEY" not in text


def test_register_rejects_private_keys_bad_names_and_small_keys(chat, user_keys):
    client, _ = chat
    private_pem = export_private_key(user_keys["alice"]).decode()
    assert (
        client.post("/api/chat/register", json={"name": "Eve", "public_key_pem": private_pem}).status_code
        == 400
    )
    pem = export_public_key(user_keys["alice"]).decode()
    assert (
        client.post("/api/chat/register", json={"name": "<script>", "public_key_pem": pem}).status_code == 400
    )
    small = export_public_key(RSA.generate(1024)).decode()
    assert (
        client.post("/api/chat/register", json={"name": "Tiny", "public_key_pem": small}).status_code == 400
    )


# Sending and receiving
def test_two_way_chat_through_three_relays(chat, user_keys):
    client, runtime = chat
    alice = register(client, "Alice", user_keys["alice"])
    bob = register(client, "Bob", user_keys["bob"])
    directory = client.get("/api/chat/directory").json()

    # Alice -> Bob
    sent = client.post("/api/chat/send", json=python_chat_packet(directory, alice, bob, "hi Bob")).json()
    assert sent["delivered"] is True
    hops = [event["service_id"] for event in sent["trace"] if event["stage"] in {"decrypted", "stored"}]
    assert hops == ["relay-a", "relay-b", "relay-c", "mailbox"]

    # Bob reads it with his private key; the server only had ciphertext.
    inbox = client.get("/api/chat/inbox", params={"user_id": bob["user_id"]}, headers=auth(bob)).json()[
        "messages"
    ]
    assert len(inbox) == 1
    message = json.loads(decrypt_message_e2e(inbox[0]["envelope"], user_keys["bob"], bob["key_id"]))
    assert message["text"] == "hi Bob" and message["from"] == alice["user_id"]

    # Bob -> Alice (the reply uses Alice's public key from the directory)
    reply = client.post("/api/chat/send", json=python_chat_packet(directory, bob, alice, "hi Alice")).json()
    assert reply["delivered"] is True
    alice_inbox = client.get(
        "/api/chat/inbox", params={"user_id": alice["user_id"]}, headers=auth(alice)
    ).json()
    reply_text = json.loads(
        decrypt_message_e2e(alice_inbox["messages"][0]["envelope"], user_keys["alice"], alice["key_id"])
    )["text"]
    assert reply_text == "hi Alice"


def test_server_never_stores_or_returns_plaintext(chat, user_keys):
    client, runtime = chat
    alice = register(client, "Alice", user_keys["alice"])
    bob = register(client, "Bob", user_keys["bob"])
    directory = client.get("/api/chat/directory").json()
    secret = "the eagle lands at midnight"
    response = client.post("/api/chat/send", json=python_chat_packet(directory, alice, bob, secret))
    assert secret not in response.text

    # Neither the text nor the sender's name is anywhere in the database file...
    assert secret.encode() not in Path(runtime.chat_store.path).read_bytes()
    # ...and the stored mailbox entry does not reveal who sent it.
    stored = json.dumps(runtime.chat_store.inbox(user_id=bob["user_id"]))
    assert "Alice" not in stored and alice["user_id"] not in stored

    events = client.get("/api/events", params={"limit": 200}).text
    assert secret not in events


def test_inbox_requires_the_right_token(chat, user_keys):
    client, _ = chat
    bob = register(client, "Bob", user_keys["bob"])
    url = "/api/chat/inbox"
    assert client.get(url, params={"user_id": bob["user_id"]}).status_code == 401
    wrong = {"Authorization": "Bearer " + "x" * 43}
    assert client.get(url, params={"user_id": bob["user_id"]}, headers=wrong).status_code == 401
    assert client.get(url, params={"user_id": "u-nobody"}, headers=auth(bob)).status_code == 401
    assert client.get(url, params={"user_id": bob["user_id"]}, headers=auth(bob)).status_code == 200


def test_unknown_recipient_and_garbage_are_rejected(chat, user_keys):
    client, _ = chat
    alice = register(client, "Alice", user_keys["alice"])
    directory = client.get("/api/chat/directory").json()
    ghost = {"user_id": "u-ghost", "name": "Ghost"}
    directory["users"].append(
        {
            "user_id": "u-ghost",
            "key_id": "u-ghost-key",
            "public_key_pem": export_public_key(user_keys["bob"]).decode(),
        }
    )
    result = client.post("/api/chat/send", json=python_chat_packet(directory, alice, ghost, "boo")).json()
    assert result["delivered"] is False
    assert result["rejected_by"] == "mailbox" and result["error_category"] == "unknown_recipient"

    assert client.post("/api/chat/send", json={"hello": "world"}).status_code == 400


def test_chat_survives_relay_key_rotation(chat, user_keys, monkeypatch):
    from config.settings import settings

    monkeypatch.setattr(settings, "key_action_cooldown_seconds", 0.0)
    client, _ = chat
    alice = register(client, "Alice", user_keys["alice"])
    bob = register(client, "Bob", user_keys["bob"])
    old_key = client.get("/api/chat/directory").json()["relays"][1]["key_id"]
    assert client.post("/api/keys/rotate", json={"service_id": "relay-b"}).status_code == 200

    directory = client.get("/api/chat/directory").json()
    assert directory["relays"][1]["key_id"] != old_key  # the directory advertises the new key
    assert client.post(
        "/api/chat/send", json=python_chat_packet(directory, alice, bob, "after rotation")
    ).json()["delivered"]


# Live WebSocket delivery
def test_websocket_pushes_new_mail_and_rejects_bad_tokens(chat, user_keys):
    client, _ = chat
    alice = register(client, "Alice", user_keys["alice"])
    bob = register(client, "Bob", user_keys["bob"])

    with client.websocket_connect("/ws/chat") as socket:
        socket.send_json({"user_id": bob["user_id"], "token": "wrong"})
        assert socket.receive_json()["type"] == "error"

    with client.websocket_connect("/ws/chat") as socket:
        socket.send_json({"user_id": bob["user_id"], "token": bob["token"]})
        assert socket.receive_json()["type"] == "ready"
        directory = client.get("/api/chat/directory").json()
        assert next(u for u in directory["users"] if u["user_id"] == bob["user_id"])["online"] is True

        client.post("/api/chat/send", json=python_chat_packet(directory, alice, bob, "live!"))
        event = socket.receive_json()
        while event["type"] != "message":
            event = socket.receive_json()
        text = json.loads(decrypt_message_e2e(event["envelope"], user_keys["bob"], bob["key_id"]))["text"]
        assert text == "live!"


# The real browser code (run under Node.js) against the real relays
@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed")
def test_browser_client_onion_is_accepted_by_python_relays(chat, user_keys, tmp_path):
    client, runtime = chat
    bob = register(client, "Bob", user_keys["bob"])
    directory = client.get("/api/chat/directory").json()
    to = next(user for user in directory["users"] if user["user_id"] == bob["user_id"])

    python_secret = RSA.generate(2048)
    spec = {
        "text": "héllo from the browser code 🌍",
        "relays": directory["relays"],
        "recipient": to,
        "mailbox_id": directory["mailbox_id"],
        "cell_bytes": directory["cell_bytes"],
        "python_e2e": encrypt_message_e2e("python → browser", python_secret.publickey(), "k1"),
        "python_private_pkcs8_pem": export_private_key(python_secret).decode(),
    }
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(spec))
    run = subprocess.run(
        ["node", str(ROOT / "tests/js/interop.mjs"), str(spec_path)],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=ROOT,
    )
    assert run.returncode == 0, run.stderr
    out = json.loads(run.stdout)

    assert out["decrypted"] == "python → browser"
    assert out["identity_pem_ok"] is True
    assert out["packet_bytes"] == directory["cell_bytes"]

    sent = client.post("/api/chat/send", json=out["packet"]).json()
    assert sent["delivered"] is True, sent
    inbox = client.get("/api/chat/inbox", params={"user_id": bob["user_id"]}, headers=auth(bob)).json()[
        "messages"
    ]
    message = json.loads(decrypt_message_e2e(inbox[0]["envelope"], user_keys["bob"], bob["key_id"]))
    assert message["text"] == "héllo from the browser code 🌍"
    assert message["type"] == "chat"
