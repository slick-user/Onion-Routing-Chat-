from __future__ import annotations

from typing import Any

import httpx

from fastapi import FastAPI

from client.receiver import create_receiver_app
from client.sender import Sender
from config.settings import settings
from crypto.keys import generate_keypair, import_private_key, import_public_key
from networking.inprocess import InProcessNetwork
from relay.node import create_relay_app
from relay.registry import PeerRegistry
from relay.router import RelayRole
from storage.database import Database

RELAY_IDS = ("relay-a", "relay-b", "relay-c")
RECEIVER_ID = "receiver-bob"
RELAY_BASE_URLS = {
    "relay-a": "http://relay-a.internal",
    "relay-b": "http://relay-b.internal",
    "relay-c": "http://relay-c.internal",
}
RECEIVER_BASE_URL = "http://receiver.internal"


def generate_test_keypairs(bits: int = 2048) -> dict[str, bytes]:
    names = list(RELAY_IDS) + [RECEIVER_ID]
    return {name: generate_keypair(bits)["private_key"] for name in names}


def key_material_from_pem(private_pems: dict[str, bytes]):
    private_keys = {name: import_private_key(pem) for name, pem in private_pems.items()}
    public_keys = {name: private_keys[name].publickey() for name in private_keys}
    return private_keys, public_keys


def build_stack(*, tmp_path, private_pems: dict[str, bytes], replay_ttl_seconds: int = 300):
    private_keys, public_keys = key_material_from_pem(private_pems)
    network = InProcessNetwork()
    registry = PeerRegistry(
        relay_urls=dict(RELAY_BASE_URLS),
        receiver_urls={RECEIVER_ID: RECEIVER_BASE_URL},
    )
    dbs = {service_id: Database(tmp_path / f"{service_id}.db") for service_id in list(RELAY_IDS) + [RECEIVER_ID]}

    receiver_app = create_receiver_app(
        receiver_id=RECEIVER_ID,
        private_key=private_keys[RECEIVER_ID],
        key_id=settings.receiver_key_id,
        db=dbs[RECEIVER_ID],
    )
    network.register(RECEIVER_BASE_URL, receiver_app)

    apps: dict[str, FastAPI] = {RECEIVER_ID: receiver_app}
    for relay_id in RELAY_IDS:
        app = create_relay_app(
            relay_id=relay_id,
            role=RelayRole(settings.relay_role(relay_id)),
            private_key=private_keys[relay_id],
            key_id=settings.relay_key_ids[relay_id],
            registry=registry,
            db=dbs[relay_id],
            forwarder=network,
            replay_ttl_seconds=replay_ttl_seconds,
        )
        apps[relay_id] = app
        network.register(RELAY_BASE_URLS[relay_id], app)

    return {
        "apps": apps,
        "dbs": dbs,
        "network": network,
        "private_keys": private_keys,
        "public_keys": public_keys,
        "registry": registry,
    }


def build_sender(stack, *, entry_url: str = RELAY_BASE_URLS["relay-a"]) -> Sender:
    public_keys = stack["public_keys"]
    return Sender(
        entry_relay_url=entry_url,
        receiver_id=RECEIVER_ID,
        receiver_key_id=settings.receiver_key_id,
        receiver_public_key=public_keys[RECEIVER_ID],
        relay_path=list(RELAY_IDS),
        relay_public_keys={relay_id: public_keys[relay_id] for relay_id in RELAY_IDS},
        relay_key_ids={relay_id: settings.relay_key_ids[relay_id] for relay_id in RELAY_IDS},
        forwarder=stack["network"],
    )


async def apost(app: FastAPI, path: str, payload: dict[str, Any], *, base_url: str = "http://test") -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=base_url) as client:
        return await client.post(path, json=payload)


async def aget(app: FastAPI, path: str, *, base_url: str = "http://test") -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=base_url) as client:
        return await client.get(path)
