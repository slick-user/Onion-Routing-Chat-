"""In-process topology used by the hosted interactive demo.

The CLI runs every relay and the receiver as separate processes/containers.
Free hosting platforms generally expose a single web port, so the demo builds
the same four FastAPI applications in one process and connects them through
:class:`~networking.inprocess.InProcessNetwork`.  The services still exchange
real HTTP requests (via ``httpx.ASGITransport``) and every relay still peels
exactly one layer; nothing bypasses the relay/receiver code paths.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from Crypto.PublicKey import RSA

from client.receiver import create_receiver_app
from client.sender import Sender
from config.settings import settings
from crypto.keys import (
    generate_service_keys,
    key_fingerprint,
    load_private_key,
    load_public_key,
)
from crypto.onion import build_onion, canonical_json, peel_layer, seal_layer
from networking.inprocess import InProcessNetwork
from networking.transport import TransportError, receive_url, relay_url, status_url
from relay.node import create_relay_app
from relay.registry import PeerRegistry
from relay.router import RelayRole
from storage.database import Database
from web.trace import capture, record

RELAY_IDS: tuple[str, ...] = ("relay-a", "relay-b", "relay-c")
DEFAULT_MESSAGE = "Hello Bob! This is an OnionChat test."

INTERNAL_RELAY_URLS: dict[str, str] = {relay_id: f"http://{relay_id}.internal" for relay_id in RELAY_IDS}
INTERNAL_RECEIVER_URL = "http://receiver.internal"

ATTACK_NAMES = (
    "tamper",
    "replay",
    "wrong_key",
    "wrong_layer",
    "unknown_next_hop",
    "unknown_receiver",
    "oversized",
)


@dataclass
class WebRuntime:
    """All services plus the sender client for a single demo instance."""

    apps: dict[str, Any]
    dbs: dict[str, Database]
    network: InProcessNetwork
    private_keys: dict[str, RSA.RsaKey]
    public_keys: dict[str, RSA.RsaKey]
    sender: Sender
    registry: PeerRegistry
    key_ids: dict[str, str]
    keys_dir: Path
    # The demo is a single shared inbox and a single replay cache. Serialising
    # sends and experiments keeps message IDs and replay observations stable
    # when several browser sessions use the same instance.
    operation_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------
    @classmethod
    def build(
        cls,
        *,
        keys_dir: str | Path | None = None,
        db_dir: str | Path | None = None,
        key_bits: int = 3072,
        auto_generate: bool = True,
        replay_ttl_seconds: int | None = None,
    ) -> "WebRuntime":
        keys_path = Path(keys_dir) if keys_dir is not None else settings.keys_dir
        db_path = Path(db_dir) if db_dir is not None else settings.db_dir

        keys_path.mkdir(parents=True, exist_ok=True)
        db_path.mkdir(parents=True, exist_ok=True)
        for directory in (keys_path, db_path):
            try:
                os.chmod(directory, 0o700)
            except OSError:
                pass

        receiver_id = settings.receiver.service_id
        service_ids = list(RELAY_IDS) + [receiver_id]
        key_ids = {
            relay_id: settings.relay_key_ids[relay_id] for relay_id in RELAY_IDS
        }
        key_ids[receiver_id] = settings.receiver_key_id

        missing = [
            service_id
            for service_id in service_ids
            if not (keys_path / f"{service_id}_private.pem").exists()
            or not (keys_path / f"{service_id}_public.pem").exists()
        ]
        if missing:
            if not auto_generate:
                raise FileNotFoundError(
                    "Missing key files; run `python main.py init-keys` or enable auto-generation"
                )
            generate_service_keys(
                keys_path,
                {service_id: key_ids[service_id] for service_id in missing},
                bits=key_bits,
            )

        private_keys = {
            service_id: load_private_key(keys_path / f"{service_id}_private.pem")
            for service_id in service_ids
        }
        public_keys = {
            service_id: load_public_key(keys_path / f"{service_id}_public.pem")
            for service_id in service_ids
        }

        registry = PeerRegistry(
            relay_urls=dict(INTERNAL_RELAY_URLS),
            receiver_urls={receiver_id: INTERNAL_RECEIVER_URL},
        )
        network = InProcessNetwork()
        dbs = {
            service_id: Database(db_path / f"{service_id}.db")
            for service_id in service_ids
        }

        receiver_app = create_receiver_app(
            receiver_id=receiver_id,
            private_key=private_keys[receiver_id],
            key_id=key_ids[receiver_id],
            db=dbs[receiver_id],
            observer=record,
        )
        network.register(INTERNAL_RECEIVER_URL, receiver_app)

        apps: dict[str, Any] = {receiver_id: receiver_app}
        for relay_id in RELAY_IDS:
            relay_app = create_relay_app(
                relay_id=relay_id,
                role=RelayRole(settings.relay_role(relay_id)),
                private_key=private_keys[relay_id],
                key_id=key_ids[relay_id],
                registry=registry,
                db=dbs[relay_id],
                forwarder=network,
                replay_ttl_seconds=replay_ttl_seconds,
                observer=record,
            )
            apps[relay_id] = relay_app
            network.register(INTERNAL_RELAY_URLS[relay_id], relay_app)

        sender = Sender(
            entry_relay_url=INTERNAL_RELAY_URLS["relay-a"],
            receiver_id=receiver_id,
            receiver_key_id=key_ids[receiver_id],
            receiver_public_key=public_keys[receiver_id],
            relay_path=list(RELAY_IDS),
            relay_public_keys={relay_id: public_keys[relay_id] for relay_id in RELAY_IDS},
            relay_key_ids={relay_id: key_ids[relay_id] for relay_id in RELAY_IDS},
            forwarder=network,
        )

        return cls(
            apps=apps,
            dbs=dbs,
            network=network,
            private_keys=private_keys,
            public_keys=public_keys,
            sender=sender,
            registry=registry,
            key_ids=key_ids,
            keys_dir=keys_path,
        )

    # ------------------------------------------------------------------
    # Demo actions
    # ------------------------------------------------------------------
    @property
    def receiver_id(self) -> str:
        return settings.receiver.service_id

    def _entry_app(self, entry: str) -> tuple[str, Any]:
        if entry not in self.apps:
            raise KeyError("unknown entry service")
        base = INTERNAL_RELAY_URLS[entry]
        return base, self.apps[entry]

    async def submit_packet(
        self,
        envelope: dict[str, Any],
        *,
        entry: str = "relay-a",
    ) -> tuple[int, dict[str, Any]]:
        """Submit an envelope directly and return ``(status_code, body)``."""
        base, app = self._entry_app(entry)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url=base) as client:
            response = await client.post("/relay", json=envelope)
        try:
            body = response.json()
        except ValueError:
            body = {"detail": "non-JSON response"}
        if not isinstance(body, dict):
            body = {"detail": "unexpected response"}
        return response.status_code, body

    async def deliver(self, message: str) -> dict[str, Any]:
        """Build an onion, run the circuit, and return a sanitized trace."""
        async with self.operation_lock:
            packet = self.sender.build_packet(message)
            with capture() as trace:
                response = await self.network.post_json(
                    relay_url(INTERNAL_RELAY_URLS["relay-a"]),
                    packet,
                )
            latest = self.dbs[self.receiver_id].latest_message(receiver_id=self.receiver_id)
            return {
                "status": "sent",
                "message_id": latest["id"] if latest else None,
                "entry_response": response,
                "packet_bytes": len(canonical_json(packet)),
                "trace": trace,
            }

    async def run_attack(self, attack: str) -> dict[str, Any]:
        async with self.operation_lock:
            return await self._run_attack(attack)

    async def _run_attack(self, attack: str) -> dict[str, Any]:
        """Execute one simulated attack and return the observed result."""
        if attack not in ATTACK_NAMES:
            raise ValueError("unknown attack")

        base_packet = self.sender.build_packet(DEFAULT_MESSAGE)
        trace: list[dict[str, Any]] = []

        if attack == "replay":
            with capture() as captured:
                first_status, first_body = await self.submit_packet(base_packet)
                second_status, second_body = await self.submit_packet(base_packet)
            trace = captured
            return {
                "attack": attack,
                "status_code": second_status,
                "first_status_code": first_status,
                "body": second_body,
                "first_body": first_body,
                "trace": trace,
            }

        if attack == "oversized":
            oversized = dict(base_packet)
            oversized["ciphertext"] = "A" * (settings.max_packet_bytes + 4096)
            with capture() as captured:
                status, body = await self.submit_packet(oversized)
            return {"attack": attack, "status_code": status, "body": body, "trace": captured}

        if attack == "wrong_key":
            tampered = dict(base_packet)
            # A packet for Relay A relabelled as a Relay B packet.
            tampered["recipient_key_id"] = self.key_ids["relay-b"]
            with capture() as captured:
                status, body = await self.submit_packet(tampered)
            return {"attack": attack, "status_code": status, "body": body, "trace": captured}

        if attack == "tamper":
            tampered = dict(base_packet)
            ciphertext = list(str(tampered["ciphertext"]))
            ciphertext[0] = "A" if ciphertext[0] != "A" else "B"
            tampered["ciphertext"] = "".join(ciphertext)
            with capture() as captured:
                status, body = await self.submit_packet(tampered)
            return {"attack": attack, "status_code": status, "body": body, "trace": captured}

        if attack == "wrong_layer":
            # Build a packet whose only layer is an exit instruction, then send
            # it to the entry relay, which must reject the wrong instruction.
            wrong_layer = build_onion(
                message=DEFAULT_MESSAGE,
                receiver_id=self.receiver_id,
                receiver_key_id=self.key_ids[self.receiver_id],
                receiver_public_key=self.public_keys[self.receiver_id],
                relay_path=["relay-a"],
                relay_public_keys={relay_id: self.public_keys[relay_id] for relay_id in RELAY_IDS},
                relay_key_ids={relay_id: self.key_ids[relay_id] for relay_id in RELAY_IDS},
            )
            with capture() as captured:
                status, body = await self.submit_packet(wrong_layer)
            return {"attack": attack, "status_code": status, "body": body, "trace": captured}

        if attack == "unknown_next_hop":
            inner = build_onion(
                message=DEFAULT_MESSAGE,
                receiver_id=self.receiver_id,
                receiver_key_id=self.key_ids[self.receiver_id],
                receiver_public_key=self.public_keys[self.receiver_id],
                relay_path=["relay-b", "relay-c"],
                relay_public_keys={relay_id: self.public_keys[relay_id] for relay_id in RELAY_IDS},
                relay_key_ids={relay_id: self.key_ids[relay_id] for relay_id in RELAY_IDS},
            )
            malicious = seal_layer(
                {
                    # Packet contents can only carry a logical ID. Even a URL
                    # here is rejected by the local trusted registry.
                    "next_hop_id": "http://attacker.example/steal",
                    "envelope": inner,
                },
                recipient_key_id=self.key_ids["relay-a"],
                public_key=self.public_keys["relay-a"],
            )
            with capture() as captured:
                status, body = await self.submit_packet(malicious)
            return {"attack": attack, "status_code": status, "body": body, "trace": captured}

        if attack == "unknown_receiver":
            packet = build_onion(
                message=DEFAULT_MESSAGE,
                receiver_id="mallory",
                receiver_key_id=self.key_ids[self.receiver_id],
                receiver_public_key=self.public_keys[self.receiver_id],
                relay_path=list(RELAY_IDS),
                relay_public_keys={relay_id: self.public_keys[relay_id] for relay_id in RELAY_IDS},
                relay_key_ids={relay_id: self.key_ids[relay_id] for relay_id in RELAY_IDS},
            )
            instruction_a = peel_layer(packet, self.private_keys["relay-a"], self.key_ids["relay-a"])
            instruction_b = peel_layer(
                instruction_a["envelope"],
                self.private_keys["relay-b"],
                self.key_ids["relay-b"],
            )
            with capture() as captured:
                status, body = await self.submit_packet(instruction_b["envelope"], entry="relay-c")
            return {"attack": attack, "status_code": status, "body": body, "trace": captured}

        raise ValueError("unhandled attack")

    # ------------------------------------------------------------------
    # Read-only views
    # ------------------------------------------------------------------
    async def status_snapshot(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for relay_id in RELAY_IDS:
            try:
                data = await self.network.get_json(status_url(INTERNAL_RELAY_URLS[relay_id]))
            except TransportError:
                data = {"service_id": relay_id, "status": "unavailable"}
            results.append(dict(data, service_type="relay", role=settings.relay_role(relay_id)))
        try:
            data = await self.network.get_json(status_url(INTERNAL_RECEIVER_URL))
        except TransportError:
            data = {"service_id": self.receiver_id, "status": "unavailable"}
        results.append(dict(data, service_type="receiver", role="receiver"))
        return results

    def key_metadata(self, keys_dir: str | Path | None = None) -> list[dict[str, Any]]:
        keys_path = Path(keys_dir) if keys_dir is not None else self.keys_dir
        services = [
            *(("relay", relay_id, settings.relay_role(relay_id)) for relay_id in RELAY_IDS),
            ("receiver", self.receiver_id, "receiver"),
        ]
        rows: list[dict[str, Any]] = []
        for service_type, service_id, role in services:
            private_path = keys_path / f"{service_id}_private.pem"
            try:
                mode = oct(private_path.stat().st_mode & 0o777)
            except OSError:
                mode = "unknown"
            rows.append(
                {
                    "service_id": service_id,
                    "service_type": service_type,
                    "role": role,
                    "key_id": self.key_ids[service_id],
                    "algorithm": f"RSA-{self.public_keys[service_id].size_in_bits()} · OAEP-SHA256",
                    "fingerprint": key_fingerprint(self.public_keys[service_id]),
                    "private_key_mode": mode,
                }
            )
        return rows

    def recent_messages(self, *, limit: int = 20) -> list[dict[str, Any]]:
        return self.dbs[self.receiver_id].recent_messages(receiver_id=self.receiver_id, limit=limit)

    def recent_events(self, *, service_id: str | None = None, limit: int = 40) -> list[dict[str, Any]]:
        """Aggregate recent operational events across every service database."""
        rows: list[dict[str, Any]] = []
        for db_service_id, db in self.dbs.items():
            if service_id is not None and db_service_id != service_id:
                continue
            rows.extend(db.recent_events(service_id=db_service_id, limit=limit))
        rows.sort(key=lambda row: str(row.get("timestamp") or ""), reverse=True)
        allowed = {
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
        return [
            {key: value for key, value in row.items() if key in allowed}
            for row in rows[: max(1, limit)]
        ]

    def reset(self) -> dict[str, int]:
        counts = {"messages": 0, "events": 0, "replays": 0}
        for service_id, db in self.dbs.items():
            counts["events"] += db.clear_events(service_id=service_id)
            if service_id == self.receiver_id:
                counts["messages"] += db.clear_messages(receiver_id=service_id)
            else:
                counts["replays"] += db.clear_replays(relay_id=service_id)
        return counts


__all__ = [
    "ATTACK_NAMES",
    "DEFAULT_MESSAGE",
    "INTERNAL_RECEIVER_URL",
    "INTERNAL_RELAY_URLS",
    "RELAY_IDS",
    "WebRuntime",
]
