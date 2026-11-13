"""Sender client: end-to-end encrypt, build an onion, submit to Relay A."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from Crypto.PublicKey import RSA

from crypto.onion import build_onion
from networking.schemas import SendResult
from networking.traffic_policy import TrafficPolicy
from networking.transport import JsonForwarder, TransportError, relay_url


class Sender:
    def __init__(
        self,
        *,
        entry_relay_url: str,
        receiver_id: str,
        receiver_key_id: str,
        receiver_public_key: RSA.RsaKey,
        relay_path: Sequence[str],
        relay_public_keys: Mapping[str, RSA.RsaKey],
        relay_key_ids: Mapping[str, str],
        forwarder: JsonForwarder | Any | None = None,
        policy: TrafficPolicy | None = None,
    ):
        self.entry_relay_url = entry_relay_url
        self.receiver_id = receiver_id
        self.receiver_key_id = receiver_key_id
        self.receiver_public_key = receiver_public_key
        self.relay_path = list(relay_path)
        self.relay_public_keys = dict(relay_public_keys)
        self.relay_key_ids = dict(relay_key_ids)
        self.forwarder = forwarder or JsonForwarder()
        self.policy = policy or TrafficPolicy()

    def build_packet(self, message: str) -> dict[str, Any]:
        """Encrypt for the receiver, wrap three layers and pad to the cell size."""
        onion = build_onion(
            message=message,
            receiver_id=self.receiver_id,
            receiver_key_id=self.receiver_key_id,
            receiver_public_key=self.receiver_public_key,
            relay_path=self.relay_path,
            relay_public_keys=self.relay_public_keys,
            relay_key_ids=self.relay_key_ids,
        )
        return self.policy.prepare_for_wire(onion)

    async def send(self, message: str) -> SendResult:
        if not message:
            return SendResult(status="failed", detail="message must not be empty")

        try:
            envelope = self.build_packet(message)
        except (ValueError, TypeError):
            return SendResult(status="failed", detail="could not construct onion packet")

        try:
            response = await self.forwarder.post_json(relay_url(self.entry_relay_url), envelope)
        except TransportError:
            return SendResult(status="failed", detail="entry relay unavailable")

        if response.get("status") not in {"forwarded", "delivered"}:
            return SendResult(status="failed", detail="entry relay rejected the packet")

        return SendResult(
            status="sent",
            detail="packet submitted to entry relay",
            response={"status": response.get("status")},
        )
