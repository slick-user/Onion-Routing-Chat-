"""Relay packet processing: replay check, one-layer decryption, forwarding."""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Protocol

from pydantic import ValidationError

from crypto.encryption import AuthenticationError, CryptoError
from crypto.onion import (
    InvalidLayerError,
    OnionError,
    canonical_json,
    classify_instruction,
    packet_digest,
    peel_layer,
)
from networking.schemas import ExitInstruction, OnionEnvelope, RelayInstruction
from networking.transport import TransportError, receive_url, relay_url
from observability.events import EventRecorder, EventStatus, EventType, safe_detail
from relay.registry import PeerRegistry, UnknownPeerError
from storage.database import Database


class RelayRole(str, Enum):
    ENTRY = "entry"
    MIDDLE = "middle"
    EXIT = "exit"


class RelayError(Exception):
    """Base class for relay processing failures."""


class InvalidPacketError(RelayError):
    """Packet rejected before forwarding (malformed, unauthenticated, unknown peer)."""


class ReplayDetectedError(RelayError):
    """Duplicate packet rejected by the persistent replay cache."""


class ForwardingError(RelayError):
    """A trusted downstream service could not be reached or failed."""


class Forwarder(Protocol):
    async def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]: ...


RelayObserver = Callable[[dict[str, Any]], None]


@dataclass
class RelayResult:
    status: str
    duration_ms: float
    packet_digest: str
    next_hop: str | None = None


class RelayProcessor:
    def __init__(
        self,
        *,
        relay_id: str,
        role: RelayRole,
        private_key: Any,
        key_id: str,
        registry: PeerRegistry,
        db: Database,
        events: EventRecorder,
        forwarder: Forwarder,
        replay_ttl_seconds: int,
        observer: RelayObserver | None = None,
    ):
        self.relay_id = relay_id
        self.role = role
        self.private_key = private_key
        self.key_id = key_id
        self.registry = registry
        self.db = db
        self.events = events
        self.forwarder = forwarder
        self.replay_ttl_seconds = replay_ttl_seconds
        self.observer = observer

    async def process(self, envelope: OnionEnvelope) -> RelayResult:
        started = time.perf_counter()
        self.events.emit(EventType.PACKET_RECEIVED, detail=safe_detail(role=self.role.value))
        self._observe(
            "received",
            started,
            packet_bytes=len(canonical_json(envelope.model_dump())),
            recipient_key_id=envelope.recipient_key_id,
        )

        digest = packet_digest(envelope)

        try:
            self._reject_replay(digest, started)
            self._check_recipient(envelope, started)
            instruction = self._decrypt(envelope, started)
            role_kind = self._validate_instruction(instruction, started)
            self._record_acceptance(digest, started)

            if role_kind == "exit":
                return await self._deliver(instruction, digest, started)
            return await self._forward(instruction, digest, started)

        except RelayError:
            raise
        except Exception:  # defensive: never leak internals
            self.events.emit(
                EventType.INTERNAL_ERROR,
                status=EventStatus.FAILURE,
                duration_ms=(time.perf_counter() - started) * 1000,
                error_category="internal_error",
            )
            raise RelayError("internal relay error") from None

    # ------------------------------------------------------------------
    @staticmethod
    def _duration_ms(started: float) -> float:
        return (time.perf_counter() - started) * 1000

    def _observe(self, stage: str, started: float, **fields: Any) -> None:
        """Send sanitized hop metadata to an optional observer.

        Observers are used by the interactive demo to visualise what each hop
        can and cannot see.  They are best-effort: a failing observer must
        never affect packet processing, and no plaintext or key material is
        ever included here.
        """
        if self.observer is None:
            return
        try:
            self.observer(
                {
                    "service_id": self.relay_id,
                    "service_type": "relay",
                    "role": self.role.value,
                    "stage": stage,
                    "duration_ms": round(self._duration_ms(started), 2),
                    **fields,
                }
            )
        except Exception:  # pragma: no cover - observer is optional instrumentation
            pass

    def _reject_replay(self, digest: str, started: float) -> None:
        if self.db.replay_exists(relay_id=self.relay_id, packet_digest=digest):
            self.events.emit(
                EventType.REPLAY_DETECTED,
                status=EventStatus.REJECTED,
                duration_ms=self._duration_ms(started),
                error_category="replay_detected",
                detail=safe_detail(role=self.role.value),
            )
            self._observe("rejected", started, error_category="replay_detected")
            raise ReplayDetectedError("replayed packet")

    def _check_recipient(self, envelope: OnionEnvelope, started: float) -> None:
        if envelope.recipient_key_id != self.key_id:
            self.events.emit(
                EventType.VALIDATION_FAILURE,
                status=EventStatus.REJECTED,
                duration_ms=self._duration_ms(started),
                error_category="key_mismatch",
                detail=safe_detail(role=self.role.value),
            )
            self._observe("rejected", started, error_category="key_mismatch")
            raise InvalidPacketError("packet is not addressed to this relay")

    def _decrypt(self, envelope: OnionEnvelope, started: float) -> dict[str, Any]:
        try:
            instruction = peel_layer(envelope, self.private_key, self.key_id)
        except AuthenticationError:
            self.events.emit(
                EventType.AUTHENTICATION_FAILURE,
                status=EventStatus.FAILURE,
                duration_ms=self._duration_ms(started),
                error_category="authentication_failed",
                detail=safe_detail(role=self.role.value),
            )
            self._observe("rejected", started, error_category="authentication_failed")
            raise InvalidPacketError("packet authentication failed") from None
        except (InvalidLayerError, OnionError, CryptoError):
            self.events.emit(
                EventType.DECRYPTION_FAILURE,
                status=EventStatus.FAILURE,
                duration_ms=self._duration_ms(started),
                error_category="decryption_failed",
                detail=safe_detail(role=self.role.value),
            )
            self._observe("rejected", started, error_category="decryption_failed")
            raise InvalidPacketError("packet could not be decrypted") from None

        self.events.emit(
            EventType.VALIDATION_SUCCESS,
            duration_ms=self._duration_ms(started),
            detail=safe_detail(role=self.role.value),
        )
        self.events.emit(
            EventType.DECRYPTION_SUCCESS,
            duration_ms=self._duration_ms(started),
            detail=safe_detail(role=self.role.value),
        )
        return instruction

    def _record_acceptance(self, digest: str, started: float) -> None:
        inserted = self.db.record_replay(
            relay_id=self.relay_id,
            packet_digest=digest,
            ttl_seconds=self.replay_ttl_seconds,
        )
        if not inserted:
            self.events.emit(
                EventType.REPLAY_DETECTED,
                status=EventStatus.REJECTED,
                duration_ms=self._duration_ms(started),
                error_category="replay_detected",
                detail=safe_detail(role=self.role.value),
            )
            self._observe("rejected", started, error_category="replay_detected")
            raise ReplayDetectedError("replayed packet")

    def _validate_instruction(self, instruction: dict[str, Any], started: float) -> str:
        try:
            kind = classify_instruction(instruction)
            if self.role == RelayRole.EXIT:
                if kind != "exit":
                    raise OnionError("exit relay received forwarding instruction")
                ExitInstruction.model_validate(instruction)
            else:
                if kind != "relay":
                    raise OnionError("non-exit relay received exit instruction")
                RelayInstruction.model_validate(instruction)
        except (OnionError, ValidationError):
            self.events.emit(
                EventType.VALIDATION_FAILURE,
                status=EventStatus.REJECTED,
                duration_ms=self._duration_ms(started),
                error_category="instruction_invalid",
                detail=safe_detail(role=self.role.value),
            )
            self._observe("rejected", started, error_category="instruction_invalid")
            raise InvalidPacketError("invalid routing instruction") from None

        if kind == "relay":
            self._observe("decrypted", started, instruction="relay", next_hop_id=instruction["next_hop_id"])
        else:
            self._observe("decrypted", started, instruction="exit", receiver_id=instruction["receiver_id"])
        return kind

    async def _forward(self, instruction: dict[str, Any], digest: str, started: float) -> RelayResult:
        validated = RelayInstruction.model_validate(instruction)
        try:
            target_url = self.registry.relay_url(validated.next_hop_id)
        except UnknownPeerError:
            self.events.emit(
                EventType.VALIDATION_FAILURE,
                status=EventStatus.REJECTED,
                error_category="unknown_peer",
                detail=safe_detail(role=self.role.value),
            )
            self._observe("rejected", started, error_category="unknown_peer")
            raise InvalidPacketError("unknown next hop") from None

        try:
            response = await self.forwarder.post_json(
                relay_url(target_url),
                validated.envelope.model_dump(),
            )
            if response.get("status") not in {"forwarded", "delivered"}:
                raise TransportError("downstream did not accept the packet")
        except TransportError:
            self.events.emit(
                EventType.DELIVERY_FAILURE,
                status=EventStatus.FAILURE,
                duration_ms=(time.perf_counter() - started) * 1000,
                error_category="transport_error",
                detail=safe_detail(role=self.role.value, hop=self.validated_hop(validated)),
            )
            self._observe("failed", started, error_category="transport_error")
            raise ForwardingError("downstream relay unavailable") from None

        duration = (time.perf_counter() - started) * 1000
        self.events.emit(
            EventType.PACKET_FORWARDED,
            duration_ms=duration,
            detail=safe_detail(role=self.role.value, hop=self.validated_hop(validated)),
        )
        self._observe("forwarded", started, next_hop_id=validated.next_hop_id)
        return RelayResult(
            status="forwarded",
            duration_ms=round(duration, 2),
            packet_digest=digest,
            next_hop=validated.next_hop_id,
        )

    async def _deliver(self, instruction: dict[str, Any], digest: str, started: float) -> RelayResult:
        exit_instruction = ExitInstruction.model_validate(instruction)
        try:
            target_url = self.registry.receiver_url(exit_instruction.receiver_id)
        except UnknownPeerError:
            self.events.emit(
                EventType.VALIDATION_FAILURE,
                status=EventStatus.REJECTED,
                error_category="unknown_peer",
                detail=safe_detail(role=self.role.value),
            )
            self._observe("rejected", started, error_category="unknown_peer")
            raise InvalidPacketError("unknown receiver") from None

        try:
            response = await self.forwarder.post_json(
                receive_url(target_url),
                exit_instruction.message.model_dump(),
            )
            if response.get("status") != "delivered":
                raise TransportError("receiver did not confirm delivery")
        except TransportError:
            self.events.emit(
                EventType.DELIVERY_FAILURE,
                status=EventStatus.FAILURE,
                duration_ms=(time.perf_counter() - started) * 1000,
                error_category="transport_error",
                detail=safe_detail(role=self.role.value),
            )
            self._observe("failed", started, error_category="transport_error")
            raise ForwardingError("receiver unavailable") from None

        duration = (time.perf_counter() - started) * 1000
        self.events.emit(EventType.DELIVERY_SUCCESS, duration_ms=duration, detail=safe_detail(role=self.role.value))
        self._observe("delivered", started, receiver_id=exit_instruction.receiver_id)
        return RelayResult(
            status="delivered",
            duration_ms=round(duration, 2),
            packet_digest=digest,
            next_hop=exit_instruction.receiver_id,
        )

    @staticmethod
    def validated_hop(instruction: RelayInstruction) -> str:
        # Logical identifier only; never log the configured URL.
        return instruction.next_hop_id
