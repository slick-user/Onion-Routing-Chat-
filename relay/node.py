"""FastAPI relay node service."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException

from config.settings import settings
from crypto.keyring import KeyRing
from networking.limits import BodySizeLimitMiddleware
from networking.schemas import HealthResponse, OnionEnvelope, RelayStatusResponse
from observability.events import EventRecorder, EventStatus, EventType
from relay.registry import PeerRegistry
from relay.router import (
    Forwarder,
    ForwardingError,
    InvalidPacketError,
    RelayError,
    RelayObserver,
    RelayProcessor,
    RelayRole,
    ReplayDetectedError,
)
from storage.database import Database


def _relay_failure_counts(db: Database, relay_id: str) -> int:
    return sum(
        db.count_events(service_id=relay_id, event_type=event.value, status=EventStatus.FAILURE.value)
        + db.count_events(service_id=relay_id, event_type=event.value, status=EventStatus.REJECTED.value)
        for event in (
            EventType.VALIDATION_FAILURE,
            EventType.DECRYPTION_FAILURE,
            EventType.AUTHENTICATION_FAILURE,
            EventType.DELIVERY_FAILURE,
            EventType.INTERNAL_ERROR,
        )
    )


def create_relay_app(
    *,
    relay_id: str,
    role: RelayRole,
    registry: PeerRegistry,
    db: Database,
    forwarder: Forwarder,
    replay_ttl_seconds: int | None = None,
    observer: RelayObserver | None = None,
    private_key: Any = None,
    key_id: str | None = None,
    keyring: KeyRing | None = None,
) -> FastAPI:
    ttl = replay_ttl_seconds if replay_ttl_seconds is not None else settings.replay_ttl_seconds
    events = EventRecorder(db, service_id=relay_id, service_type="relay")
    processor = RelayProcessor(
        relay_id=relay_id,
        role=role,
        private_key=private_key,
        key_id=key_id,
        keyring=keyring,
        registry=registry,
        db=db,
        events=events,
        forwarder=forwarder,
        replay_ttl_seconds=ttl,
        observer=observer,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        events.emit(EventType.STARTUP, detail=f"role={role.value}")
        try:
            yield
        finally:
            events.emit(EventType.SHUTDOWN, detail=f"role={role.value}")

    app = FastAPI(
        title=f"OnionChat Relay {relay_id}",
        version="1.0.0",
        description=f"Educational onion-routing {role.value} node.",
        lifespan=lifespan,
    )
    app.state.relay_id = relay_id
    app.state.role = role
    app.state.keyring = processor.keyring
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_packet_bytes)

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        events.emit(EventType.HEALTH_CHECK, detail="status=healthy")
        return HealthResponse(status="healthy", service_id=relay_id, service_type="relay")

    @app.get("/status", response_model=RelayStatusResponse)
    async def status() -> RelayStatusResponse:
        return RelayStatusResponse(
            service_id=relay_id,
            packets_received=db.count_events(service_id=relay_id, event_type=EventType.PACKET_RECEIVED.value),
            packets_forwarded=db.count_events(
                service_id=relay_id, event_type=EventType.PACKET_FORWARDED.value
            ),
            packets_delivered=db.count_events(
                service_id=relay_id, event_type=EventType.DELIVERY_SUCCESS.value
            ),
            packets_failed=_relay_failure_counts(db, relay_id),
            replays_detected=db.count_events(service_id=relay_id, event_type=EventType.REPLAY_DETECTED.value),
        )

    @app.post("/relay")
    async def relay(envelope: OnionEnvelope) -> dict[str, Any]:
        try:
            result = await processor.process(envelope)
        except ReplayDetectedError:
            raise HTTPException(status_code=409, detail="Duplicate packet rejected") from None
        except InvalidPacketError:
            raise HTTPException(status_code=400, detail="Invalid onion packet") from None
        except ForwardingError:
            raise HTTPException(status_code=502, detail="Relay forwarding failed") from None
        except RelayError:
            raise HTTPException(status_code=500, detail="Internal relay error") from None

        return {
            "status": result.status,
            "relay": relay_id,
            "processing_ms": result.duration_ms,
        }

    return app
