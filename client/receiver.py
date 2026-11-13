"""Receiver service: authenticate, decrypt and store end-to-end messages."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import Any, Callable

from fastapi import FastAPI, HTTPException

from config.settings import settings
from crypto.encryption import AuthenticationError, CryptoError, decrypt_message_e2e
from networking.limits import BodySizeLimitMiddleware
from networking.schemas import DeliveryResponse, E2EEnvelope, HealthResponse, ReceiverStatusResponse
from observability.events import EventRecorder, EventStatus, EventType, safe_detail
from storage.database import Database


def create_receiver_app(
    *,
    receiver_id: str,
    private_key: Any,
    key_id: str,
    db: Database,
    observer: Callable[[dict[str, Any]], None] | None = None,
) -> FastAPI:
    events = EventRecorder(db, service_id=receiver_id, service_type="receiver")

    def _observe(stage: str, **fields: Any) -> None:
        if observer is None:
            return
        try:
            observer(
                {
                    "service_id": receiver_id,
                    "service_type": "receiver",
                    "stage": stage,
                    **fields,
                }
            )
        except Exception:  # pragma: no cover - observer is optional instrumentation
            pass

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        events.emit(EventType.STARTUP)
        try:
            yield
        finally:
            events.emit(EventType.SHUTDOWN)

    app = FastAPI(
        title=f"OnionChat Receiver {receiver_id}",
        version="1.0.0",
        description="Educational onion-routing message receiver.",
        lifespan=lifespan,
    )
    app.state.receiver_id = receiver_id
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_packet_bytes)

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        events.emit(EventType.HEALTH_CHECK, detail="status=healthy")
        return HealthResponse(status="healthy", service_id=receiver_id, service_type="receiver")

    @app.get("/status", response_model=ReceiverStatusResponse)
    async def status() -> ReceiverStatusResponse:
        failures = sum(
            db.count_events(
                service_id=receiver_id,
                event_type=event.value,
                status=status_value,
            )
            for event in (
                EventType.VALIDATION_FAILURE,
                EventType.DECRYPTION_FAILURE,
                EventType.AUTHENTICATION_FAILURE,
                EventType.DELIVERY_FAILURE,
                EventType.INTERNAL_ERROR,
            )
            for status_value in (EventStatus.FAILURE.value, EventStatus.REJECTED.value)
        )
        return ReceiverStatusResponse(
            service_id=receiver_id,
            messages_received=db.count_messages(receiver_id=receiver_id),
            messages_failed=failures,
        )

    @app.post("/receive", response_model=DeliveryResponse)
    async def receive(envelope: E2EEnvelope) -> DeliveryResponse:
        started = time.perf_counter()
        events.emit(EventType.PACKET_RECEIVED)
        _observe("received", recipient_key_id=envelope.recipient_key_id)

        if envelope.recipient_key_id != key_id:
            events.emit(
                EventType.VALIDATION_FAILURE,
                status=EventStatus.REJECTED,
                duration_ms=(time.perf_counter() - started) * 1000,
                error_category="key_mismatch",
            )
            _observe("rejected", error_category="key_mismatch")
            raise HTTPException(status_code=400, detail="Invalid message envelope")

        events.emit(EventType.VALIDATION_SUCCESS)

        try:
            plaintext = decrypt_message_e2e(envelope.model_dump(), private_key, key_id)
        except AuthenticationError:
            events.emit(
                EventType.AUTHENTICATION_FAILURE,
                status=EventStatus.FAILURE,
                duration_ms=(time.perf_counter() - started) * 1000,
                error_category="authentication_failed",
            )
            _observe("rejected", error_category="authentication_failed")
            raise HTTPException(status_code=400, detail="Message authentication failed") from None
        except CryptoError:
            events.emit(
                EventType.DECRYPTION_FAILURE,
                status=EventStatus.FAILURE,
                duration_ms=(time.perf_counter() - started) * 1000,
                error_category="decryption_failed",
            )
            _observe("rejected", error_category="decryption_failed")
            raise HTTPException(status_code=400, detail="Message could not be decrypted") from None

        events.emit(EventType.DECRYPTION_SUCCESS)
        _observe("decrypted")

        try:
            message = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            events.emit(
                EventType.VALIDATION_FAILURE,
                status=EventStatus.REJECTED,
                duration_ms=(time.perf_counter() - started) * 1000,
                error_category="invalid_payload",
            )
            _observe("rejected", error_category="invalid_payload")
            raise HTTPException(status_code=400, detail="Invalid message payload") from None

        try:
            message_id = db.insert_message(receiver_id=receiver_id, message=message)
        except Exception:
            events.emit(
                EventType.DELIVERY_FAILURE,
                status=EventStatus.FAILURE,
                duration_ms=(time.perf_counter() - started) * 1000,
                error_category="storage_error",
            )
            _observe("failed", error_category="storage_error")
            raise HTTPException(status_code=500, detail="Message storage failed") from None

        events.emit(
            EventType.DELIVERY_SUCCESS,
            duration_ms=(time.perf_counter() - started) * 1000,
            detail=safe_detail(message_id=message_id),
        )
        _observe(
            "stored",
            message_id=message_id,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
        )
        return DeliveryResponse(status="delivered", detail="message stored", message_id=message_id)

    return app
