"""Mailbox service: the receiver for chat messages.

Relay C delivers here. The mailbox cannot decrypt anything: it stores the
ciphertext for the right user and notifies their open browser tabs.
It learns who a message is for, but not the text or the sender.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException

from config.settings import settings
from crypto.onion import canonical_json
from networking.limits import BodySizeLimitMiddleware
from networking.schemas import DeliveryResponse, E2EEnvelope, HealthResponse
from networking.traffic_policy import strip_padding
from observability.events import EventRecorder, EventStatus, EventType, safe_detail
from storage.chat_store import ChatStore
from storage.database import Database

MAILBOX_ID = "mailbox"


class ChatHub:
    """Sends live events to connected WebSocket clients (one queue per tab)."""

    def __init__(self) -> None:
        self._queues: dict[str, set[asyncio.Queue]] = defaultdict(set)

    def connect(self, user_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._queues[user_id].add(queue)
        return queue

    def disconnect(self, user_id: str, queue: asyncio.Queue) -> None:
        self._queues[user_id].discard(queue)
        if not self._queues[user_id]:
            del self._queues[user_id]

    def online_users(self) -> set[str]:
        return set(self._queues)

    def publish(self, user_id: str, event: dict[str, Any]) -> None:
        for queue in list(self._queues.get(user_id, ())):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass

    def broadcast(self, event: dict[str, Any]) -> None:
        for user_id in list(self._queues):
            self.publish(user_id, event)


def create_mailbox_app(
    *,
    store: ChatStore,
    hub: ChatHub,
    db: Database,
    observer: Callable[[dict[str, Any]], None] | None = None,
) -> FastAPI:
    events = EventRecorder(db, service_id=MAILBOX_ID, service_type="receiver")

    def _observe(stage: str, **fields: Any) -> None:
        if observer is None:
            return
        try:
            observer({"service_id": MAILBOX_ID, "service_type": "receiver", "stage": stage, **fields})
        except Exception:  # pragma: no cover - observer is optional instrumentation
            pass

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        events.emit(EventType.STARTUP)
        yield
        events.emit(EventType.SHUTDOWN)

    app = FastAPI(title="OnionChat Mailbox", version="1.0.0", lifespan=lifespan)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_packet_bytes)

    @app.get("/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        return HealthResponse(status="healthy", service_id=MAILBOX_ID, service_type="receiver")

    @app.post("/receive", response_model=DeliveryResponse)
    async def receive(envelope: E2EEnvelope) -> DeliveryResponse:
        started = time.perf_counter()
        events.emit(EventType.PACKET_RECEIVED)
        _observe("received", packet_bytes=len(canonical_json(envelope.model_dump())))

        user = store.user_by_key_id(envelope.recipient_key_id)
        if user is None:
            events.emit(
                EventType.VALIDATION_FAILURE,
                status=EventStatus.REJECTED,
                duration_ms=(time.perf_counter() - started) * 1000,
                error_category="unknown_recipient",
            )
            _observe("rejected", error_category="unknown_recipient")
            raise HTTPException(status_code=400, detail="Invalid message envelope")

        # Store the ciphertext as-is (minus the throw-away padding).
        stored = store.store(user_id=user["user_id"], envelope=strip_padding(envelope.model_dump()))
        hub.publish(user["user_id"], {"type": "message", **stored})

        duration = (time.perf_counter() - started) * 1000
        events.emit(EventType.DELIVERY_SUCCESS, duration_ms=duration, detail=safe_detail(stored="ciphertext"))
        _observe("stored", recipient=user["user_id"], encrypted=True, duration_ms=round(duration, 2))
        return DeliveryResponse(status="delivered", detail="stored encrypted", message_id=stored["id"])

    return app


__all__ = ["ChatHub", "MAILBOX_ID", "create_mailbox_app"]
