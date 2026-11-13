"""Structured operational event emission (JSON logs + SQLite)."""

from __future__ import annotations

from enum import Enum
from typing import Any

from observability.logger import get_logger
from storage.database import Database


class EventType(str, Enum):
    STARTUP = "startup"
    SHUTDOWN = "shutdown"
    PACKET_RECEIVED = "packet_received"
    VALIDATION_SUCCESS = "validation_success"
    VALIDATION_FAILURE = "validation_failure"
    DECRYPTION_SUCCESS = "decryption_success"
    DECRYPTION_FAILURE = "decryption_failure"
    PACKET_FORWARDED = "packet_forwarded"
    DELIVERY_SUCCESS = "delivery_success"
    DELIVERY_FAILURE = "delivery_failure"
    AUTHENTICATION_FAILURE = "authentication_failure"
    REPLAY_DETECTED = "replay_detected"
    HEALTH_CHECK = "health_check"
    INTERNAL_ERROR = "internal_error"


class EventStatus(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    REJECTED = "rejected"


class EventRecorder:
    """Persist and log an operational event.

    Safety rules enforced by callers: never pass plaintext, keys, session
    keys, raw packets, client IPs or sensitive routing details in ``detail``.
    """

    def __init__(self, db: Database, *, service_id: str, service_type: str):
        self.db = db
        self.service_id = service_id
        self.service_type = service_type
        self.logger = get_logger(f"onionchat.{service_type}.{service_id}")

    def emit(
        self,
        event_type: EventType,
        *,
        status: EventStatus = EventStatus.SUCCESS,
        duration_ms: float | None = None,
        error_category: str | None = None,
        detail: str | None = None,
    ) -> str | None:
        event_value = event_type.value
        status_value = status.value
        duration = round(float(duration_ms), 2) if duration_ms is not None else None

        try:
            event_id = self.db.insert_event(
                service_id=self.service_id,
                service_type=self.service_type,
                event_type=event_value,
                status=status_value,
                duration_ms=duration,
                error_category=error_category,
                detail=detail,
            )
        except Exception:  # pragma: no cover - defensive logging path
            self.logger.error(
                "event_persistence_failed",
                extra={
                    "service_id": self.service_id,
                    "service_type": self.service_type,
                    "event_type": event_value,
                    "status": status_value,
                    "error_category": "storage_error",
                },
            )
            return None

        self.logger.info(
            event_value,
            extra={
                "service_id": self.service_id,
                "service_type": self.service_type,
                "event_type": event_value,
                "status": status_value,
                "duration_ms": duration,
                "error_category": error_category,
                "detail": detail,
            },
        )
        return event_id


def safe_detail(**fields: Any) -> str:
    """Build a short sanitized detail string from enumerated/operational values."""
    parts = [f"{key}={value}" for key, value in fields.items() if value is not None]
    return ",".join(parts)[:256]
