from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from config.settings import settings


def _b64ish(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError("must be a non-empty base64 string")
    if len(value) > settings.max_field_chars:
        raise ValueError("field too large")
    # Allow standard base64 chars, padding, and URL-safe just in case; decoder will validate strictly later.
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")
    if any(c not in allowed for c in value):
        raise ValueError("invalid base64 characters")
    return value


class OnionEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    version: Literal[1]
    recipient_key_id: str = Field(min_length=1, max_length=128)
    wrapped_key: str = Field(min_length=1)
    nonce: str = Field(min_length=1)
    ciphertext: str = Field(min_length=1)
    tag: str = Field(min_length=1)

    @field_validator("wrapped_key", "nonce", "ciphertext", "tag")
    @classmethod
    def validate_b64_fields(cls, v: str) -> str:
        return _b64ish(v)


class E2EEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    version: Literal[1]
    recipient_key_id: str = Field(min_length=1, max_length=128)
    wrapped_key: str = Field(min_length=1)
    nonce: str = Field(min_length=1)
    ciphertext: str = Field(min_length=1)
    tag: str = Field(min_length=1)

    @field_validator("wrapped_key", "nonce", "ciphertext", "tag")
    @classmethod
    def validate_b64_fields(cls, v: str) -> str:
        return _b64ish(v)


class RelayInstruction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    next_hop_id: str = Field(min_length=1, max_length=128)
    envelope: OnionEnvelope


class ExitInstruction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    receiver_id: str = Field(min_length=1, max_length=128)
    message: E2EEnvelope


class RelayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    envelope: OnionEnvelope


class ReceiveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sender_hint: Optional[str] = Field(default=None, max_length=128)
    message: E2EEnvelope


class HealthResponse(BaseModel):
    status: str
    service_id: str
    service_type: str


class RelayStatusResponse(BaseModel):
    service_id: str
    packets_received: int = 0
    packets_forwarded: int = 0
    packets_delivered: int = 0
    packets_failed: int = 0
    replays_detected: int = 0


class DeliveryResponse(BaseModel):
    status: str
    detail: Optional[str] = None
    message_id: Optional[int] = None


class ReceiverStatusResponse(BaseModel):
    service_id: str
    messages_received: int = 0
    messages_failed: int = 0


class SendResult(BaseModel):
    status: str
    detail: Optional[str] = None
    response: Optional[dict[str, Any]] = None
