"""Web frontend: the single-page UI, JSON API and security headers."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from config.settings import settings
from crypto.keyring import KeyRingError
from networking.traffic_policy import PacketTooLargeError
from networking.transport import TransportError
from web.chat import create_chat_router
from web.runtime import ATTACK_NAMES, KeyActionThrottled, WebRuntime

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

MAX_MESSAGE_CHARS = 4000
TRAFFIC_EXPERIMENT_COOLDOWN_SECONDS = 5.0

ATTACK_INFO: dict[str, dict[str, Any]] = {
    "tamper": {
        "title": "Tamper with the ciphertext",
        "expected": 400,
        "explanation": (
            "A single changed ciphertext byte breaks the AES-256-GCM authentication tag. "
            "Relay A rejects the packet before it can forward anything."
        ),
    },
    "replay": {
        "title": "Replay the exact same packet",
        "expected": 409,
        "explanation": (
            "The first submission succeeds. The second is rejected because the relay-scoped "
            "replay cache already contains the packet digest."
        ),
    },
    "wrong_key": {
        "title": "Address a packet to the wrong relay",
        "expected": 400,
        "explanation": (
            "Relay A checks the packet's recipient key id before decrypting. A packet labelled "
            "for Relay B is refused instead of being probed."
        ),
    },
    "wrong_layer": {
        "title": "Send an exit instruction to the entry relay",
        "expected": 400,
        "explanation": (
            "Each relay validates the instruction shape for its role. An entry relay must see a "
            "forwarding instruction, not a receiver delivery instruction."
        ),
    },
    "unknown_next_hop": {
        "title": "Put a URL in the next-hop field (SSRF attempt)",
        "expected": 400,
        "explanation": (
            "Packet contents may only contain logical peer IDs. The URL is not in the local "
            "registry, so no outbound request is made to the attacker's endpoint."
        ),
    },
    "unknown_receiver": {
        "title": "Deliver to an unregistered receiver",
        "expected": 400,
        "explanation": (
            "The exit relay resolves the receiver ID through its trusted local registry. An "
            "unknown identity cannot redirect the message."
        ),
    },
    "oversized": {
        "title": "Send an oversized packet",
        "expected": 413,
        "explanation": (
            "The ASGI body-size middleware checks Content-Length (and streams) before parsing. "
            "Oversized requests are dropped with HTTP 413."
        ),
    },
}


class SendRequest(BaseModel):
    message: str = Field(min_length=1, max_length=MAX_MESSAGE_CHARS)


class AttackRequest(BaseModel):
    attack: str = Field(min_length=1, max_length=64)


KEY_ID_PATTERN = r"^[a-z0-9][a-z0-9-]{0,63}$"


class KeyServiceRequest(BaseModel):
    service_id: str = Field(min_length=1, max_length=64, pattern=KEY_ID_PATTERN)


class KeyRequest(KeyServiceRequest):
    key_id: str = Field(min_length=1, max_length=64, pattern=KEY_ID_PATTERN)


class TrafficAnalysisRequest(BaseModel):
    senders: int = Field(default=6, ge=3, le=10)
    rounds: int = Field(default=3, ge=1, le=5)
    mix_delay_ms: int = Field(default=250, ge=0, le=1000)


class RevokeRequest(KeyRequest):
    reason: str = Field(default="manual revocation", max_length=120)


def _security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; connect-src 'self'; font-src 'self'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'",
    )
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


def create_web_app(runtime: WebRuntime | None = None) -> FastAPI:
    runtime = runtime or WebRuntime.build()

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    app = FastAPI(
        title="OnionChat — Interactive Onion Routing",
        version="1.0.0",
        description=(
            "A visual, end-to-end demonstration of three-hop onion routing with "
            "AES-256-GCM layers and RSA-OAEP key transport."
        ),
    )
    app.state.runtime = runtime
    app.state.last_experiment = float("-inf")
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(create_chat_router(runtime))

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        return _security_headers(response)

    @app.exception_handler(Exception)
    async def unhandled_exception(_: Request, __: Exception) -> JSONResponse:
        # Never expose internals to the browser.
        return JSONResponse(status_code=500, content={"detail": "Internal demo error"})

    # Pages
    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "relays": [
                    {
                        "id": relay_id,
                        "role": settings.relay_role(relay_id),
                        "label": relay_id.replace("-", " ").title(),
                    }
                    for relay_id in ("relay-a", "relay-b", "relay-c")
                ],
                "receiver_id": settings.receiver.service_id,
                "max_message_chars": MAX_MESSAGE_CHARS,
                "max_packet_kib": settings.max_packet_bytes // 1024,
                "replay_ttl_seconds": settings.replay_ttl_seconds,
                "key_grace_seconds": settings.key_grace_seconds,
                "attacks": [
                    {
                        "id": attack_id,
                        "title": info["title"],
                        "explanation": info["explanation"],
                        "expected": info["expected"],
                    }
                    for attack_id, info in ATTACK_INFO.items()
                ],
            },
        )

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "healthy",
            "service": "onionchat-web",
            "relays": 3,
            "receiver": settings.receiver.service_id,
        }

    # JSON API
    @app.get("/api/overview")
    async def overview() -> dict[str, Any]:
        receiver_db = runtime.dbs[runtime.receiver_id]
        return {
            "services": await runtime.status_snapshot(),
            "keys": runtime.key_metadata(),
            "counts": {
                "messages": receiver_db.count_messages(receiver_id=runtime.receiver_id),
            },
            "topology": {
                "relays": [
                    {"id": relay_id, "role": settings.relay_role(relay_id)}
                    for relay_id in ("relay-a", "relay-b", "relay-c")
                ],
                "receiver_id": runtime.receiver_id,
            },
            "limits": {
                "max_message_chars": MAX_MESSAGE_CHARS,
                "max_packet_bytes": settings.max_packet_bytes,
                "replay_ttl_seconds": settings.replay_ttl_seconds,
            },
        }

    @app.post("/api/send")
    async def send(payload: SendRequest) -> dict[str, Any]:
        if not payload.message.strip():
            raise HTTPException(status_code=400, detail="Message must not be empty")
        try:
            result = await runtime.deliver(payload.message)
        except TransportError:
            raise HTTPException(status_code=502, detail="A relay was unavailable") from None
        except PacketTooLargeError:
            raise HTTPException(
                status_code=400, detail="Message is too long to fit in one fixed-size cell"
            ) from None
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="Could not construct the onion packet") from None
        return result

    @app.get("/api/messages")
    async def messages(limit: int = 20) -> dict[str, Any]:
        receiver_db = runtime.dbs[runtime.receiver_id]
        return {
            "messages": runtime.recent_messages(limit=max(1, min(limit, 100))),
            "total": receiver_db.count_messages(receiver_id=runtime.receiver_id),
        }

    @app.get("/api/events")
    async def events(service: str | None = None, limit: int = 40) -> dict[str, Any]:
        known = set(runtime.dbs)
        if service is not None and service not in known:
            raise HTTPException(status_code=400, detail="Unknown service")
        return {"events": runtime.recent_events(service_id=service, limit=max(1, min(limit, 200)))}

    @app.post("/api/attack")
    async def attack(payload: AttackRequest) -> dict[str, Any]:
        if payload.attack not in ATTACK_NAMES:
            raise HTTPException(status_code=400, detail="Unknown attack")
        try:
            result = await runtime.run_attack(payload.attack)
        except TransportError:
            raise HTTPException(status_code=502, detail="A service was unavailable") from None
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="Could not build the attack packet") from None

        info = ATTACK_INFO[payload.attack]
        result.update(
            {
                "title": info["title"],
                "expected": info["expected"],
                "explanation": info["explanation"],
                "blocked": int(result["status_code"]) >= 400,
                "events": runtime.recent_events(limit=12),
            }
        )
        return result

    # Traffic analysis (global passive observer)
    @app.get("/api/traffic-policy")
    async def traffic_policy() -> dict[str, Any]:
        return runtime.policy.describe()

    @app.post("/api/traffic-analysis")
    async def traffic_analysis(payload: TrafficAnalysisRequest) -> dict[str, Any]:
        # The experiment sends dozens of real onions, so limit how often it runs.
        now = time.monotonic()
        if now - app.state.last_experiment < TRAFFIC_EXPERIMENT_COOLDOWN_SECONDS:
            raise HTTPException(
                status_code=429, detail="The experiment is cooling down; try again shortly"
            ) from None
        app.state.last_experiment = now
        try:
            return await runtime.traffic_analysis(
                senders=payload.senders,
                rounds=payload.rounds,
                mix_delay_ms=payload.mix_delay_ms,
            )
        except TransportError:
            raise HTTPException(status_code=502, detail="A service was unavailable") from None

    # Key lifecycle
    @app.get("/api/keys")
    async def keys() -> dict[str, Any]:
        return {
            "services": runtime.key_lifecycle(),
            "grace_seconds": settings.key_grace_seconds,
        }

    @app.post("/api/keys/rotate")
    async def rotate_key(payload: KeyServiceRequest) -> dict[str, Any]:
        try:
            result = await runtime.rotate_key(payload.service_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="Unknown service") from None
        except KeyActionThrottled:
            raise HTTPException(status_code=429, detail="Please wait a moment between key actions") from None
        return {**result, "services": runtime.key_lifecycle()}

    @app.post("/api/keys/revoke")
    async def revoke_key(payload: RevokeRequest) -> dict[str, Any]:
        reason = " ".join(payload.reason.split()) or "manual revocation"
        try:
            result = await runtime.revoke_key(payload.service_id, payload.key_id, reason)
        except KeyError:
            raise HTTPException(status_code=404, detail="Unknown service") from None
        except KeyActionThrottled:
            raise HTTPException(status_code=429, detail="Please wait a moment between key actions") from None
        except KeyRingError as exc:
            detail = "Key is already revoked" if "already" in str(exc) else "Unknown key"
            raise HTTPException(status_code=409 if "already" in str(exc) else 404, detail=detail) from None
        return {**result, "services": runtime.key_lifecycle()}

    @app.post("/api/keys/probe")
    async def probe_key(payload: KeyRequest) -> dict[str, Any]:
        try:
            result = await runtime.probe_key(payload.service_id, payload.key_id)
        except (KeyError, KeyRingError):
            raise HTTPException(status_code=404, detail="Unknown service or key") from None
        return result

    @app.post("/api/reset")
    async def reset() -> dict[str, Any]:
        return {"status": "reset", "cleared": runtime.reset()}

    return app


__all__ = ["ATTACK_INFO", "create_web_app"]
