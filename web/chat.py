"""Chat API: directory, registration, sending, inbox and WebSocket.

Browsers build and decrypt messages themselves (onion-client.js); the server
only handles public keys and ciphertext. Sending needs no login on purpose,
so the server cannot link a packet to the person who sent it.
"""

from __future__ import annotations

import asyncio
import re
import secrets
from typing import TYPE_CHECKING, Any

from Crypto.PublicKey import RSA
from fastapi import APIRouter, Header, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field, ValidationError

from crypto.keys import export_public_key, key_fingerprint
from networking.schemas import OnionEnvelope
from storage.chat_store import DirectoryFullError

if TYPE_CHECKING:  # pragma: no cover
    from web.runtime import WebRuntime

NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,23}$")
MIN_USER_KEY_BITS = 2048
MAX_USER_KEY_BITS = 4096


class RegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=24)
    public_key_pem: str = Field(min_length=100, max_length=2000)


def _parse_public_key(pem: str) -> RSA.RsaKey:
    """Accept only a plain RSA *public* key of a sensible size."""
    try:
        key = RSA.import_key(pem)
    except (ValueError, IndexError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid public key") from None
    if key.has_private():
        # Someone pasted a private key: refuse rather than store it.
        raise HTTPException(status_code=400, detail="Send only the public key") from None
    if not MIN_USER_KEY_BITS <= key.size_in_bits() <= MAX_USER_KEY_BITS:
        raise HTTPException(status_code=400, detail="Key must be RSA 2048-4096 bits") from None
    return key


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing mailbox token")
    return authorization[len("Bearer ") :].strip()


def create_chat_router(runtime: "WebRuntime") -> APIRouter:
    router = APIRouter()
    store = runtime.chat_store
    hub = runtime.chat_hub

    def directory() -> dict[str, Any]:
        runtime.sync_keys()  # always advertise the current (post-rotation) relay keys
        online = hub.online_users()
        return {
            "relays": [
                {
                    "id": relay_id,
                    "key_id": runtime.key_ids[relay_id],
                    "public_key_pem": export_public_key(runtime.public_keys[relay_id]).decode("ascii"),
                }
                for relay_id in runtime.relay_ids
            ],
            "mailbox_id": runtime.mailbox_id,
            "cell_bytes": runtime.policy.cell_bytes,
            "users": [dict(user, online=user["user_id"] in online) for user in store.users()],
        }

    @router.get("/api/chat/directory")
    async def get_directory() -> dict[str, Any]:
        return directory()

    @router.post("/api/chat/register")
    async def register(payload: RegisterRequest) -> dict[str, Any]:
        name = " ".join(payload.name.split())
        if not NAME_PATTERN.match(name):
            raise HTTPException(status_code=400, detail="Use letters, numbers, spaces, '.', '-' or '_'")
        key = _parse_public_key(payload.public_key_pem)

        user_id = "u-" + secrets.token_hex(4)
        key_id = f"{user_id}-{key_fingerprint(key)[:8]}"
        pem = export_public_key(key).decode("ascii")
        try:
            token = store.register(name=name, key_id=key_id, public_key_pem=pem, user_id=user_id)
        except DirectoryFullError:
            raise HTTPException(status_code=503, detail="The demo directory is full") from None

        hub.broadcast({"type": "directory"})  # tell everyone a new user joined
        return {"user_id": user_id, "name": name, "key_id": key_id, "token": token}

    @router.post("/api/chat/send")
    async def send(packet: dict[str, Any]) -> dict[str, Any]:
        """Hand a browser-built onion to Relay A. The server cannot open it."""
        try:
            OnionEnvelope.model_validate(packet)
        except ValidationError:
            raise HTTPException(status_code=400, detail="Invalid onion packet") from None
        status_code, trace = await runtime.submit_chat_packet(packet)
        rejection = next((event for event in trace if event.get("stage") == "rejected"), None)
        return {
            "delivered": status_code < 400,
            "status_code": status_code,
            "rejected_by": rejection.get("service_id") if rejection else None,
            "error_category": rejection.get("error_category") if rejection else None,
            "trace": trace,
        }

    @router.get("/api/chat/inbox")
    async def inbox(
        user_id: str, after: int = 0, authorization: str | None = Header(default=None)
    ) -> dict[str, Any]:
        if not store.authenticate(user_id, _bearer(authorization)):
            raise HTTPException(status_code=401, detail="Invalid mailbox token")
        return {"messages": store.inbox(user_id=user_id, after_id=max(0, after))}

    @router.websocket("/ws/chat")
    async def live(websocket: WebSocket) -> None:
        """Push new mail and directory changes to one browser tab.

        The first message must be {"user_id": ..., "token": ...}; the token is sent
        inside the socket rather than in the URL so it does not end up in logs.
        """
        await websocket.accept()
        try:
            hello = await asyncio.wait_for(websocket.receive_json(), timeout=10)
            user_id, token = str(hello.get("user_id", "")), str(hello.get("token", ""))
        except Exception:
            await websocket.close(code=1008)
            return
        if not store.authenticate(user_id, token):
            await websocket.send_json({"type": "error", "detail": "Invalid mailbox token"})
            await websocket.close(code=1008)
            return

        queue = hub.connect(user_id)
        hub.broadcast({"type": "directory"})  # presence changed
        await websocket.send_json({"type": "ready"})
        try:
            while True:
                # Wait for either an event to push or the browser to go away.
                receive = asyncio.ensure_future(websocket.receive_text())
                event = asyncio.ensure_future(queue.get())
                done, pending = await asyncio.wait({receive, event}, return_when=asyncio.FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                if event in done:
                    await websocket.send_json(event.result())
                if receive in done:
                    receive.result()  # raises WebSocketDisconnect when the tab closes
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            hub.disconnect(user_id, queue)
            hub.broadcast({"type": "directory"})

    return router


__all__ = ["create_chat_router"]
