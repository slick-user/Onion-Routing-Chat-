"""In-process network used by the hosted demo and the tests.

All services run in one process but still talk real HTTP through
httpx.ASGITransport. Only registered URLs can be reached.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI

from networking.transport import TransportError


class InProcessNetwork:
    """Async forwarder that dispatches trusted registry URLs to ASGI apps."""

    def __init__(self) -> None:
        self.apps: dict[str, FastAPI] = {}
        # Taps see every packet sent (url, payload) but cannot change it. Used by adversary/.
        self.taps: list[Callable[[str, dict[str, Any]], None]] = []

    def register(self, base_url: str, app: FastAPI) -> None:
        self.apps[base_url.rstrip("/")] = app

    def _app_for(self, url: str) -> tuple[str, FastAPI, str]:
        parts = urlsplit(url)
        base = f"{parts.scheme}://{parts.netloc}"
        app = self.apps.get(base)
        if app is None:
            raise TransportError("unknown in-process endpoint")
        return base, app, parts.path

    async def _request(
        self,
        method: str,
        url: str,
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        base, app, path = self._app_for(url)
        if method == "POST" and payload is not None:
            for tap in list(self.taps):
                tap(url, payload)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url=base) as client:
            if method == "POST":
                response = await client.post(path, json=payload)
            else:
                response = await client.get(path)
        if response.status_code >= 400:
            raise TransportError(f"in-process endpoint returned status {response.status_code}")
        body = response.json()
        if not isinstance(body, dict):
            raise TransportError("in-process endpoint returned non-object")
        return body

    async def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._request("POST", url, payload)

    async def get_json(self, url: str) -> dict[str, Any]:
        return await self._request("GET", url)
