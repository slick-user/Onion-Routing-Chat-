"""In-process ASGI transport for demo and test deployments.

The real services always talk HTTP: relays POST to trusted registry URLs and
the receiver answers on its own endpoint.  When the whole topology runs inside
one process (the hosted demo and the test-suite) we still want that same HTTP
boundary, so this module implements a small forwarder that dispatches trusted
registry URLs to mounted ASGI applications with ``httpx.ASGITransport``.

Only URLs registered explicitly through :meth:`InProcessNetwork.register` can
be reached; packet contents can never introduce a new endpoint.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import httpx

from fastapi import FastAPI

from networking.transport import TransportError


class InProcessNetwork:
    """Async forwarder that dispatches trusted registry URLs to ASGI apps."""

    def __init__(self) -> None:
        self.apps: dict[str, FastAPI] = {}

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
