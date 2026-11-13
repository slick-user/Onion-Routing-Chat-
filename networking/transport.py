"""Async HTTP transport with explicit timeouts and no redirect following."""

from __future__ import annotations

from typing import Any

import httpx

from config.settings import settings


class TransportError(Exception):
    """Raised when an inter-service HTTP request fails."""


class JsonForwarder:
    """Posts JSON to trusted registry URLs (never to URLs taken from a packet)."""

    def __init__(self, timeout_seconds: float | None = None):
        self.timeout_seconds = (
            timeout_seconds if timeout_seconds is not None else settings.request_timeout_seconds
        )

    async def post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        timeout = httpx.Timeout(self.timeout_seconds)
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.post(url, json=payload)
        except httpx.HTTPError as exc:
            raise TransportError("upstream service unavailable") from exc

        if response.status_code < 200 or response.status_code >= 300:
            raise TransportError(f"upstream returned status {response.status_code}")

        try:
            body = response.json()
        except ValueError as exc:
            raise TransportError("upstream returned non-JSON response") from exc

        if not isinstance(body, dict):
            raise TransportError("upstream returned unexpected response shape")
        return body

    async def get_json(self, url: str) -> dict[str, Any]:
        timeout = httpx.Timeout(self.timeout_seconds)
        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = await client.get(url)
        except httpx.HTTPError as exc:
            raise TransportError("service unavailable") from exc
        if response.status_code < 200 or response.status_code >= 300:
            raise TransportError(f"service returned status {response.status_code}")
        try:
            body = response.json()
        except ValueError as exc:
            raise TransportError("service returned non-JSON response") from exc
        if not isinstance(body, dict):
            raise TransportError("service returned unexpected response shape")
        return body


def relay_url(base_url: str) -> str:
    return base_url.rstrip("/") + "/relay"


def receive_url(base_url: str) -> str:
    return base_url.rstrip("/") + "/receive"


def health_url(base_url: str) -> str:
    return base_url.rstrip("/") + "/health"


def status_url(base_url: str) -> str:
    return base_url.rstrip("/") + "/status"
