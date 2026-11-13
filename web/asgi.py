"""ASGI entry point: uvicorn web.asgi:app"""

from __future__ import annotations

from web.app import create_web_app

app = create_web_app()

__all__ = ["app"]
