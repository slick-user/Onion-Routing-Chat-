"""ASGI entry point for ``uvicorn web.asgi:app``.

Keeping application construction here means importing :mod:`web.app` (for
tests or reuse) never generates keys or opens the demo databases as a side
effect.
"""

from __future__ import annotations

from web.app import create_web_app

app = create_web_app()

__all__ = ["app"]
