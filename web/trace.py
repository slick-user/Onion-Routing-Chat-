"""Per-request circuit tracing for the interactive demo.

The relay and receiver services accept an optional observer callback.  The web
layer installs a callback that appends sanitized hop metadata to a
``ContextVar`` scoped to the current request, so a single ``POST /api/send``
can render the whole journey without exposing plaintext or key material.

The observer never runs for the production/CLI services because it defaults to
``None`` and is only supplied by the web runtime.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterator

_current: ContextVar[list[dict[str, Any]] | None] = ContextVar("onionchat_trace", default=None)


def record(event: dict[str, Any]) -> None:
    """Append a hop event to the active trace, if one is being captured."""
    events = _current.get()
    if events is not None:
        events.append(dict(event))


@contextmanager
def capture() -> Iterator[list[dict[str, Any]]]:
    """Collect observer events emitted while the context manager is active."""
    events: list[dict[str, Any]] = []
    token = _current.set(events)
    try:
        yield events
    finally:
        _current.reset(token)
