"""Per-request hop trace for the web demo.

Relays report safe metadata (stage, sizes, timings) to an observer; this
module collects it for the current request so the UI can show each hop.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

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
