"""Locally configured allowlists for relay and receiver destinations.

Incoming onion instructions contain logical peer identifiers only.  This
registry maps those identifiers to trusted endpoints, preventing packets from
turning relays into an SSRF proxy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import urlsplit


class UnknownPeerError(Exception):
    """Raised when a packet references a peer outside the local registry."""


def _validate_endpoint(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ValueError("invalid configured endpoint")
    if parts.username or parts.password:
        raise ValueError("endpoint must not contain credentials")
    return url.rstrip("/")


@dataclass(frozen=True)
class PeerRegistry:
    relay_urls: Mapping[str, str] = field(default_factory=dict)
    receiver_urls: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "relay_urls",
            {key: _validate_endpoint(value) for key, value in self.relay_urls.items()},
        )
        object.__setattr__(
            self,
            "receiver_urls",
            {key: _validate_endpoint(value) for key, value in self.receiver_urls.items()},
        )

    def relay_url(self, relay_id: str) -> str:
        try:
            return self.relay_urls[relay_id]
        except KeyError as exc:
            raise UnknownPeerError("unknown relay") from exc

    def receiver_url(self, receiver_id: str) -> str:
        try:
            return self.receiver_urls[receiver_id]
        except KeyError as exc:
            raise UnknownPeerError("unknown receiver") from exc

    def known_relays(self) -> tuple[str, ...]:
        return tuple(self.relay_urls.keys())

    def known_receivers(self) -> tuple[str, ...]:
        return tuple(self.receiver_urls.keys())
