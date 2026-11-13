"""Defences against traffic analysis: fixed-size cells and mixing delays.

Padding makes every packet the same size on every link, so its size no longer
shows the hop position or the message length. Mixing makes each relay wait a
random time before forwarding, so packets do not leave in arrival order.
"""

from __future__ import annotations

import asyncio
import base64
import os
import secrets
from dataclasses import dataclass
from typing import Any

from crypto.onion import canonical_json

PADDING_FIELD = "padding"

# Uses the operating system's secure random generator, like the crypto code.
_random = secrets.SystemRandom()


class PacketTooLargeError(ValueError):
    """The packet does not fit into one fixed-size cell (message too long)."""


def wire_size(packet: dict[str, Any]) -> int:
    """Number of bytes an observer sees for this packet on the wire."""
    return len(canonical_json(packet))


def strip_padding(packet: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of the packet without its padding field."""
    return {key: value for key, value in packet.items() if key != PADDING_FIELD}


def random_filler(length: int) -> str:
    """Random base64 text of exactly `length` characters."""
    if length <= 0:
        return ""
    raw = os.urandom(length)  # base64 makes it ~4/3 longer, so this is plenty
    return base64.b64encode(raw).decode("ascii")[:length]


def pad_to_cell(packet: dict[str, Any], cell_bytes: int) -> dict[str, Any]:
    """Add padding so the packet is exactly ``cell_bytes`` bytes on the wire."""
    unpadded = strip_padding(packet)
    # Size of the packet with an *empty* padding field: the JSON key and quotes
    # are part of the cell too.
    base_size = wire_size({**unpadded, PADDING_FIELD: ""})
    if base_size > cell_bytes:
        raise PacketTooLargeError(
            f"packet needs {base_size} bytes but a cell holds {cell_bytes}; send a shorter message"
        )
    padded = {**unpadded, PADDING_FIELD: random_filler(cell_bytes - base_size)}
    assert wire_size(padded) == cell_bytes  # base64 characters are 1 byte each in JSON
    return padded


@dataclass
class TrafficPolicy:
    """Padding and mixing settings shared by the sender and all relays.

    cell_bytes=None turns padding off; mix_delay_ms=0 turns mixing off.
    """

    cell_bytes: int | None = None
    mix_delay_ms: int = 0

    @property
    def padding_enabled(self) -> bool:
        return self.cell_bytes is not None

    def prepare_for_wire(self, packet: dict[str, Any]) -> dict[str, Any]:
        """Pad the packet if padding is on; otherwise drop any old padding."""
        if self.cell_bytes is None:
            return strip_padding(packet)
        return pad_to_cell(packet, self.cell_bytes)

    async def mix(self) -> float:
        """Wait a random 0..mix_delay_ms milliseconds. Returns the delay used."""
        if self.mix_delay_ms <= 0:
            return 0.0
        delay_ms = _random.uniform(0, self.mix_delay_ms)
        await asyncio.sleep(delay_ms / 1000)
        return delay_ms

    def describe(self) -> dict[str, Any]:
        return {
            "padding": self.padding_enabled,
            "cell_bytes": self.cell_bytes,
            "mix_delay_ms": self.mix_delay_ms,
        }


__all__ = [
    "PADDING_FIELD",
    "PacketTooLargeError",
    "TrafficPolicy",
    "pad_to_cell",
    "random_filler",
    "strip_padding",
    "wire_size",
]
