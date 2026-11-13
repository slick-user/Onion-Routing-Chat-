"""Onion packet construction and one-layer-at-a-time processing."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

from Crypto.PublicKey import RSA
from pydantic import ValidationError

from crypto.encryption import (
    AuthenticationError,
    CryptoError,
    PROTOCOL_VERSION,
    _b64decode,
    _b64encode,
    build_aad,
    decrypt_aes_gcm,
    decrypt_message_e2e,
    encrypt_aes_gcm,
    encrypt_message_e2e,
    generate_session_key,
    unwrap_key,
    wrap_key,
)
from networking.schemas import OnionEnvelope

RELAY_INSTRUCTION_KEYS = {"next_hop_id", "envelope"}
EXIT_INSTRUCTION_KEYS = {"receiver_id", "message"}


class OnionError(Exception):
    """Base class for onion construction/processing failures."""


class InvalidLayerError(OnionError):
    """Raised when a layer is not addressed to the expected relay."""


def canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def packet_digest(envelope: Mapping[str, Any] | OnionEnvelope) -> str:
    """Relay-local replay digest of the exact packet envelope.

    The digest is not a global packet identifier: it is scoped to a relay in
    the replay database.  We hash the canonical envelope representation rather
    than logging or storing the packet itself.
    """
    if isinstance(envelope, OnionEnvelope):
        data = envelope.model_dump()
    else:
        data = dict(envelope)
    return hashlib.sha256(canonical_json(data)).hexdigest()


def seal_layer(
    instruction: Mapping[str, Any],
    recipient_key_id: str,
    public_key: RSA.RsaKey,
    version: int = PROTOCOL_VERSION,
) -> dict[str, Any]:
    """Create one authenticated onion layer for a relay."""
    plaintext = canonical_json(dict(instruction))
    session_key = generate_session_key()
    aad = build_aad("onion", version, recipient_key_id)
    encrypted = encrypt_aes_gcm(plaintext, session_key, aad)
    wrapped = wrap_key(session_key, public_key)
    return {
        "version": version,
        "recipient_key_id": recipient_key_id,
        "wrapped_key": _b64encode(wrapped),
        "nonce": encrypted["nonce"],
        "ciphertext": encrypted["ciphertext"],
        "tag": encrypted["tag"],
    }


def peel_layer(
    envelope: Mapping[str, Any] | OnionEnvelope,
    private_key: RSA.RsaKey,
    expected_key_id: str,
) -> dict[str, Any]:
    """Validate and decrypt exactly one onion layer.

    Returns the decrypted routing instruction.  Raises ``InvalidLayerError``
    for packets addressed to another relay and ``CryptoError`` subclasses for
    malformed or unauthenticated data.
    """
    try:
        parsed = envelope if isinstance(envelope, OnionEnvelope) else OnionEnvelope.model_validate(envelope)
    except ValidationError as exc:
        raise OnionError("invalid onion envelope") from exc

    if parsed.version != PROTOCOL_VERSION:
        raise InvalidLayerError("unsupported onion version")
    if parsed.recipient_key_id != expected_key_id:
        raise InvalidLayerError("layer is addressed to a different relay")

    try:
        wrapped = _b64decode(parsed.wrapped_key, "wrapped_key")
        session_key = unwrap_key(wrapped, private_key)
        aad = build_aad("onion", parsed.version, parsed.recipient_key_id)
        plaintext = decrypt_aes_gcm(
            nonce=parsed.nonce,
            ciphertext=parsed.ciphertext,
            tag=parsed.tag,
            key=session_key,
            aad=aad,
        )
        instruction = json.loads(plaintext.decode("utf-8"))
    except AuthenticationError:
        raise
    except CryptoError:
        raise
    except (ValueError, UnicodeDecodeError, TypeError) as exc:
        raise OnionError("invalid onion payload") from exc

    if not isinstance(instruction, dict):
        raise OnionError("onion instruction must be an object")
    return instruction


def classify_instruction(instruction: Mapping[str, Any]) -> str:
    """Return ``relay`` or ``exit`` for a decrypted instruction."""
    keys = set(instruction.keys())
    if keys == EXIT_INSTRUCTION_KEYS:
        return "exit"
    if keys == RELAY_INSTRUCTION_KEYS:
        return "relay"
    raise OnionError("unknown instruction shape")


def build_onion(
    *,
    message: str | bytes,
    receiver_id: str,
    receiver_key_id: str,
    receiver_public_key: RSA.RsaKey,
    relay_path: Sequence[str],
    relay_public_keys: Mapping[str, RSA.RsaKey],
    relay_key_ids: Mapping[str, str],
) -> dict[str, Any]:
    """Build an onion packet from the inside out.

    ``relay_path`` is ordered from entry to exit, e.g.
    ``["relay-a", "relay-b", "relay-c"]``.
    """
    path = list(relay_path)
    if not path:
        raise ValueError("relay path must not be empty")
    if len(set(path)) != len(path):
        raise ValueError("relay path must not contain duplicates")
    for relay_id in path:
        if relay_id not in relay_public_keys:
            raise ValueError(f"missing public key for relay: {relay_id}")
        if relay_id not in relay_key_ids:
            raise ValueError(f"missing key id for relay: {relay_id}")

    e2e_envelope = encrypt_message_e2e(message, receiver_public_key, receiver_key_id)
    envelope: dict[str, Any] = {}

    for index in range(len(path) - 1, -1, -1):
        relay_id = path[index]
        if index == len(path) - 1:
            instruction: dict[str, Any] = {
                "receiver_id": receiver_id,
                "message": e2e_envelope,
            }
        else:
            instruction = {
                "next_hop_id": path[index + 1],
                "envelope": envelope,
            }
        envelope = seal_layer(
            instruction,
            recipient_key_id=relay_key_ids[relay_id],
            public_key=relay_public_keys[relay_id],
        )

    return envelope


def decrypt_e2e_from_exit(instruction: Mapping[str, Any], private_key: RSA.RsaKey, expected_key_id: str) -> bytes:
    """Decrypt the receiver envelope (used by the receiver service/tests)."""
    message = instruction.get("message")
    if not isinstance(message, Mapping):
        raise OnionError("missing end-to-end message")
    return decrypt_message_e2e(message, private_key, expected_key_id)
