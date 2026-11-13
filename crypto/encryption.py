"""Authenticated encryption and key-wrapping primitives.

Two independent encryption domains are used:

* ``onion`` layers, one AES-256-GCM key per relay layer, wrapped with that
  relay's RSA-OAEP public key.
* ``e2e`` message encryption between sender and receiver, wrapped with the
  receiver's RSA-OAEP public key.

AES keys are never reused between the two domains.
"""

from __future__ import annotations

import base64
import json
from typing import Any, Mapping

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

AES_KEY_BYTES = 32
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
PROTOCOL_VERSION = 1


class CryptoError(Exception):
    """Base class for cryptographic failures (never exposes internals)."""


class AuthenticationError(CryptoError):
    """Raised when AEAD authentication fails or input is malformed."""


class KeyWrapError(CryptoError):
    """Raised when RSA-OAEP key transport fails."""


def generate_session_key() -> bytes:
    return get_random_bytes(AES_KEY_BYTES)


def build_aad(domain: str, version: int, key_id: str) -> bytes:
    """Bind protocol version, domain and recipient key id into the AEAD tag."""
    return f"onionchat:{domain}:v{version}:{key_id}".encode("utf-8")


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise AuthenticationError(f"invalid base64 in {field}") from exc


def encrypt_aes_gcm(plaintext: bytes, key: bytes, aad: bytes = b"") -> dict[str, str]:
    """Encrypt bytes with AES-256-GCM using a fresh 96-bit nonce."""
    if len(key) != AES_KEY_BYTES:
        raise CryptoError("invalid AES key length")
    nonce = get_random_bytes(GCM_NONCE_BYTES)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_BYTES)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
        "tag": _b64encode(tag),
    }


def decrypt_aes_gcm(
    *,
    nonce: str,
    ciphertext: str,
    tag: str,
    key: bytes,
    aad: bytes = b"",
) -> bytes:
    """Decrypt and authenticate AES-256-GCM data."""
    if len(key) != AES_KEY_BYTES:
        raise CryptoError("invalid AES key length")

    nonce_bytes = _b64decode(nonce, "nonce")
    ciphertext_bytes = _b64decode(ciphertext, "ciphertext")
    tag_bytes = _b64decode(tag, "tag")

    if len(nonce_bytes) != GCM_NONCE_BYTES or len(tag_bytes) != GCM_TAG_BYTES:
        raise AuthenticationError("invalid AES-GCM parameters")

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_bytes, mac_len=GCM_TAG_BYTES)
    cipher.update(aad)
    try:
        return cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes)
    except ValueError as exc:
        raise AuthenticationError("message authentication failed") from exc


# Backwards-compatible helpers used by earlier scaffold code.
def encrypt(data: bytes, key: bytes, aad: bytes = b"") -> dict[str, str]:
    return encrypt_aes_gcm(data, key, aad)


def decrypt(envelope: Mapping[str, str], key: bytes, aad: bytes = b"") -> bytes:
    return decrypt_aes_gcm(
        nonce=envelope["nonce"],
        ciphertext=envelope["ciphertext"],
        tag=envelope["tag"],
        key=key,
        aad=aad,
    )


def wrap_key(key: bytes, public_key: RSA.RsaKey) -> bytes:
    """Wrap an AES session key with RSA-OAEP (SHA-256)."""
    try:
        cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
        return cipher.encrypt(key)
    except (ValueError, TypeError) as exc:
        raise KeyWrapError("key wrapping failed") from exc


def unwrap_key(wrapped: bytes, private_key: RSA.RsaKey) -> bytes:
    """Recover an AES session key from RSA-OAEP ciphertext."""
    try:
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        return cipher.decrypt(wrapped)
    except (ValueError, TypeError) as exc:
        raise KeyWrapError("key unwrapping failed") from exc


def _canonical_json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def encrypt_message_e2e(
    message: str | bytes,
    receiver_public_key: RSA.RsaKey,
    receiver_key_id: str,
    version: int = PROTOCOL_VERSION,
) -> dict[str, Any]:
    """Encrypt a message for the receiver (inner end-to-end layer)."""
    if isinstance(message, str):
        plaintext = message.encode("utf-8")
    else:
        plaintext = bytes(message)

    session_key = generate_session_key()
    aad = build_aad("e2e", version, receiver_key_id)
    encrypted = encrypt_aes_gcm(plaintext, session_key, aad)
    wrapped = wrap_key(session_key, receiver_public_key)
    return {
        "version": version,
        "recipient_key_id": receiver_key_id,
        "wrapped_key": _b64encode(wrapped),
        "nonce": encrypted["nonce"],
        "ciphertext": encrypted["ciphertext"],
        "tag": encrypted["tag"],
    }


def decrypt_message_e2e(
    envelope: Mapping[str, Any],
    receiver_private_key: RSA.RsaKey,
    expected_key_id: str,
) -> bytes:
    """Decrypt and authenticate an end-to-end message envelope."""
    version = int(envelope.get("version", 0))
    key_id = str(envelope.get("recipient_key_id", ""))
    if version != PROTOCOL_VERSION:
        raise CryptoError("unsupported protocol version")
    if key_id != expected_key_id:
        raise CryptoError("recipient key mismatch")

    wrapped = _b64decode(str(envelope.get("wrapped_key", "")), "wrapped_key")
    session_key = unwrap_key(wrapped, receiver_private_key)
    aad = build_aad("e2e", version, key_id)
    return decrypt_aes_gcm(
        nonce=str(envelope.get("nonce", "")),
        ciphertext=str(envelope.get("ciphertext", "")),
        tag=str(envelope.get("tag", "")),
        key=session_key,
        aad=aad,
    )
