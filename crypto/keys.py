"""RSA key generation, import/export and secure on-disk storage.

The project uses RSA-3072 keys for relay and receiver key pairs.  Private
key files are written with mode ``0600`` and key directories with ``0700``.
This module intentionally does not log key material.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Mapping

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

DEFAULT_BITS = 3072
MIN_BITS = 2048


class KeyStoreError(Exception):
    """Raised when a key cannot be generated, loaded or safely stored."""


def generate_keypair(bits: int = DEFAULT_BITS) -> dict[str, bytes]:
    """Generate an RSA key pair and return PEM encoded private/public keys."""
    if bits < MIN_BITS:
        raise ValueError(f"RSA key size must be at least {MIN_BITS} bits")
    key = RSA.generate(bits)
    return {
        "private_key": key.export_key(format="PEM", pkcs=8),
        "public_key": key.publickey().export_key(format="PEM"),
    }


def _secure_makedirs(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass


def _write_atomic(path: Path, data: bytes, mode: int) -> None:
    _secure_makedirs(path.parent)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def save_keypair(keypair: Mapping[str, bytes], directory: str | Path, name: str) -> tuple[Path, Path]:
    """Persist a key pair with secure permissions.

    Returns ``(private_path, public_path)``.
    """
    path = Path(directory)
    _secure_makedirs(path)

    private_path = path / f"{name}_private.pem"
    public_path = path / f"{name}_public.pem"

    _write_atomic(private_path, bytes(keypair["private_key"]), 0o600)
    _write_atomic(public_path, bytes(keypair["public_key"]), 0o644)
    return private_path, public_path


def load_private_key(path: str | Path, enforce_permissions: bool = True) -> RSA.RsaKey:
    """Load a private key, tightening file permissions when possible."""
    key_path = Path(path)
    try:
        if enforce_permissions:
            mode = key_path.stat().st_mode & 0o777
            if mode & 0o077:
                os.chmod(key_path, 0o600)
        return RSA.import_key(key_path.read_bytes())
    except (OSError, ValueError, IndexError, TypeError) as exc:
        raise KeyStoreError(f"Unable to load private key: {key_path.name}") from exc


def load_public_key(path: str | Path) -> RSA.RsaKey:
    """Load a public key from disk."""
    key_path = Path(path)
    try:
        return RSA.import_key(key_path.read_bytes()).publickey()
    except (OSError, ValueError, IndexError, TypeError) as exc:
        raise KeyStoreError(f"Unable to load public key: {key_path.name}") from exc


def import_public_key(pem: bytes | str) -> RSA.RsaKey:
    return RSA.import_key(pem).publickey()


def import_private_key(pem: bytes | str) -> RSA.RsaKey:
    return RSA.import_key(pem)


def export_public_key(key: RSA.RsaKey) -> bytes:
    return key.publickey().export_key(format="PEM")


def export_private_key(key: RSA.RsaKey) -> bytes:
    return key.export_key(format="PEM", pkcs=8)


def key_fingerprint(key: RSA.RsaKey) -> str:
    """Return a short, non-secret fingerprint usable as a key identifier."""
    der = key.publickey().export_key(format="DER")
    return SHA256.new(der).hexdigest()[:16]


def generate_service_keys(
    keys_dir: str | Path,
    names: Mapping[str, str] | None = None,
    bits: int = DEFAULT_BITS,
    force: bool = False,
) -> dict[str, tuple[Path, Path]]:
    """Generate key pairs for a set of logical service names.

    ``names`` maps a service name to a key identifier.  Returns a mapping of
    service name to ``(private_path, public_path)``.
    """
    if names is None:
        names = {
            "relay-a": "relay-a-key",
            "relay-b": "relay-b-key",
            "relay-c": "relay-c-key",
            "receiver-bob": "receiver-bob-key",
        }

    results: dict[str, tuple[Path, Path]] = {}
    for name in names:
        private_path = Path(keys_dir) / f"{name}_private.pem"
        public_path = Path(keys_dir) / f"{name}_public.pem"
        if not force and private_path.exists() and public_path.exists():
            results[name] = (private_path, public_path)
            continue
        results[name] = save_keypair(generate_keypair(bits), keys_dir, name)
    return results
