from __future__ import annotations

import os

import pytest

from crypto.encryption import (
    AuthenticationError,
    CryptoError,
    KeyWrapError,
    build_aad,
    decrypt_aes_gcm,
    decrypt_message_e2e,
    encrypt_aes_gcm,
    encrypt_message_e2e,
    generate_session_key,
    unwrap_key,
    wrap_key,
)
from crypto.keys import (
    generate_keypair,
    import_private_key,
    load_private_key,
    load_public_key,
    save_keypair,
)
from config.settings import settings


def test_default_keypair_is_rsa_3072():
    keypair = generate_keypair()
    key = import_private_key(keypair["private_key"])
    assert key.size_in_bits() == 3072


def test_keypair_rejects_small_keys():
    with pytest.raises(ValueError):
        generate_keypair(1024)


def test_save_and_load_keypair(tmp_path):
    keypair = generate_keypair(2048)
    private_path, public_path = save_keypair(keypair, tmp_path, "relay-x")

    assert private_path.exists() and public_path.exists()
    assert (private_path.stat().st_mode & 0o777) == 0o600
    assert (public_path.stat().st_mode & 0o777) == 0o644

    private_key = load_private_key(private_path)
    public_key = load_public_key(public_path)
    assert private_key.size_in_bits() == 2048
    assert public_key.size_in_bits() == 2048


def test_private_key_permissions_are_tightened(tmp_path):
    keypair = generate_keypair(2048)
    private_path, _ = save_keypair(keypair, tmp_path, "relay-y")
    os.chmod(private_path, 0o644)

    load_private_key(private_path)
    assert (private_path.stat().st_mode & 0o777) == 0o600


def test_aes_gcm_roundtrip():
    key = generate_session_key()
    aad = build_aad("e2e", 1, "receiver-key")
    plaintext = b"hello onionchat"

    envelope = encrypt_aes_gcm(plaintext, key, aad)
    recovered = decrypt_aes_gcm(
        nonce=envelope["nonce"],
        ciphertext=envelope["ciphertext"],
        tag=envelope["tag"],
        key=key,
        aad=aad,
    )
    assert recovered == plaintext
    assert envelope["nonce"] != encrypt_aes_gcm(plaintext, key, aad)["nonce"]


def test_aes_gcm_tampered_ciphertext_fails():
    key = generate_session_key()
    envelope = encrypt_aes_gcm(b"hello", key, b"aad")
    tampered = dict(envelope)
    data = list(tampered["ciphertext"])
    data[0] = "A" if data[0] != "A" else "B"
    tampered["ciphertext"] = "".join(data)

    with pytest.raises(AuthenticationError):
        decrypt_aes_gcm(**tampered, key=key, aad=b"aad")


def test_aes_gcm_tampered_tag_fails():
    key = generate_session_key()
    envelope = encrypt_aes_gcm(b"hello", key, b"aad")
    tampered = dict(envelope)
    tampered["tag"] = "AAAAAAAAAAAAAAAAAAAAAA=="

    with pytest.raises(AuthenticationError):
        decrypt_aes_gcm(**tampered, key=key, aad=b"aad")


def test_aes_gcm_wrong_aad_fails():
    key = generate_session_key()
    envelope = encrypt_aes_gcm(b"hello", key, b"aad-1")

    with pytest.raises(AuthenticationError):
        decrypt_aes_gcm(**envelope, key=key, aad=b"aad-2")


def test_rsa_oaep_wrap_and_unwrap(key_material):
    private_keys, public_keys = key_material
    session_key = generate_session_key()

    wrapped = wrap_key(session_key, public_keys["relay-a"])
    recovered = unwrap_key(wrapped, private_keys["relay-a"])
    assert recovered == session_key


def test_rsa_oaep_wrong_key_fails(key_material):
    _, public_keys = key_material
    private_keys, _ = key_material
    wrapped = wrap_key(generate_session_key(), public_keys["relay-a"])

    with pytest.raises(KeyWrapError):
        unwrap_key(wrapped, private_keys["relay-b"])


def test_e2e_message_roundtrip(key_material):
    private_keys, public_keys = key_material
    envelope = encrypt_message_e2e(
        "Hello Bob! This is an OnionChat test.",
        public_keys["receiver-bob"],
        settings.receiver_key_id,
    )
    recovered = decrypt_message_e2e(
        envelope,
        private_keys["receiver-bob"],
        settings.receiver_key_id,
    )
    assert recovered.decode() == "Hello Bob! This is an OnionChat test."


def test_e2e_rejects_wrong_key_id(key_material):
    private_keys, public_keys = key_material
    envelope = encrypt_message_e2e("secret", public_keys["receiver-bob"], settings.receiver_key_id)

    with pytest.raises(CryptoError):
        decrypt_message_e2e(envelope, private_keys["receiver-bob"], "different-key")


def test_e2e_rejects_tampered_ciphertext(key_material):
    private_keys, public_keys = key_material
    envelope = encrypt_message_e2e("secret", public_keys["receiver-bob"], settings.receiver_key_id)
    tampered = dict(envelope)
    tampered["ciphertext"] = tampered["ciphertext"][:-4] + "AAAA"

    with pytest.raises(CryptoError):
        decrypt_message_e2e(tampered, private_keys["receiver-bob"], settings.receiver_key_id)
