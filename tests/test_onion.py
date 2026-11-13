from __future__ import annotations

import json

import pytest

from config.settings import settings
from crypto.encryption import AuthenticationError, CryptoError, decrypt_message_e2e
from crypto.onion import (
    InvalidLayerError,
    build_onion,
    classify_instruction,
    packet_digest,
    peel_layer,
)
from tests.helpers import RELAY_IDS

MESSAGE = "Hello Bob! This is an OnionChat test."


def _build(key_material, *, path=None, message=MESSAGE):
    _, public_keys = key_material
    return build_onion(
        message=message,
        receiver_id=settings.receiver.service_id,
        receiver_key_id=settings.receiver_key_id,
        receiver_public_key=public_keys[settings.receiver.service_id],
        relay_path=path or list(RELAY_IDS),
        relay_public_keys={relay_id: public_keys[relay_id] for relay_id in RELAY_IDS},
        relay_key_ids={relay_id: settings.relay_key_ids[relay_id] for relay_id in RELAY_IDS},
    )


def test_onion_construction_and_peeling(key_material):
    private_keys, _ = key_material
    envelope = _build(key_material)

    instruction_a = peel_layer(envelope, private_keys["relay-a"], settings.relay_key_ids["relay-a"])
    assert classify_instruction(instruction_a) == "relay"
    assert instruction_a["next_hop_id"] == "relay-b"

    instruction_b = peel_layer(
        instruction_a["envelope"], private_keys["relay-b"], settings.relay_key_ids["relay-b"]
    )
    assert classify_instruction(instruction_b) == "relay"
    assert instruction_b["next_hop_id"] == "relay-c"

    instruction_c = peel_layer(
        instruction_b["envelope"], private_keys["relay-c"], settings.relay_key_ids["relay-c"]
    )
    assert classify_instruction(instruction_c) == "exit"
    assert instruction_c["receiver_id"] == settings.receiver.service_id

    recovered = decrypt_message_e2e(
        instruction_c["message"],
        private_keys[settings.receiver.service_id],
        settings.receiver_key_id,
    )
    assert recovered.decode() == MESSAGE


def test_relay_layers_do_not_expose_plaintext(key_material):
    private_keys, _ = key_material
    envelope = _build(key_material)

    instruction_a = peel_layer(envelope, private_keys["relay-a"], settings.relay_key_ids["relay-a"])
    instruction_b = peel_layer(
        instruction_a["envelope"], private_keys["relay-b"], settings.relay_key_ids["relay-b"]
    )
    instruction_c = peel_layer(
        instruction_b["envelope"], private_keys["relay-c"], settings.relay_key_ids["relay-c"]
    )

    assert set(instruction_a) == {"next_hop_id", "envelope"}
    assert set(instruction_b) == {"next_hop_id", "envelope"}
    assert MESSAGE not in json.dumps(instruction_a)
    assert MESSAGE not in json.dumps(instruction_b)
    assert MESSAGE not in json.dumps(instruction_c)


def test_exit_relay_cannot_decrypt_end_to_end_message(key_material):
    private_keys, _ = key_material
    envelope = _build(key_material)
    instruction_a = peel_layer(envelope, private_keys["relay-a"], settings.relay_key_ids["relay-a"])
    instruction_b = peel_layer(
        instruction_a["envelope"], private_keys["relay-b"], settings.relay_key_ids["relay-b"]
    )
    instruction_c = peel_layer(
        instruction_b["envelope"], private_keys["relay-c"], settings.relay_key_ids["relay-c"]
    )

    with pytest.raises(CryptoError):
        decrypt_message_e2e(
            instruction_c["message"],
            private_keys["relay-c"],
            settings.receiver_key_id,
        )


def test_wrong_relay_key_id_is_rejected(key_material):
    private_keys, _ = key_material
    envelope = _build(key_material)

    with pytest.raises(InvalidLayerError):
        peel_layer(envelope, private_keys["relay-b"], settings.relay_key_ids["relay-b"])


def test_wrong_private_key_is_rejected(key_material):
    private_keys, _ = key_material
    envelope = _build(key_material)

    with pytest.raises(CryptoError):
        peel_layer(envelope, private_keys["relay-b"], settings.relay_key_ids["relay-a"])


def test_tampered_ciphertext_is_rejected(key_material):
    private_keys, _ = key_material
    envelope = _build(key_material)
    tampered = dict(envelope)
    tampered["ciphertext"] = tampered["ciphertext"][:-4] + "AAAA"

    with pytest.raises(AuthenticationError):
        peel_layer(tampered, private_keys["relay-a"], settings.relay_key_ids["relay-a"])


def test_tampered_wrapped_key_is_rejected(key_material):
    private_keys, _ = key_material
    envelope = _build(key_material)
    tampered = dict(envelope)
    tampered["wrapped_key"] = tampered["wrapped_key"][:-8] + "AAAAAAAA"

    with pytest.raises(CryptoError):
        peel_layer(tampered, private_keys["relay-a"], settings.relay_key_ids["relay-a"])


def test_build_onion_requires_known_keys(key_material):
    _, public_keys = key_material
    with pytest.raises(ValueError):
        build_onion(
            message="x",
            receiver_id=settings.receiver.service_id,
            receiver_key_id=settings.receiver_key_id,
            receiver_public_key=public_keys[settings.receiver.service_id],
            relay_path=["relay-a", "relay-missing"],
            relay_public_keys=public_keys,
            relay_key_ids={relay_id: settings.relay_key_ids[relay_id] for relay_id in RELAY_IDS},
        )


def test_build_onion_rejects_duplicate_hops(key_material):
    _, public_keys = key_material
    with pytest.raises(ValueError):
        build_onion(
            message="x",
            receiver_id=settings.receiver.service_id,
            receiver_key_id=settings.receiver_key_id,
            receiver_public_key=public_keys[settings.receiver.service_id],
            relay_path=["relay-a", "relay-a"],
            relay_public_keys=public_keys,
            relay_key_ids={relay_id: settings.relay_key_ids[relay_id] for relay_id in RELAY_IDS},
        )


def test_packet_digest_is_stable_and_sensitive(key_material):
    envelope = _build(key_material)
    first = packet_digest(envelope)
    second = packet_digest(dict(envelope))
    assert first == second

    changed = dict(envelope)
    changed["nonce"] = changed["nonce"][:-4] + "AAAA"
    assert packet_digest(changed) != first
    assert MESSAGE not in first
