from __future__ import annotations

import pytest

from tests.helpers import build_stack, generate_test_keypairs


@pytest.fixture(scope="session")
def private_pems() -> dict[str, bytes]:
    return generate_test_keypairs(bits=2048)


@pytest.fixture(scope="session")
def key_material(private_pems):
    from tests.helpers import key_material_from_pem

    return key_material_from_pem(private_pems)


@pytest.fixture()
def stack(tmp_path, private_pems):
    return build_stack(tmp_path=tmp_path, private_pems=private_pems)


@pytest.fixture()
def short_replay_stack(tmp_path, private_pems):
    return build_stack(tmp_path=tmp_path, private_pems=private_pems, replay_ttl_seconds=1)
