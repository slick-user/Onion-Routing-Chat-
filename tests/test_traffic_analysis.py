"""Traffic-analysis defences (padding, mixing) and the simulated observer."""

from __future__ import annotations

import asyncio
import random

import httpx
import pytest

from adversary.traffic_analysis import (
    EntryObservation,
    ExitObservation,
    accuracy,
    run_traffic_analysis,
    size_attack,
    timing_attack,
)
from config.settings import settings
from networking.traffic_policy import (
    PacketTooLargeError,
    TrafficPolicy,
    pad_to_cell,
    random_filler,
    strip_padding,
    wire_size,
)
from web.app import create_web_app
from web.runtime import WebRuntime

CELL = settings.cell_bytes


@pytest.fixture(scope="module")
def keys_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("ta-keys")


@pytest.fixture()
def runtime(tmp_path, keys_dir):
    return WebRuntime.build(keys_dir=keys_dir, db_dir=tmp_path / "db", key_bits=2048)


def call(app, method, path, payload=None):
    async def run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://web.test") as client:
            return await client.request(method, path, json=payload)

    return asyncio.run(run())


# Padding helpers
def test_pad_to_cell_gives_exact_size_and_random_filler():
    packet = {"version": 1, "ciphertext": "QUJD"}
    first = pad_to_cell(packet, 1024)
    second = pad_to_cell(packet, 1024)
    assert wire_size(first) == wire_size(second) == 1024
    assert first["padding"] != second["padding"]  # random, not a fixed pattern
    assert strip_padding(first) == packet


def test_pad_to_cell_rejects_packets_that_do_not_fit():
    with pytest.raises(PacketTooLargeError):
        pad_to_cell({"ciphertext": "A" * 2000}, 1024)


def test_random_filler_length():
    for length in (0, 1, 3, 4, 1000):
        assert len(random_filler(length)) == length


def test_policy_off_removes_padding():
    policy = TrafficPolicy(cell_bytes=None)
    assert "padding" not in policy.prepare_for_wire({"a": "b", "padding": "QUJD"})


# Padding in the real circuit
def _hop_sizes(trace):
    relays = [
        event["packet_bytes"]
        for event in trace
        if event["stage"] == "received" and event["service_type"] == "relay"
    ]
    bob = [
        event["packet_bytes"]
        for event in trace
        if event["stage"] == "received" and event["service_type"] == "receiver"
    ]
    return relays + bob


def test_every_link_carries_one_cell_when_padding_is_on(runtime):
    runtime.policy.cell_bytes = CELL
    result = asyncio.run(runtime.deliver("short"))
    assert _hop_sizes(result["trace"]) == [CELL, CELL, CELL, CELL]
    assert result["message_id"] is not None


def test_sizes_shrink_and_leak_position_without_padding(runtime):
    runtime.policy.cell_bytes = None
    sizes = _hop_sizes(asyncio.run(runtime.deliver("short"))["trace"])
    assert sizes == sorted(sizes, reverse=True)
    assert len(set(sizes)) == 4


def test_replay_with_fresh_padding_is_still_rejected(runtime):
    runtime.policy.cell_bytes = CELL
    packet = runtime.sender.build_packet("replay me")
    first_status, _ = asyncio.run(runtime.submit_packet(packet))
    # The attacker re-pads the captured packet so its bytes look different.
    repadded = pad_to_cell(packet, CELL)
    assert repadded["padding"] != packet["padding"]
    second_status, body = asyncio.run(runtime.submit_packet(repadded))
    assert first_status == 200
    assert second_status == 409, body


def test_tampering_with_padding_does_not_break_delivery(runtime):
    runtime.policy.cell_bytes = CELL
    packet = runtime.sender.build_packet("padding is not part of the message")
    packet["padding"] = random_filler(len(packet["padding"]))
    status, _ = asyncio.run(runtime.submit_packet(packet))
    assert status == 200


def test_message_too_long_for_a_cell_is_refused_clearly(tmp_path, keys_dir):
    runtime = WebRuntime.build(keys_dir=keys_dir, db_dir=tmp_path / "db", key_bits=2048)
    app = create_web_app(runtime)
    # 4000 two-byte characters need more than one 18 KiB cell.
    response = call(app, "POST", "/api/send", {"message": "é" * 4000})
    assert response.status_code == 400
    assert "fixed-size cell" in response.json()["detail"]


def test_mixing_delay_is_applied_and_reported(runtime):
    runtime.policy.cell_bytes = CELL
    runtime.policy.mix_delay_ms = 40
    trace = asyncio.run(runtime.deliver("mixed"))["trace"]
    delays = [event["mix_delay_ms"] for event in trace if event["stage"] in {"forwarded", "delivered"}]
    assert len(delays) == 3
    assert all(0 <= delay <= 40 for delay in delays)


# Attack functions on synthetic observations
def _observations(sizes, exit_sizes, exit_order):
    entries = [EntryObservation(sender=f"u{i}", time=float(i), size=size) for i, size in enumerate(sizes)]
    exits = [
        ExitObservation(time=float(position), size=exit_sizes[user], true_sender=f"u{user}")
        for position, user in enumerate(exit_order)
    ]
    return entries, exits


def test_size_attack_wins_when_sizes_differ():
    entries, exits = _observations([100, 400, 200, 300], [10, 40, 20, 30], [2, 0, 3, 1])
    assert accuracy(size_attack(entries, exits, random.Random(1)), exits) == 1.0


def test_size_attack_is_only_guessing_when_all_sizes_match():
    rng = random.Random(3)
    scores = []
    for _ in range(200):
        entries, exits = _observations([500] * 6, [500] * 6, list(range(6)))
        scores.append(accuracy(size_attack(entries, exits, rng), exits))
    assert sum(scores) / len(scores) < 0.35  # a blind guess averages 1/6 ≈ 0.17


def test_timing_attack_wins_on_first_in_first_out():
    entries, exits = _observations([1] * 5, [1] * 5, [0, 1, 2, 3, 4])
    assert accuracy(timing_attack(entries, exits, random.Random(1)), exits) == 1.0


def test_timing_attack_fails_when_order_is_shuffled():
    entries, exits = _observations([1] * 4, [1] * 4, [3, 2, 1, 0])
    assert accuracy(timing_attack(entries, exits, random.Random(1)), exits) == 0.0


# Full experiment
def test_experiment_shows_each_defence_stops_its_attack(runtime):
    runtime.policy.cell_bytes = CELL
    runtime.policy.mix_delay_ms = 0
    before = runtime.dbs[runtime.receiver_id].count_messages(receiver_id=runtime.receiver_id)

    async def run():
        async with runtime.operation_lock:
            return await run_traffic_analysis(runtime, senders=4, rounds=2, mix_delay_ms=150, seed=11)

    result = asyncio.run(run())
    rows = {row["id"]: row for row in result["scenarios"]}

    assert rows["no_defence"]["size_attack_accuracy"] == 1.0
    assert rows["no_defence"]["timing_attack_accuracy"] == 1.0
    assert rows["padding"]["timing_attack_accuracy"] == 1.0
    assert all(link["avg_bytes"] == CELL for link in rows["padding"]["link_bytes"])
    assert rows["padding_mixing"]["avg_latency_ms"] > rows["padding"]["avg_latency_ms"]
    assert rows["padding"]["bytes_per_message"] > rows["no_defence"]["bytes_per_message"]

    # The experiment restores the live policy and leaves Bob's inbox untouched.
    assert (runtime.policy.cell_bytes, runtime.policy.mix_delay_ms) == (CELL, 0)
    assert runtime.dbs[runtime.receiver_id].count_messages(receiver_id=runtime.receiver_id) == before


def test_api_runs_experiment_and_rate_limits(runtime):
    app = create_web_app(runtime)
    payload = {"senders": 3, "rounds": 1, "mix_delay_ms": 20}
    first = call(app, "POST", "/api/traffic-analysis", payload)
    assert first.status_code == 200
    body = first.json()
    assert [row["id"] for row in body["scenarios"]] == ["no_defence", "padding", "padding_mixing"]
    assert "[experiment]" not in first.text  # no message plaintext in the results
    assert call(app, "POST", "/api/traffic-analysis", payload).status_code == 429
    assert call(app, "POST", "/api/traffic-analysis", {"senders": 50}).status_code == 422
    assert call(app, "GET", "/api/traffic-policy").json()["padding"] is True
