"""Traffic-analysis attack by a global passive observer.

The observer sees the size and time of every packet on every link but cannot
decrypt anything. It tries to match each message that reaches Bob to its
sender, first by packet size and then by timing (first in, first out).
We run it with no defences, with fixed-size cells, and with cells plus mixing.
"""

from __future__ import annotations

import asyncio
import random
import statistics
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from crypto.encryption import decrypt_message_e2e
from networking.traffic_policy import wire_size
from networking.transport import relay_url

if TYPE_CHECKING:  # pragma: no cover - imported only for type hints
    from web.runtime import WebRuntime


# What the adversary observes
@dataclass
class EntryObservation:
    """A packet seen on a user's link into Relay A."""

    sender: str  # the adversary knows who is sending (e.g. their IP address)
    time: float  # seconds
    size: int  # bytes


@dataclass
class ExitObservation:
    """A packet seen on Relay C's link to Bob."""

    time: float
    size: int
    # Ground truth for scoring only. The attack functions never read it.
    true_sender: str = field(default="", repr=False)


# The two attacks (pure functions: easy to read and to unit-test)
def _match_by_rank(
    entries: list[EntryObservation],
    exits: list[ExitObservation],
    entry_key,
    exit_key,
    rng: random.Random,
) -> list[str]:
    """Pair the i-th smallest entry with the i-th smallest exit.

    Ties are broken randomly, otherwise equal sizes would fall back to time order.
    """
    shuffled_entries = entries[:]
    rng.shuffle(shuffled_entries)
    exit_order = list(range(len(exits)))
    rng.shuffle(exit_order)

    entries_sorted = sorted(shuffled_entries, key=entry_key)
    exits_sorted = sorted(exit_order, key=lambda index: exit_key(exits[index]))

    guesses = [""] * len(exits)
    for entry, exit_index in zip(entries_sorted, exits_sorted):
        guesses[exit_index] = entry.sender
    return guesses


def size_attack(
    entries: list[EntryObservation], exits: list[ExitObservation], rng: random.Random | None = None
) -> list[str]:
    """Guess the sender of each exit packet by matching packet sizes."""
    return _match_by_rank(entries, exits, lambda e: e.size, lambda x: x.size, rng or random.Random())


def timing_attack(
    entries: list[EntryObservation], exits: list[ExitObservation], rng: random.Random | None = None
) -> list[str]:
    """Guess the sender of each exit packet assuming first-in, first-out."""
    return _match_by_rank(entries, exits, lambda e: e.time, lambda x: x.time, rng or random.Random())


def accuracy(guesses: list[str], exits: list[ExitObservation]) -> float:
    """Fraction of exit packets whose sender was guessed correctly."""
    if not exits:
        return 0.0
    correct = sum(1 for guess, observed in zip(guesses, exits) if guess == observed.true_sender)
    return correct / len(exits)


# Configurations to compare
@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    padding: bool
    mix_delay_ms: int


def default_scenarios(mix_delay_ms: int = 250) -> list[Scenario]:
    return [
        Scenario("no_defence", "No defences", padding=False, mix_delay_ms=0),
        Scenario("padding", "Fixed-size cells", padding=True, mix_delay_ms=0),
        Scenario("padding_mixing", "Fixed-size cells + mixing", padding=True, mix_delay_ms=mix_delay_ms),
    ]


LINK_NAMES = {
    "relay-a": "Alice → Relay A",
    "relay-b": "Relay A → Relay B",
    "relay-c": "Relay B → Relay C",
    "receiver": "Relay C → Bob",
}


def _link_name(url: str) -> str:
    for marker, name in LINK_NAMES.items():
        if f"//{marker}." in url:
            return name
    return url


# Running the experiment on the real circuit
class _Experiment:
    """Runs rounds of traffic through ``runtime`` and records what a tap sees."""

    def __init__(self, runtime: "WebRuntime", senders: int, gap_ms: float, rng: random.Random):
        self.runtime = runtime
        self.senders = senders
        self.gap_ms = gap_ms
        self.rng = rng
        self.entry_url = relay_url(_entry_url(runtime))
        self.exits: list[ExitObservation] = []
        self.link_sizes: dict[str, list[int]] = {}
        self.receiver_key_id = runtime.key_ids[runtime.receiver_id]
        self.receiver_key = runtime.private_keys[runtime.receiver_id]

    # The wire tap: called by the network for every packet sent.
    def tap(self, url: str, payload: dict[str, Any]) -> None:
        size = wire_size(payload)
        self.link_sizes.setdefault(_link_name(url), []).append(size)
        if url.endswith("/receive"):
            self.exits.append(
                ExitObservation(time=time.perf_counter(), size=size, true_sender=self._referee(payload))
            )

    def _referee(self, payload: dict[str, Any]) -> str:
        """Decrypt with Bob's key to learn the true sender (scoring only)."""
        try:
            text = decrypt_message_e2e(payload, self.receiver_key, self.receiver_key_id).decode("utf-8")
        except Exception:
            return "unknown"
        # Messages look like "[experiment] from alice-3: xxxx"
        return text.split("from ", 1)[1].split(":", 1)[0] if "from " in text else "unknown"

    async def _send_one(self, sender: str, length: int, delay_s: float) -> tuple[EntryObservation, float]:
        message = f"[experiment] from {sender}: " + "x" * length
        packet = self.runtime.sender.build_packet(message)
        await asyncio.sleep(delay_s)
        started = time.perf_counter()
        entry = EntryObservation(sender=sender, time=started, size=wire_size(packet))
        await self.runtime.network.post_json(self.entry_url, packet)
        return entry, (time.perf_counter() - started) * 1000

    async def run_round(self) -> tuple[list[EntryObservation], list[ExitObservation], list[float]]:
        self.exits = []
        names = [f"alice-{index + 1}" for index in range(self.senders)]
        # Every user writes a different-length message (10..1500 characters).
        lengths = self.rng.sample(range(10, 1500, 23), self.senders)
        tasks = [
            self._send_one(name, length, index * self.gap_ms / 1000)
            for index, (name, length) in enumerate(zip(names, lengths))
        ]
        results = await asyncio.gather(*tasks)
        entries = [entry for entry, _ in results]
        latencies = [latency for _, latency in results]
        return entries, list(self.exits), latencies


def _entry_url(runtime: "WebRuntime") -> str:
    from web.runtime import INTERNAL_RELAY_URLS

    return INTERNAL_RELAY_URLS["relay-a"]


async def run_traffic_analysis(
    runtime: "WebRuntime",
    *,
    senders: int = 6,
    rounds: int = 3,
    gap_ms: float = 25.0,
    mix_delay_ms: int = 250,
    scenarios: list[Scenario] | None = None,
    seed: int | None = None,
) -> dict[str, Any]:
    """Run every scenario and return accuracy, latency and bandwidth numbers.

    The caller must hold runtime.operation_lock. The live policy is restored and
    experiment messages are removed from Bob's inbox afterwards.
    """
    rng = random.Random(seed)
    policy = runtime.policy
    saved = (policy.cell_bytes, policy.mix_delay_ms)
    receiver_db = runtime.dbs[runtime.receiver_id]
    latest = receiver_db.latest_message(receiver_id=runtime.receiver_id)
    last_real_message_id = latest["id"] if latest else 0

    from config.settings import settings

    results = []
    experiment = _Experiment(runtime, senders, gap_ms, rng)
    runtime.network.taps.append(experiment.tap)
    try:
        for scenario in scenarios or default_scenarios(mix_delay_ms):
            policy.cell_bytes = settings.cell_bytes if scenario.padding else None
            policy.mix_delay_ms = scenario.mix_delay_ms
            experiment.link_sizes = {}

            size_scores, timing_scores, latencies = [], [], []
            for _ in range(rounds):
                entries, exits, round_latencies = await experiment.run_round()
                size_scores.append(accuracy(size_attack(entries, exits, rng), exits))
                timing_scores.append(accuracy(timing_attack(entries, exits, rng), exits))
                latencies.extend(round_latencies)

            link_sizes = {name: sizes for name, sizes in experiment.link_sizes.items()}
            results.append(
                {
                    "id": scenario.id,
                    "title": scenario.title,
                    "padding": scenario.padding,
                    "cell_bytes": policy.cell_bytes,
                    "mix_delay_ms": scenario.mix_delay_ms,
                    "size_attack_accuracy": round(statistics.mean(size_scores), 3),
                    "timing_attack_accuracy": round(statistics.mean(timing_scores), 3),
                    "avg_latency_ms": round(statistics.mean(latencies), 1),
                    "max_latency_ms": round(max(latencies), 1),
                    # Average bytes on each link, and summed over the 4 links.
                    "link_bytes": [
                        {
                            "link": name,
                            "avg_bytes": round(statistics.mean(sizes)),
                            "distinct_sizes": len(set(sizes)),
                        }
                        for name, sizes in link_sizes.items()
                    ],
                    "bytes_per_message": round(sum(statistics.mean(s) for s in link_sizes.values())),
                }
            )
    finally:
        runtime.network.taps.remove(experiment.tap)
        policy.cell_bytes, policy.mix_delay_ms = saved
        receiver_db.delete_messages_after(receiver_id=runtime.receiver_id, message_id=last_real_message_id)

    return {
        "senders": senders,
        "rounds": rounds,
        "gap_ms": gap_ms,
        "random_guess": round(1 / senders, 3),
        "scenarios": results,
    }


__all__ = [
    "EntryObservation",
    "ExitObservation",
    "Scenario",
    "accuracy",
    "default_scenarios",
    "run_traffic_analysis",
    "size_attack",
    "timing_attack",
]
