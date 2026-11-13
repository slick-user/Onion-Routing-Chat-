"""Security vs. usability benchmarks (`python main.py benchmark`).

Measures RSA key size vs. speed, padding vs. bandwidth, and mixing delay vs.
timing-attack accuracy. Results go to docs/results/. Everything runs in one
process, so compare the rows with each other, not with real networks.
"""

from __future__ import annotations

import asyncio
import json
import platform
import statistics
import tempfile
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from Crypto.PublicKey import RSA

from adversary.traffic_analysis import Scenario, run_traffic_analysis
from config.settings import settings
from crypto.onion import build_onion, peel_layer
from networking.traffic_policy import pad_to_cell, wire_size
from networking.transport import relay_url

RESULTS_DIR = settings.base_dir / "docs" / "results"
SAMPLE_MESSAGE = "Meet at the library at 5pm. Bring the notes for the crypto exam."


def _median_ms(function: Callable[[], Any], repeat: int) -> float:
    """Run ``function`` ``repeat`` times and return the median time in ms."""
    samples = []
    for _ in range(repeat):
        started = time.perf_counter()
        function()
        samples.append((time.perf_counter() - started) * 1000)
    return round(statistics.median(samples), 2)


# 1. RSA key size
def _fresh_runtime(key_bits: int, workdir: Path):
    from web.runtime import WebRuntime

    return WebRuntime.build(
        keys_dir=workdir / f"keys-{key_bits}", db_dir=workdir / f"db-{key_bits}", key_bits=key_bits
    )


async def _circuit_latency_ms(runtime, messages: int) -> float:
    from web.runtime import INTERNAL_RELAY_URLS

    url = relay_url(INTERNAL_RELAY_URLS["relay-a"])
    samples = []
    for _ in range(messages):
        packet = runtime.sender.build_packet(SAMPLE_MESSAGE)
        started = time.perf_counter()
        await runtime.network.post_json(url, packet)
        samples.append((time.perf_counter() - started) * 1000)
    return round(statistics.median(samples), 2)


def bench_key_sizes(bits_options: tuple[int, ...], messages: int, workdir: Path) -> list[dict[str, Any]]:
    rows = []
    for bits in bits_options:
        print(f"  RSA-{bits}: generating keys...", flush=True)
        started = time.perf_counter()
        runtime = _fresh_runtime(bits, workdir)  # generates 4 key pairs
        keygen_ms = (time.perf_counter() - started) * 1000 / 4

        build_ms = _median_ms(lambda rt=runtime: rt.sender.build_packet(SAMPLE_MESSAGE), messages)
        latency_ms = asyncio.run(_circuit_latency_ms(runtime, messages))
        rows.append(
            {
                "rsa_bits": bits,
                "keygen_ms_per_key": round(keygen_ms, 1),
                "build_onion_ms": build_ms,
                "end_to_end_ms": latency_ms,
                "security_note": {
                    2048: "~112-bit security",
                    3072: "~128-bit security (default)",
                    4096: "~140-bit security",
                }.get(bits, ""),
            }
        )
    return rows


# 2. Padding / bandwidth
def bench_padding(lengths: tuple[int, ...]) -> list[dict[str, Any]]:
    """Bytes on each of the 4 links for one message, without and with padding."""
    keys = {name: RSA.generate(3072) for name in ("relay-a", "relay-b", "relay-c", "bob")}
    rows = []
    for length in lengths:
        packet = build_onion(
            message="x" * length,
            receiver_id="bob",
            receiver_key_id="bob-key",
            receiver_public_key=keys["bob"].publickey(),
            relay_path=["relay-a", "relay-b", "relay-c"],
            relay_public_keys={name: keys[name].publickey() for name in ("relay-a", "relay-b", "relay-c")},
            relay_key_ids={name: name for name in ("relay-a", "relay-b", "relay-c")},
        )
        # Peel the layers ourselves to measure every link.
        links = [packet]
        layer = packet
        for relay in ("relay-a", "relay-b"):
            layer = peel_layer(layer, keys[relay], relay)["envelope"]
            links.append(layer)
        links.append(peel_layer(layer, keys["relay-c"], "relay-c")["message"])

        unpadded = [wire_size(link) for link in links]
        fits = unpadded[0] + len(',"padding":""') <= settings.cell_bytes
        padded = [wire_size(pad_to_cell(link, settings.cell_bytes)) for link in links] if fits else None
        rows.append(
            {
                "message_chars": length,
                "unpadded_link_bytes": unpadded,
                "unpadded_total": sum(unpadded),
                "padded_link_bytes": padded,
                "padded_total": sum(padded) if padded else None,
                "overhead_factor": round(sum(padded) / sum(unpadded), 2) if padded else None,
            }
        )
    return rows


# 3. Mixing delay vs. timing attack
def bench_mixing(delays: tuple[int, ...], rounds: int, workdir: Path) -> list[dict[str, Any]]:
    runtime = _fresh_runtime(3072, workdir)
    scenarios = [
        Scenario(f"mix_{delay}", f"Mixing {delay} ms", padding=True, mix_delay_ms=delay) for delay in delays
    ]

    async def run() -> dict[str, Any]:
        async with runtime.operation_lock:
            return await run_traffic_analysis(runtime, rounds=rounds, scenarios=scenarios, seed=7)

    result = asyncio.run(run())
    return [
        {
            "mix_delay_ms": scenario["mix_delay_ms"],
            "timing_attack_accuracy": scenario["timing_attack_accuracy"],
            "size_attack_accuracy": scenario["size_attack_accuracy"],
            "avg_latency_ms": scenario["avg_latency_ms"],
            "random_guess": result["random_guess"],
        }
        for scenario in result["scenarios"]
    ]


# Report
def _percent(value: float | None) -> str:
    return "—" if value is None else f"{value * 100:.0f}%"


def to_markdown(results: dict[str, Any]) -> str:
    lines = [
        "# Benchmark results",
        "",
        f"Generated {results['generated_at']} on {results['machine']} by `python main.py benchmark`.",
        "All services run in one process, so compare rows with each other rather than with real networks.",
        "",
        "## 1. RSA key size vs. speed",
        "",
        "| RSA key | Key generation (per key) | Build onion | Alice → Bob end to end | Strength |",
        "|---|---|---|---|---|",
    ]
    for row in results["key_sizes"]:
        lines.append(
            f"| {row['rsa_bits']} | {row['keygen_ms_per_key']} ms | {row['build_onion_ms']} ms | "
            f"{row['end_to_end_ms']} ms | {row['security_note']} |"
        )
    lines += [
        "",
        f"## 2. Fixed-size cells vs. bandwidth (cell = {settings.cell_bytes} bytes)",
        "",
        "| Message | Bytes per link without padding (A, B, C, Bob) | Total | Total with padding | Overhead |",
        "|---|---|---|---|---|",
    ]
    for row in results["padding"]:
        unpadded = ", ".join(str(size) for size in row["unpadded_link_bytes"])
        padded = row["padded_total"] if row["padded_total"] else "does not fit"
        overhead = f"{row['overhead_factor']}×" if row["overhead_factor"] else "—"
        lines.append(
            f"| {row['message_chars']} chars | {unpadded} | {row['unpadded_total']} | {padded} | {overhead} |"
        )
    lines += [
        "",
        "Without padding, sizes shrink at every hop (revealing the hop position) and grow with message length",
        "(letting an observer match packets). With padding every link carries exactly one cell.",
        "",
        "## 3. Mixing delay vs. timing attack",
        "",
        "| Max mixing delay per relay | Timing attack accuracy | Size attack accuracy | Average latency |",
        "|---|---|---|---|",
    ]
    for row in results["mixing"]:
        lines.append(
            f"| {row['mix_delay_ms']} ms | {_percent(row['timing_attack_accuracy'])} | "
            f"{_percent(row['size_attack_accuracy'])} | {row['avg_latency_ms']} ms |"
        )
    if results["mixing"]:
        lines += ["", f"A blind guess is right {_percent(results['mixing'][0]['random_guess'])} of the time."]
    return "\n".join(lines) + "\n"


def run_benchmarks(*, quick: bool = False, output_dir: Path | None = None) -> dict[str, Any]:
    output = output_dir or RESULTS_DIR
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="onionchat-bench-") as tmp:
        workdir = Path(tmp)
        print("1/3 RSA key sizes")
        key_sizes = bench_key_sizes(
            (2048, 3072) if quick else (2048, 3072, 4096), 5 if quick else 15, workdir
        )
        print("2/3 Padding overhead")
        padding = bench_padding((10, 500, 2000, 4000))
        print("3/3 Mixing delay vs. timing attack")
        mixing = bench_mixing((0, 100, 250) if quick else (0, 50, 100, 250, 500), 2 if quick else 4, workdir)

    results = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "machine": f"{platform.system()} {platform.machine()}, Python {platform.python_version()}",
        "key_sizes": key_sizes,
        "padding": padding,
        "mixing": mixing,
    }
    (output / "benchmarks.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    (output / "benchmarks.md").write_text(to_markdown(results), encoding="utf-8")
    return results


__all__ = ["bench_key_sizes", "bench_mixing", "bench_padding", "run_benchmarks", "to_markdown"]
