"""OnionChat command-line entry point.

Examples:
    python main.py init-keys
    python main.py demo
    python main.py web
    python main.py keys
    python main.py rotate-key --id relay-b
    python main.py traffic-analysis
    python main.py benchmark --quick
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import uvicorn

from client.receiver import create_receiver_app
from client.sender import Sender
from config.settings import BASE_DIR, settings
from crypto.keyring import KeyRing, KeyRingError, reset_keyring_files
from crypto.keys import generate_service_keys
from networking.transport import (
    JsonForwarder,
    TransportError,
    health_url,
    status_url,
)
from observability.logger import configure_logging
from relay.node import create_relay_app
from relay.registry import PeerRegistry
from relay.router import RelayRole
from storage.database import Database

RELAY_IDS = ("relay-a", "relay-b", "relay-c")
SERVICE_IDS = (*RELAY_IDS, settings.receiver.service_id)
DEFAULT_MESSAGE = "Hello Bob! This is an OnionChat test."


# Shared helpers
def build_registry() -> PeerRegistry:
    return PeerRegistry(
        relay_urls={relay_id: settings.relay_endpoint(relay_id).base_url for relay_id in RELAY_IDS},
        receiver_urls={settings.receiver.service_id: settings.receiver.base_url},
    )


def _require_key(path: Path) -> None:
    if not path.exists():
        raise SystemExit(f"Missing key file: {path}\nRun: python main.py init-keys")


def _require_all_keys() -> None:
    for service_id in list(RELAY_IDS) + [settings.receiver.service_id]:
        _require_key(settings.private_key_path(service_id))
        _require_key(settings.public_key_path(service_id))


def open_keyring(service_id: str) -> KeyRing:
    """Open a service's key ring (bootstraps a manifest for pre-rotation key files)."""
    _require_key(settings.private_key_path(service_id))
    return KeyRing.open(
        service_id,
        settings.keys_dir,
        default_key_id=settings.default_key_id(service_id),
        grace_seconds=settings.key_grace_seconds,
    )


def build_relay_app(relay_id: str):
    if relay_id not in RELAY_IDS:
        raise SystemExit(f"Unknown relay id: {relay_id}")
    return create_relay_app(
        relay_id=relay_id,
        role=RelayRole(settings.relay_role(relay_id)),
        keyring=open_keyring(relay_id),
        policy=settings.traffic_policy(),
        registry=build_registry(),
        db=Database(settings.database_path(relay_id)),
        forwarder=JsonForwarder(),
    )


def build_receiver_app():
    service_id = settings.receiver.service_id
    return create_receiver_app(
        receiver_id=service_id,
        keyring=open_keyring(service_id),
        db=Database(settings.database_path(service_id)),
    )


def all_urls() -> list[str]:
    return [settings.relay_endpoint(relay_id).base_url for relay_id in RELAY_IDS] + [
        settings.receiver.base_url
    ]


# Commands
def cmd_init_keys(args: argparse.Namespace) -> int:
    services = {
        **{relay_id: settings.relay_key_ids[relay_id] for relay_id in RELAY_IDS},
        settings.receiver.service_id: settings.receiver_key_id,
    }
    if args.force:
        for service_id in services:
            reset_keyring_files(settings.keys_dir, service_id)
    try:
        results = generate_service_keys(settings.keys_dir, services, bits=args.bits, force=args.force)
    except ValueError as exc:
        print(f"Key generation failed: {exc}", file=sys.stderr)
        return 2
    for name, (private_path, public_path) in results.items():
        print(f"{name}: key_id={services[name]} private={private_path} public={public_path}")
    print("Private keys are stored with mode 0600; never commit them.")
    return 0


def cmd_run_relay(args: argparse.Namespace) -> int:
    configure_logging(args.log_level)
    endpoint = settings.relay_endpoint(args.id)
    host = args.host or endpoint.host
    port = args.port if args.port is not None else endpoint.port
    app = build_relay_app(args.id)
    print(f"Starting OnionChat {settings.relay_role(args.id)} relay {args.id} on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_config=None, access_log=False)
    return 0


def cmd_run_receiver(args: argparse.Namespace) -> int:
    configure_logging(args.log_level)
    endpoint = settings.receiver
    host = args.host or endpoint.host
    port = args.port if args.port is not None else endpoint.port
    app = build_receiver_app()
    print(f"Starting OnionChat receiver {endpoint.service_id} on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_config=None, access_log=False)
    return 0


def _spawn_services() -> list[subprocess.Popen[bytes]]:
    main_path = str(Path(__file__).resolve())
    commands: list[list[str]] = [
        [sys.executable, main_path, "run-relay", "--id", relay_id] for relay_id in RELAY_IDS
    ]
    commands.append([sys.executable, main_path, "run-receiver"])
    processes: list[subprocess.Popen[bytes]] = []
    for command in commands:
        processes.append(subprocess.Popen(command, cwd=str(BASE_DIR)))
    return processes


def _stop_services(processes: list[subprocess.Popen[bytes]]) -> None:
    for process in processes:
        if process.poll() is None:
            process.terminate()
    for process in processes:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


async def _safe_health(forwarder: JsonForwarder, url: str) -> bool:
    try:
        body = await forwarder.get_json(health_url(url))
        return body.get("status") == "healthy"
    except TransportError:
        return False


async def _wait_for_health(timeout: float = 30.0) -> None:
    forwarder = JsonForwarder(timeout_seconds=2)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        checks = await asyncio.gather(*(_safe_health(forwarder, url) for url in all_urls()))
        if all(checks):
            return
        await asyncio.sleep(0.25)
    raise TimeoutError("services did not become healthy in time")


async def _collect_status() -> list[dict[str, Any]]:
    forwarder = JsonForwarder(timeout_seconds=3)
    results = []
    for url in all_urls():
        try:
            body = await forwarder.get_json(status_url(url))
        except TransportError:
            body = {"service": url, "status": "unavailable"}
        results.append(body)
    return results


def cmd_run_web(args: argparse.Namespace) -> int:
    """Run the interactive single-port demo used for hosting."""
    configure_logging(args.log_level)
    host = args.host or os.environ.get("ONIONCHAT_WEB_HOST", "127.0.0.1")
    port = args.port if args.port is not None else int(os.environ.get("PORT", "8080"))

    # Imported lazily so the CLI commands stay usable without the web extras.
    from web.app import create_web_app

    print("Preparing OnionChat web demo (RSA-3072 keys are generated if missing)...")
    app = create_web_app()
    print(f"OnionChat web demo listening on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_config=None, access_log=False)
    return 0


def cmd_run_all(args: argparse.Namespace) -> int:
    configure_logging(args.log_level)
    _require_all_keys()
    processes = _spawn_services()
    try:
        try:
            asyncio.run(_wait_for_health())
        except TimeoutError as exc:
            print(f"Failed to start services: {exc}", file=sys.stderr)
            return 1
        print("OnionChat services are running:")
        for relay_id in RELAY_IDS:
            endpoint = settings.relay_endpoint(relay_id)
            print(f"  {relay_id} ({settings.relay_role(relay_id)}): {endpoint.base_url}")
        print(f"  receiver: {settings.receiver.base_url}")
        print("Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping OnionChat services...")
        return 0
    finally:
        _stop_services(processes)


def _build_sender(entry_url: str | None = None) -> Sender:
    """Build the sender from the *currently active* key of every service."""
    relay_path = list(RELAY_IDS)
    rings = {service_id: open_keyring(service_id) for service_id in SERVICE_IDS}
    receiver_ring = rings[settings.receiver.service_id]

    return Sender(
        entry_relay_url=entry_url or settings.relay_a.base_url,
        receiver_id=settings.receiver.service_id,
        receiver_key_id=receiver_ring.active_key_id,
        receiver_public_key=receiver_ring.active_public_key,
        relay_path=relay_path,
        relay_public_keys={relay_id: rings[relay_id].active_public_key for relay_id in relay_path},
        relay_key_ids={relay_id: rings[relay_id].active_key_id for relay_id in relay_path},
        policy=settings.traffic_policy(),
    )


async def _send(message: str, entry_url: str | None = None) -> int:
    sender = _build_sender(entry_url)
    result = await sender.send(message)
    print(json.dumps(result.model_dump(), indent=2))
    return 0 if result.status == "sent" else 1


def cmd_send(args: argparse.Namespace) -> int:
    configure_logging(args.log_level)
    return asyncio.run(_send(args.message, args.entry))


async def _wait_for_message(timeout: float = 15.0) -> bool:
    db = Database(settings.database_path(settings.receiver.service_id))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if db.count_messages(receiver_id=settings.receiver.service_id) > 0:
            return True
        await asyncio.sleep(0.2)
    return False


async def _demo_async() -> int:
    processes = _spawn_services()
    try:
        try:
            await _wait_for_health()
        except TimeoutError as exc:
            print(f"Failed to start services: {exc}", file=sys.stderr)
            return 1
        result = await _send(DEFAULT_MESSAGE)
        if result != 0:
            return result
        if not await _wait_for_message():
            print("Delivery failed: receiver did not store a message.")
            return 1

        db = Database(settings.database_path(settings.receiver.service_id))
        latest = db.latest_message(receiver_id=settings.receiver.service_id)
        if latest is None:
            print("Delivery failed: receiver database is empty.")
            return 1

        print("\n--- OnionChat demo ---")
        print(f"Message received: {latest['message']}")
        print("\nService status:")
        print(json.dumps(await _collect_status(), indent=2))
        return 0
    finally:
        _stop_services(processes)


def cmd_demo(args: argparse.Namespace) -> int:
    configure_logging(args.log_level)
    _require_all_keys()
    return asyncio.run(_demo_async())


async def _health() -> int:
    forwarder = JsonForwarder(timeout_seconds=3)
    for url in all_urls():
        try:
            body = await forwarder.get_json(health_url(url))
            print(json.dumps({"url": url, **body}))
        except TransportError:
            print(json.dumps({"url": url, "status": "unavailable"}))
    return 0


def cmd_health(args: argparse.Namespace) -> int:
    return asyncio.run(_health())


async def _status() -> int:
    print(json.dumps(await _collect_status(), indent=2))
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    return asyncio.run(_status())


def cmd_events(args: argparse.Namespace) -> int:
    service_id = args.service
    db_path = (
        settings.database_path(service_id)
        if service_id
        else settings.database_path(settings.receiver.service_id)
    )
    db = Database(db_path)
    events = db.recent_events(service_id=service_id, limit=args.limit)
    print(json.dumps(events, indent=2))
    return 0


def _format_time(value: float | None) -> str:
    if value is None:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))


def _print_ring(service_id: str, ring: KeyRing) -> None:
    print(f"{service_id}:")
    for record in ring.records():
        extra = ""
        if record["status"] == "retired":
            extra = f" (accepted for {record['grace_remaining_seconds']}s more)"
        elif record["status"] == "revoked":
            extra = f" (reason: {record['reason']})"
        print(
            f"  {record['status']:<8} {record['key_id']:<24} fp={record['fingerprint']} "
            f"created={_format_time(record['created_at'])}{extra}"
        )


def cmd_keys(args: argparse.Namespace) -> int:
    for service_id in SERVICE_IDS:
        _print_ring(service_id, open_keyring(service_id))
    return 0


def cmd_rotate_key(args: argparse.Namespace) -> int:
    ring = open_keyring(args.id)
    record = ring.rotate(bits=args.bits)
    print(f"Rotated {args.id}: new active key {record.key_id} (fp={record.fingerprint}).")
    print(
        f"The previous key stays valid for {settings.key_grace_seconds}s so in-flight packets still arrive."
    )
    _print_ring(args.id, ring)
    return 0


def cmd_revoke_key(args: argparse.Namespace) -> int:
    ring = open_keyring(args.id)
    try:
        result = ring.revoke(args.key_id, reason=args.reason)
    except KeyRingError as exc:
        print(f"Revocation failed: {exc}", file=sys.stderr)
        return 2
    print(f"Revoked {args.key_id}. Packets addressed to it are now rejected; its private key was destroyed.")
    if result["replacement"]:
        print(f"It was the active key, so {result['replacement']['key_id']} was generated as a replacement.")
    _print_ring(args.id, ring)
    return 0


def cmd_traffic_analysis(args: argparse.Namespace) -> int:
    """Run the global-passive-observer experiment and print a table."""
    import tempfile

    from web.runtime import WebRuntime

    with tempfile.TemporaryDirectory(prefix="onionchat-ta-") as tmp:
        # Use the real keys, but a scratch database so Bob's inbox is untouched.
        runtime = WebRuntime.build(db_dir=Path(tmp))

        async def run() -> dict[str, Any]:
            return await runtime.traffic_analysis(
                senders=args.senders, rounds=args.rounds, mix_delay_ms=args.mix_delay_ms
            )

        result = asyncio.run(run())

    print(
        f"{result['senders']} users, {result['rounds']} rounds. A blind guess is right {result['random_guess']:.0%} of the time.\n"
    )
    print(f"{'Configuration':<28}{'Size attack':>13}{'Timing attack':>15}{'Latency':>11}{'Bytes/msg':>11}")
    for row in result["scenarios"]:
        print(
            f"{row['title']:<28}{row['size_attack_accuracy']:>13.0%}{row['timing_attack_accuracy']:>15.0%}"
            f"{row['avg_latency_ms']:>9.0f}ms{row['bytes_per_message']:>11}"
        )
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    from evaluation.benchmarks import RESULTS_DIR, run_benchmarks, to_markdown

    results = run_benchmarks(quick=args.quick)
    print()
    print(to_markdown(results))
    print(f"Saved to {RESULTS_DIR / 'benchmarks.md'} and benchmarks.json")
    return 0


# CLI
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="OnionChat educational onion-routing demo")
    parser.add_argument("--log-level", default="INFO")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init-keys", help="generate RSA relay and receiver key pairs")
    init_parser.add_argument("--bits", type=int, default=3072)
    init_parser.add_argument("--force", action="store_true", help="overwrite existing keys")
    init_parser.set_defaults(func=cmd_init_keys)

    relay_parser = subparsers.add_parser("run-relay", help="run one relay service")
    relay_parser.add_argument("--id", required=True, choices=list(RELAY_IDS))
    relay_parser.add_argument("--host", default=None)
    relay_parser.add_argument("--port", type=int, default=None)
    relay_parser.set_defaults(func=cmd_run_relay)

    receiver_parser = subparsers.add_parser("run-receiver", help="run the receiver service")
    receiver_parser.add_argument("--host", default=None)
    receiver_parser.add_argument("--port", type=int, default=None)
    receiver_parser.set_defaults(func=cmd_run_receiver)

    run_all_parser = subparsers.add_parser("run-all", help="run all four local services")
    run_all_parser.set_defaults(func=cmd_run_all)

    web_parser = subparsers.add_parser("web", help="run the interactive single-port web demo")
    web_parser.add_argument("--host", default=None)
    web_parser.add_argument("--port", type=int, default=None)
    web_parser.set_defaults(func=cmd_run_web)

    send_parser = subparsers.add_parser("send", help="send a message through the onion path")
    send_parser.add_argument("--message", default=DEFAULT_MESSAGE)
    send_parser.add_argument("--entry", default=None, help="override entry relay base URL")
    send_parser.set_defaults(func=cmd_send)

    demo_parser = subparsers.add_parser("demo", help="start services, send a message, print receipt")
    demo_parser.set_defaults(func=cmd_demo)

    health_parser = subparsers.add_parser("health", help="query /health on all services")
    health_parser.set_defaults(func=cmd_health)

    status_parser = subparsers.add_parser("status", help="query /status on all services")
    status_parser.set_defaults(func=cmd_status)

    events_parser = subparsers.add_parser("events", help="print persisted structured events")
    events_parser.add_argument("--service", default=None)
    events_parser.add_argument("--limit", type=int, default=30)
    events_parser.set_defaults(func=cmd_events)

    keys_parser = subparsers.add_parser("keys", help="list every service's key ring")
    keys_parser.set_defaults(func=cmd_keys)

    rotate_parser = subparsers.add_parser(
        "rotate-key", help="rotate a service's key (old key enters a grace period)"
    )
    rotate_parser.add_argument("--id", required=True, choices=list(SERVICE_IDS))
    rotate_parser.add_argument("--bits", type=int, default=None)
    rotate_parser.set_defaults(func=cmd_rotate_key)

    revoke_parser = subparsers.add_parser(
        "revoke-key", help="revoke a key immediately (e.g. after compromise)"
    )
    revoke_parser.add_argument("--id", required=True, choices=list(SERVICE_IDS))
    revoke_parser.add_argument("--key-id", required=True)
    revoke_parser.add_argument("--reason", default="manual revocation")
    revoke_parser.set_defaults(func=cmd_revoke_key)

    ta_parser = subparsers.add_parser("traffic-analysis", help="run the traffic-analysis attack experiment")
    ta_parser.add_argument("--senders", type=int, default=6)
    ta_parser.add_argument("--rounds", type=int, default=3)
    ta_parser.add_argument("--mix-delay-ms", type=int, default=250)
    ta_parser.set_defaults(func=cmd_traffic_analysis)

    bench_parser = subparsers.add_parser("benchmark", help="measure security vs. usability trade-offs")
    bench_parser.add_argument("--quick", action="store_true", help="smaller, faster run")
    bench_parser.set_defaults(func=cmd_benchmark)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
