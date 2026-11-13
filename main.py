"""OnionChat unified development entry point.

Examples:
    python main.py init-keys
    python main.py run-all
    python main.py send --message "Hello Bob! This is an OnionChat test."
    python main.py demo
    python main.py web
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
from crypto.keys import KeyStoreError, generate_service_keys, load_private_key, load_public_key
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
DEFAULT_MESSAGE = "Hello Bob! This is an OnionChat test."


# ----------------------------------------------------------------------
# Shared helpers
# ----------------------------------------------------------------------
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


def build_relay_app(relay_id: str):
    if relay_id not in RELAY_IDS:
        raise SystemExit(f"Unknown relay id: {relay_id}")
    private_path = settings.private_key_path(relay_id)
    _require_key(private_path)
    private_key = load_private_key(private_path)
    return create_relay_app(
        relay_id=relay_id,
        role=RelayRole(settings.relay_role(relay_id)),
        private_key=private_key,
        key_id=settings.relay_key_ids[relay_id],
        registry=build_registry(),
        db=Database(settings.database_path(relay_id)),
        forwarder=JsonForwarder(),
    )


def build_receiver_app():
    service_id = settings.receiver.service_id
    private_path = settings.private_key_path(service_id)
    _require_key(private_path)
    return create_receiver_app(
        receiver_id=service_id,
        private_key=load_private_key(private_path),
        key_id=settings.receiver_key_id,
        db=Database(settings.database_path(service_id)),
    )


def all_urls() -> list[str]:
    return [settings.relay_endpoint(relay_id).base_url for relay_id in RELAY_IDS] + [settings.receiver.base_url]


# ----------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------
def cmd_init_keys(args: argparse.Namespace) -> int:
    services = {
        **{relay_id: settings.relay_key_ids[relay_id] for relay_id in RELAY_IDS},
        settings.receiver.service_id: settings.receiver_key_id,
    }
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
    relay_path = list(RELAY_IDS)
    relay_public_keys = {}
    for relay_id in relay_path:
        path = settings.public_key_path(relay_id)
        _require_key(path)
        relay_public_keys[relay_id] = load_public_key(path)

    receiver_public_path = settings.public_key_path(settings.receiver.service_id)
    _require_key(receiver_public_path)
    receiver_public_key = load_public_key(receiver_public_path)

    return Sender(
        entry_relay_url=entry_url or settings.relay_a.base_url,
        receiver_id=settings.receiver.service_id,
        receiver_key_id=settings.receiver_key_id,
        receiver_public_key=receiver_public_key,
        relay_path=relay_path,
        relay_public_keys=relay_public_keys,
        relay_key_ids={relay_id: settings.relay_key_ids[relay_id] for relay_id in relay_path},
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
    db_path = settings.database_path(service_id) if service_id else settings.database_path(settings.receiver.service_id)
    db = Database(db_path)
    events = db.recent_events(service_id=service_id, limit=args.limit)
    print(json.dumps(events, indent=2))
    return 0


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
