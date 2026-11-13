# OnionChat

OnionChat is an educational anonymous messaging system inspired by Tor's
onion-routing design. Alice sends an end-to-end encrypted message to Bob
through three independently running relay services:

```
Alice (sender CLI)
   │  E2E-encrypted message envelope
   ▼
Relay A (entry) ──peel layer A──▶ Relay B (middle) ──peel layer B──▶ Relay C (exit)
                                                                        │
                                                                        ▼
                                                                  Bob (receiver)
```

Each relay decrypts exactly one RSA-OAEP/AES-256-GCM onion layer, learns only
its own next hop, and forwards the remaining encrypted packet. Bob receives
only the inner end-to-end encrypted envelope and decrypts it with his private
key. Relays never see the message plaintext.

> **Educational project, not Tor.** This implementation does not provide
> Tor-level anonymity or production-grade cryptography. It runs on localhost
> against a static relay registry. See [Limitations](#limitations).

The project also ships an interactive web frontend that turns the same relay
and receiver services into a guided, visual demo: send a message, watch each
layer peel, inspect what every hop learned, and run real attack experiments in
the Security Lab. See [Interactive web demo](#interactive-web-demo).

## Features

- Three independently runnable FastAPI relay services (entry, middle, exit).
- A receiver service and a sender CLI.
- AES-256-GCM onion layers with RSA-3072 / RSA-OAEP-SHA-256 key transport.
- Independent AES-256-GCM end-to-end encryption between sender and receiver.
- Strict Pydantic packet validation and hard request-body limits.
- Trusted local relay/receiver registry (no arbitrary next-hop URLs).
- Persistent SQLite replay protection with configurable retention.
- Structured JSON logs and SQLite operational events.
- Responsive, dependency-free web UI with a guided tour, accessible tooltips,
  live hop animation, packet-size visualisation and a message inbox.
- Security Lab that submits real hostile packets (tamper, replay, wrong key,
  wrong layer, SSRF-style next hop, unknown receiver, oversized body).
- Per-request hop tracing showing exactly what each relay/receiver observed,
  without exposing plaintext or key material.
- Pytest unit, integration and web API tests.
- One-command local demo and single-port hosted demo.

## Requirements

- Python 3.10+ (developed with Python 3.13)
- Dependencies in `requirements.txt`: FastAPI, Uvicorn, PyCryptodome, HTTPX,
  Pydantic, Jinja2, Pytest.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Generate RSA-3072 keys for relay-a, relay-b, relay-c and receiver-bob.
python main.py init-keys

# Start all services, send a test message, print the receipt and status.
python main.py demo

# Or start the interactive web demo (also generates missing keys).
python main.py web
# open http://127.0.0.1:8080
```

Expected demo output includes:

```
Message received: Hello Bob! This is an OnionChat test.
```

Keys are written to `data/keys/` with private-key mode `0600`. Databases are
written to `data/db/`. Both are excluded by `.gitignore`.

## Interactive web demo

The web demo runs the whole topology in one process so it can be hosted on a
single port, while still using the real relay/receiver applications and real
HTTP request boundaries (`httpx.ASGITransport`). Nothing bypasses the onion
protocol: each relay still peels exactly one layer.

```bash
source .venv/bin/activate
pip install -r requirements.txt
python main.py web --host 127.0.0.1 --port 8080
```

Open <http://127.0.0.1:8080>. Missing RSA keys are generated automatically on
first start using the same `data/keys/` directory; private keys are never
served by the API or rendered in the UI.

The page has four sections:

| Section | What it shows |
|---|---|
| **Circuit** | Compose as Alice, animate the packet through Relay A/B/C, inspect per-hop knowledge, see the shrinking onion and Bob's inbox. |
| **Security lab** | Seven real attack experiments with the actual HTTP status, expected status, blocked verdict and relay trace. |
| **How it works** | A clickable layer model, cryptographic building blocks, a who-learns-what table and honest design trade-offs. |
| **Keys & logs** | Service counters, public key fingerprints/file modes, sanitised event log and a demo reset. |

First-time visitors get a five-step guided tour. Tooltips explain crypto
terms, all controls are keyboard accessible, and motion respects
`prefers-reduced-motion`. The UI uses plain HTML/CSS/JavaScript served from
`web/static/` with no CDN, build step or telemetry.

Useful web environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `8080` | Port used when `--port` is omitted (hosting platforms set this). |
| `ONIONCHAT_WEB_HOST` | `127.0.0.1` | Bind host when `--host` is omitted. |
| `ONIONCHAT_DATA_DIR` | `./data` | Root for generated keys and SQLite databases. |

The JSON API is also usable directly: `GET /health`, `GET /api/overview`,
`POST /api/send`, `GET /api/messages`, `GET /api/events`,
`POST /api/attack`, `POST /api/reset`. FastAPI's OpenAPI pages are available
at `/docs`.

## Running services individually

Each service is logically independent and can run in its own terminal or
process:

```bash
# Terminal 1 — entry relay
python main.py run-relay --id relay-a

# Terminal 2 — middle relay
python main.py run-relay --id relay-b

# Terminal 3 — exit relay
python main.py run-relay --id relay-c

# Terminal 4 — receiver
python main.py run-receiver
```

Default endpoints:

| Service | URL |
|---|---|
| Relay A (entry) | http://127.0.0.1:8001 |
| Relay B (middle) | http://127.0.0.1:8002 |
| Relay C (exit) | http://127.0.0.1:8003 |
| Receiver (Bob) | http://127.0.0.1:9000 |

Send a message from another terminal:

```bash
python main.py send --message "Hello Bob! This is an OnionChat test."
```

Or start all four services in one process manager:

```bash
python main.py run-all
```

Use `--host` / `--port` on `run-relay` and `run-receiver` to override the
default bind address for a service. The client and relay registry use the
configured ports in `config/settings.py`.

## Docker Compose

Docker is optional. The local Python workflow above is the primary development
path. A compose topology is included for running each relay and the receiver
as a separate container:

```bash
# Keys must exist on the host; they are mounted read-only into containers.
python main.py init-keys

docker compose up --build -d
docker compose ps
python main.py health

# The sender runs on the host and submits to the exposed entry relay.
python main.py send --message "Docker onion test"

# Structured events are visible in container logs and in each service DB.
docker compose logs -f relay-a
docker compose exec relay-a python main.py events --service relay-a

# The single-port web demo is included as a fifth service.
docker compose up --build -d web
# open http://127.0.0.1:8080

docker compose down -v
```

Compose uses `RELAY_A_HOST`/`RELAY_B_HOST`/`RELAY_C_HOST`/`RECEIVER_HOST`
environment variables so containers resolve each other by service name. Each
service gets its own named volume for SQLite state; keys are mounted read-only
from `data/keys`. The `web` service mounts the same key directory writable so
it can generate keys on first run, and uses its own database volume.
Host-side `python main.py events` only sees the local `data/db` files, not the
named container volumes.

## Deployment

The single-port web demo is designed for free hosting:

- **Render:** `render.yaml` defines a Docker web service with a `/health`
  check and `ONIONCHAT_DATA_DIR=/app/data`. The image's default command is
  `python main.py web --host 0.0.0.0`, and `main.py` reads the
  platform-provided `PORT`.
- **Procfile platforms:** `Procfile` contains
  `web: python main.py web --host 0.0.0.0`, and the app reads `PORT`.
- **Any container host:**

  ```bash
  docker build -t onionchat .
  docker run --rm -p 8080:8080 -e PORT=8080 onionchat web --host 0.0.0.0
  ```

Keys and SQLite databases are created at runtime. Free hosting typically has
ephemeral storage, so keys and messages reset on redeploy/restart; that is
acceptable for a public teaching demo but not for real messaging. The web
endpoints (`/api/reset`, `/api/attack`) are intentionally public in this
sandbox — add authentication and rate limiting before exposing a real system.

## Health, status and events

```bash
python main.py health
python main.py status
python main.py events --service relay-a --limit 50
```

Or query the HTTP endpoints directly:

```bash
curl http://127.0.0.1:8001/health
curl http://127.0.0.1:8001/status
curl http://127.0.0.1:9000/health
```

FastAPI OpenAPI/Swagger documentation is available at `/docs` and the schema
at `/openapi.json` on every service (for example,
http://127.0.0.1:8001/docs).

## Tests

```bash
source .venv/bin/activate
pytest -q
```

The suite covers RSA generation/loading, AES-GCM round trips and tampering,
RSA-OAEP wrapping, onion construction and peeling, invalid packet rejection,
persistent replay detection, relay forwarding, receiver authentication, and a
full Alice → Relay A → Relay B → Relay C → Bob delivery. It also verifies that
no relay can decrypt the end-to-end plaintext and that tampered and replayed
packets are rejected.

Web tests additionally cover page/static rendering and security headers, the
send trace, all seven attack experiments, event aggregation and sanitisation,
key-metadata exposure, and reset behaviour. The full suite is **62 tests**:

```bash
./.venv/bin/python -m pytest -q
# 62 passed
```

## Protocol summary

### Packet envelope

Every onion layer is a JSON envelope:

```json
{
  "version": 1,
  "recipient_key_id": "relay-a-key",
  "wrapped_key": "<base64 RSA-OAEP wrapped AES-256 key>",
  "nonce": "<base64 96-bit GCM nonce>",
  "ciphertext": "<base64 GCM ciphertext>",
  "tag": "<base64 128-bit GCM tag>"
}
```

AAD is `onionchat:onion:v1:<recipient_key_id>` for onion layers and
`onionchat:e2e:v1:<recipient_key_id>` for the end-to-end envelope. This binds
the protocol version and recipient key identifier to the authenticated
ciphertext and separates the two encryption domains.

### Inner instructions

Non-exit relays decrypt an instruction of the form:

```json
{
  "next_hop_id": "relay-b",
  "envelope": { "...next onion envelope..." }
}
```

The exit relay decrypts:

```json
{
  "receiver_id": "receiver-bob",
  "message": { "...end-to-end encrypted envelope..." }
}
```

`next_hop_id` and `receiver_id` are logical identifiers only. They are resolved
through `relay/registry.py`; packet contents cannot supply a URL.

### End-to-end encryption

The sender generates a random AES-256 key, encrypts the message with
AES-256-GCM, and wraps that key with the receiver's RSA-OAEP-SHA-256 public
key. This inner envelope is placed inside the innermost onion layer. Onion
layer keys are generated independently and are never reused for message
encryption.

## Security controls

- RSA-3072 relay and receiver keys, RSA-OAEP with SHA-256.
- AES-256-GCM with a fresh 96-bit nonce and 128-bit tag per encryption.
- AAD domain separation and recipient key binding.
- Strict Pydantic models with `extra="forbid"` and field-size limits.
- Hard ASGI request-body limit (default 256 KiB).
- Local allowlists for relays and receivers; no arbitrary forwarding.
- Persistent, relay-scoped SQLite replay cache with TTL retention.
- Explicit HTTP timeouts; no redirect following.
- Generic public error responses; detailed categories only in sanitized
  operational events.
- Private-key files created with `0600` and loaded defensively.
- No plaintext, keys, session keys, raw packets, or client IPs in structured
  logs or event rows.

## Project layout

```
onionchat/
├── client/
│   ├── sender.py          # E2E encryption + onion construction + submission
│   └── receiver.py        # FastAPI receiver, authentication and storage
├── relay/
│   ├── node.py            # FastAPI relay service
│   ├── router.py          # replay, one-layer peel, forwarding/delivery
│   └── registry.py        # trusted relay/receiver allowlist
├── crypto/
│   ├── keys.py            # RSA generation, PEM import/export, permissions
│   ├── encryption.py      # AES-GCM, RSA-OAEP, E2E envelope helpers
│   └── onion.py           # inside-out construction and layer peeling
├── networking/
│   ├── schemas.py         # Pydantic packet/request/response models
│   ├── transport.py       # HTTPX JSON forwarder with timeouts
│   ├── limits.py          # ASGI body-size middleware
│   └── inprocess.py       # shared ASGI network for demo/tests
├── storage/
│   └── database.py        # SQLite messages, events and replay cache
├── observability/
│   ├── logger.py          # structured JSON logging
│   └── events.py          # operational event types and persistence
├── config/
│   └── settings.py        # ports, paths, limits and topology
├── web/
│   ├── app.py             # FastAPI web UI, JSON API, security headers
│   ├── asgi.py            # uvicorn web.asgi:app entry point
│   ├── runtime.py         # in-process four-service demo topology
│   ├── trace.py           # per-request sanitised hop tracing
│   ├── templates/         # Jinja2 single-page UI
│   └── static/            # vanilla CSS and JavaScript
├── tests/
├── data/                  # generated keys and SQLite databases (ignored)
├── docs/
├── main.py                # unified CLI / development entry point
├── Dockerfile             # optional container image
├── docker-compose.yml     # optional five-service topology (4 services + web)
├── render.yaml            # free-hosting blueprint for the single-port demo
├── Procfile               # Procfile-based hosts
├── requirements.txt
└── README.md
```

## Documentation

| Document | Contents |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Components, Mermaid system-context/data-flow/sequence diagrams, trust boundaries and the web runtime. |
| [`docs/protocol-specification.md`](docs/protocol-specification.md) | Packet formats, instructions, AAD and error behaviour. |
| [`docs/threat-model.md`](docs/threat-model.md) | Assets, adversaries (including the public web API), mitigations and residual risks. |
| [`docs/security-evaluation.md`](docs/security-evaluation.md) | Seven-attack result matrix, cryptographic evaluation, web controls and trade-offs. |
| [`docs/presentation.md`](docs/presentation.md) | Marp-compatible slide deck for the course presentation. |
| [`docs/demo-script.md`](docs/demo-script.md) | Timed live-demo script, pre-flight checklist, fallbacks and anticipated questions. |

## Configuration

Defaults live in `config/settings.py`:

- relay and receiver endpoints and key identifiers;
- request timeout (10 s);
- maximum request body (256 KiB) and field size;
- replay retention (300 s);
- key and database directories.

Replay retention can be changed per relay when constructing the app, or
globally in `Settings.replay_ttl_seconds`.

## Docker / multi-host readiness

Local development does not require Docker. The `Dockerfile` builds the image
and defaults to the single-port web demo; `docker-compose.yml` additionally
defines the four-service topology plus the web service. The image is built
locally and smoke-tested with a full Alice → Relay A → Relay B → Relay C → Bob
delivery through the web API. The service boundaries, HTTP interfaces and
registry indirection keep relays independently addressable.

For a production-like multi-host deployment you would additionally need to:

1. Put TLS/mTLS in front of relay, receiver and web HTTP endpoints, because the
   localhost/compose demo intentionally uses plaintext HTTP on a private
   network.
2. Replace the compose service-name registry with your real relay/receiver
   endpoints via the `RELAY_*_HOST` / `RECEIVER_HOST` environment variables.
3. Protect key mounts with appropriate host/container permissions and use a
   secrets manager or HSM rather than a bind-mounted `data/keys` directory.
4. Use persistent, backed-up storage for SQLite replay state (or replace
   SQLite if you need multi-replica coordination).
5. Add rate limiting, authentication for demo/admin endpoints, monitoring,
   log aggregation and network policy around the service boundary.

## Limitations

- **Not Tor.** There is no cover traffic, traffic-analysis resistance,
  circuit padding, guard selection, directory consensus, or onion service.
- **No forward secrecy.** RSA-OAEP static key transport means compromise of a
  relay or receiver private key can expose recorded packets addressed to that
  key. The project intentionally documents this rather than claiming
  production-grade cryptography.
- **No sender authentication.** The receiver authenticates ciphertext
  integrity, not Alice's identity. Anyone with Bob's public key can send a
  valid encrypted message.
- **Metadata leakage.** The entry relay sees the sender's network address and
  the exit relay sees the receiver endpoint. Timing correlation remains
  possible.
- **Trusted local registry.** Relays are assumed to be configured correctly
  and to follow the protocol. There is no decentralized trust model.
- **Localhost transport is plaintext HTTP.** Do not deploy this as-is across
  untrusted networks.
- **Receiver storage.** Decrypted messages are stored locally in SQLite for
  demonstration purposes. Production systems would need at-rest encryption,
  retention controls and key protection.
- **Replay window.** Replay records expire after the configured TTL; a packet
  replayed after expiry is no longer detected.
- **Single-process SQLite.** SQLite is appropriate for this local educational
  demo, not for high-throughput or multi-node deployments.
- **Single-process hosted demo.** The web deployment runs all four services in
  one process and trusts the ASGI transport boundary. The relay/receiver code
  and one-layer peeling are real, but process isolation and network-level
  attacker models do not apply to that deployment mode.
- **Public demo controls.** There is no user authentication, rate limiting or
  CSRF token on the demo API. Same-origin JSON requests and security headers
  limit browser-driven abuse, but anyone who can reach the app can send
  messages, run attacks, or clear demo data. Treat it as a sandbox.
