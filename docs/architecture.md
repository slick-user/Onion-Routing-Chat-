# OnionChat Architecture

## Components

```
                         (configured allowlists)
                                  │
Alice ──▶ Relay A (entry) ──▶ Relay B (middle) ──▶ Relay C (exit) ──▶ Bob
  │             │                    │                   │              │
  │             └─ peel A            └─ peel B           └─ peel C      │
  │                                                                     │
  └──────────────── end-to-end encrypted envelope ─────────────────────▶┘
```

| Component | Responsibility |
|---|---|
| `client/sender.py` | E2E-encrypts the message, builds the onion inside-out, POSTs to the entry relay, reports transport failure. |
| `relay/node.py` | FastAPI app for one relay role; exposes `/relay`, `/health`, `/status`; enforces the body limit. |
| `relay/router.py` | Replay check, recipient-key check, one-layer decryption, instruction validation, trusted forwarding or receiver delivery, event emission. |
| `relay/registry.py` | Static mapping of logical relay/receiver IDs to trusted endpoints. |
| `client/receiver.py` | FastAPI receiver; validates the E2E envelope, authenticates/decrypts it, stores the message, emits events. |
| `crypto/keys.py` | RSA-3072 generation, PEM import/export, secure private-key permissions. |
| `crypto/encryption.py` | AES-256-GCM, RSA-OAEP-SHA-256, domain-separated AAD, E2E envelope helpers. |
| `crypto/onion.py` | Layer sealing/peeling, instruction shapes, packet digest. |
| `networking/` | Strict Pydantic schemas, HTTPX transport, ASGI body-size middleware. |
| `storage/database.py` | SQLite messages, operational events and replay cache. |
| `observability/` | JSON logs and structured event persistence. |
| `config/settings.py` | Ports, endpoints, key IDs, limits, TTLs and paths. |
| `main.py` | Key generation, individual service runners, `run-all`, `send`, `demo`, health/status/events. |

## Trust boundaries

1. **Sender → Relay A.** The sender knows the full circuit path and submits
   only the outermost onion envelope.
2. **Relay A → B → C.** Each relay learns the identity of the next relay from
   its decrypted layer but must resolve that identity through its local
   registry. Packet contents never contain URLs.
3. **Relay C → receiver.** Relay C learns a logical receiver ID and resolves it
   through the local registry; it forwards the E2E envelope without decrypting
   it.
4. **Receiver.** Only the receiver holds the private key capable of decrypting
   the E2E envelope.

The relay registry is a trusted configuration boundary. A compromised registry
or relay process can redirect traffic or observe metadata; onion routing does
not protect against a compromised endpoint in this educational model.

## Process and deployment model

- Each relay and the receiver is an independent FastAPI application.
- `python main.py run-relay --id ...` runs one service.
- `python main.py run-all` spawns the four local services as child processes.
- `python main.py demo` additionally sends the acceptance message and prints
  the stored receipt.
- Services communicate over HTTPX with explicit timeouts and no redirects.
- The default endpoints are localhost. The included `Dockerfile` and
  `docker-compose.yml` run each service in its own container with
  service-name registry endpoints supplied via environment variables.
  Configuration is centralized in `config/settings.py`.

## Persistence

Each service uses its own SQLite database under `data/db/`:

- `messages` (receiver): delivered plaintext messages, local to the receiver.
- `events` (all services): structured operational events.
- `replay_cache` (relays): relay-scoped packet digests with expiry.

SQLite is opened per operation with WAL mode and a busy timeout, keeping the
code safe for FastAPI's threadpool without sharing connections across threads.

## Observability

Every relay/receiver emits JSON log records and SQLite event rows for startup,
shutdown, packet receipt, validation/decryption success or failure, forwarding,
delivery, authentication failure, replay detection, health checks and internal
errors. Logs and events deliberately omit plaintext, private keys, AES session
keys, raw packets, client IPs and configured URLs.
