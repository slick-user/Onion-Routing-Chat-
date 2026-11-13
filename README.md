# OnionChat — a mini-Tor anonymous chat

**CS-3002 Information Security · Term project · Topic 11: Anonymous Communication Systems (Onion Routing)**

OnionChat sends messages through three relays, Tor-style. Each message is
encrypted end to end for the recipient and then wrapped in three layers of
encryption, one per relay. Every relay can peel only its own layer, so it
learns the previous and next hop but never the message, and no single relay
knows both who sent it and who receives it.

**Live demo:** _add the Render URL here_

```
 Alice ──▶ Relay A ──▶ Relay B ──▶ Relay C ──▶ Bob
          peels A     peels B     peels C     decrypts the message
          knows Alice knows A, C  knows Bob   knows the text
```

> Educational project, not a replacement for Tor. See [Limitations](#limitations).

## Features

**Onion routing core**
- AES-256-GCM layers with RSA-3072 (OAEP, SHA-256) key wrapping, built with
  PyCryptodome. No home-made cryptography.
- Separate end-to-end encryption between sender and receiver.
- Three independent relay services (entry, middle, exit). Each peels exactly one layer.
- Replay protection, strict packet validation, and a trusted relay registry
  (a packet can never make a relay call an arbitrary URL).

**Two-way anonymous chat**
- Each browser generates its own RSA key pair with the **Web Crypto API**. The
  private key is non-extractable and never leaves the browser.
- The browser builds, pads and sends the onion itself. The server and relays only
  ever see ciphertext, and live delivery runs over **WebSocket**.

**Key lifecycle**
- Generation, distribution (public-key directory), secure storage (`0600` files),
  **rotation** with a grace period, and immediate **revocation**.

**Security evaluation**
- **Security Lab:** seven real attacks (tampering, replay, wrong key, wrong layer,
  SSRF, unknown receiver, oversized packet), all blocked.
- **Traffic analysis:** a simulated network observer tries to link senders to
  receivers by packet size and timing. Defences are fixed-size cells (padding)
  and random mixing delays.
- **Benchmarks:** RSA key size vs. speed, padding vs. bandwidth, and mixing vs. latency.

**Usable interface**
- Guided tour, tooltips, live hop animation, and a "what each relay saw" inspector.

## Quick start

Needs Python 3.10+ (Node.js 18+ is optional and only used by one test).

```bash
git clone https://github.com/slick-user/Onion-Routing-Chat-.git
cd Onion-Routing-Chat-
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python main.py init-keys   # RSA-3072 keys for the 3 relays and Bob
python main.py web         # open http://127.0.0.1:8080
```

For a command-line-only check, `python main.py demo` starts all services as
separate processes, sends a message and prints `Message received: …`.

## Using the web app

| Tab | What you can do |
|---|---|
| **Circuit** | Send a message as Alice and watch it pass through Relay A → B → C → Bob. See what each hop knew and the packet size on every link. |
| **Security lab** | Run seven attacks against the real relays and see the HTTP verdict. Run the traffic-analysis experiment with and without defences. |
| **How it works** | An interactive explanation of the layers and of who learns what. |
| **Keys & logs** | Rotate or revoke any key, send a test onion with an old key, and read the sanitised event log. |
| **Chat** | Join with a name, then chat with someone in another tab or browser. |

## Command line

| Command | Purpose |
|---|---|
| `python main.py init-keys [--force]` | Create (or replace) all RSA keys |
| `python main.py demo` | Start every service, send one message, print the result |
| `python main.py web [--port 8080]` | Run the web app |
| `python main.py run-relay --id relay-a` / `run-receiver` / `run-all` | Run services one by one (ports 8001–8003, 9000) |
| `python main.py send --message "hi"` | Send a message through running services |
| `python main.py keys` | Show every key ring |
| `python main.py rotate-key --id relay-b` | Rotate a key (the old one stays valid for the grace period) |
| `python main.py revoke-key --id relay-b --key-id <id> --reason "stolen"` | Revoke a key immediately |
| `python main.py traffic-analysis` | Run the size and timing attack experiment |
| `python main.py benchmark [--quick]` | Measure the trade-offs and write `docs/results/benchmarks.md` |
| `python main.py health` / `status` / `events` | Inspect running services |

## Testing

```bash
python -m pytest -q        # 100 passed (99 + 1 skipped without Node.js)
```

The tests cover the crypto primitives, onion building and peeling, relays,
replay protection, full delivery, every Security Lab attack, key rotation and
revocation, padding and the traffic-analysis attacks, and the chat. They also
check that the server never stores or returns chat plaintext, and they run the
real browser JavaScript under Node.js against the Python relays.

For a hands-on checklist of every feature, see
**[docs/testing-guide.md](docs/testing-guide.md)**.

## How a message is protected

1. The sender encrypts the message for the recipient: a fresh AES-256-GCM key,
   wrapped with the recipient's RSA public key.
2. It wraps the result three times, from the inside out (C, then B, then A).
   Each layer holds only the next hop's name.
3. Every packet is padded to **18,432 bytes**, so its size gives away neither
   the hop position nor the message length.
4. Each relay unwraps its layer, checks it, re-pads it and forwards it. Relay C
   hands the still-encrypted message to the receiver.

Each layer on the wire looks like this:

```json
{
  "version": 1,
  "recipient_key_id": "relay-a-key",
  "wrapped_key": "<RSA-OAEP wrapped AES key>",
  "nonce": "<96-bit nonce>",
  "ciphertext": "<AES-GCM ciphertext>",
  "tag": "<128-bit tag>",
  "padding": "<random filler up to the cell size>"
}
```

The full format is in [docs/protocol-specification.md](docs/protocol-specification.md).

## Security at a glance

| Threat | Defence |
|---|---|
| Relay reads the message | Layered encryption plus end-to-end encryption; only the receiver can decrypt |
| Tampered packet | AES-GCM authentication tag (HTTP 400) |
| Replayed packet | Replay cache of packet hashes; padding is ignored, so re-padding does not help (HTTP 409) |
| Packet tries to redirect a relay (SSRF) | Only logical ids are allowed, resolved through a trusted registry |
| Size reveals hop position or message length | Fixed-size cells |
| Timing links sender and receiver | Optional random mixing delay at each relay |
| Stolen or old key | Rotation with a grace period; revocation rejects the key at every hop |
| Server reads chat messages | Keys are made and kept in the browser; the mailbox stores ciphertext only |
| Someone reads another user's mailbox | Secret token, stored hashed and compared in constant time |

Details: [threat model](docs/threat-model.md) · [security evaluation](docs/security-evaluation.md) ·
[benchmark results](docs/results/benchmarks.md)

## Project structure

```
├── crypto/           encryption.py (AES-GCM, RSA-OAEP), onion.py (layers), keys.py, keyring.py (rotation/revocation)
├── relay/            node.py (relay service), router.py (peel + forward), registry.py (trusted addresses)
├── client/           sender.py, receiver.py (Bob), mailbox.py (chat receiver)
├── networking/       schemas.py, transport.py, traffic_policy.py (padding + mixing), inprocess.py, limits.py
├── adversary/        traffic_analysis.py (simulated network observer)
├── evaluation/       benchmarks.py
├── storage/          database.py (events, replay cache), chat_store.py (directory + mailboxes)
├── web/              app.py (UI + API), chat.py (chat API + WebSocket), runtime.py, templates/, static/
│   └── static/js/    onion-client.js (browser crypto), chat.js, app.js
├── observability/    structured logs and events
├── config/           settings.py
├── tests/            pytest suite + js/interop.mjs
├── docs/             architecture, protocol, threat model, evaluation, testing guide, results
└── main.py           command-line entry point
```

## Configuration

Set these as environment variables, for example `ONIONCHAT_PADDING=0 python main.py web`.

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | 8080 | Web port (hosting platforms set this) |
| `ONIONCHAT_DATA_DIR` | `./data` | Where keys and databases are stored |
| `ONIONCHAT_PADDING` | on | `0` turns fixed-size cells off |
| `ONIONCHAT_CELL_BYTES` | 18432 | Cell size in bytes |
| `ONIONCHAT_MIX_DELAY_MS` | 0 | Maximum random delay per relay (0 = off) |
| `ONIONCHAT_KEY_GRACE_SECONDS` | 120 | How long a rotated-out key is still accepted |
| `ONIONCHAT_KEY_COOLDOWN_SECONDS` | 2 | Minimum gap between key actions in the web app |
| `ONIONCHAT_REPLAY_TTL_SECONDS` | 300 | How long the replay cache remembers a packet |

## Deployment

- **Render (free):** New → Blueprint → select this repo. `render.yaml` builds the
  Docker image and checks `/health`. WebSockets work on the free plan.
- **Docker:** `docker build -t onionchat . && docker run -p 8080:8080 onionchat`
- **Docker Compose:** `docker compose up --build` runs each relay and the receiver
  in its own container, plus the web app (run `python main.py init-keys` first).

Free hosting sleeps after 15 idle minutes and wipes data on restart. Keys are
regenerated automatically.

## Documentation

| Document | Contents |
|---|---|
| [Architecture](docs/architecture.md) | Components, data-flow and sequence diagrams, trust boundaries |
| [Protocol specification](docs/protocol-specification.md) | Packet formats, instructions, errors |
| [Threat model](docs/threat-model.md) | Assets, adversaries, mitigations, residual risks |
| [Security evaluation](docs/security-evaluation.md) | Attack results, traffic analysis, key lifecycle, trade-offs |
| [Benchmark results](docs/results/benchmarks.md) | Measured security vs. usability numbers |
| [Testing guide](docs/testing-guide.md) | Step-by-step manual test checklist |
| [Demo script](docs/demo-script.md) | Plan for the live presentation |

## Limitations

- **Not Tor.** The path is three fixed relays. There is no cover traffic and no
  directory consensus, so a long-term observer can still correlate activity.
- **No forward secrecy.** If a relay's private key is stolen, recorded traffic for
  that key can be decrypted. Rotation limits this to that key's lifetime.
- **No sender authentication.** Chat display names are self-claimed and messages are not signed.
- **Trusted directory.** Browsers trust the server to hand out the real public keys.
- **Mixing only helps with company.** Delays shuffle packets only when several are in flight.
- **Demo hosting.** The web version runs all services in one process over plain
  HTTP on localhost. The public demo API has no accounts or rate limits beyond
  basic cooldowns.
- **Bob's demo inbox** stores decrypted messages in SQLite without at-rest encryption.
  The chat mailbox stores only ciphertext.

## Team

| Name | Roll number | Contribution |
|---|---|---|
| _Member 1_ | | |
| _Member 2_ | | |
| _Member 3_ | | |
