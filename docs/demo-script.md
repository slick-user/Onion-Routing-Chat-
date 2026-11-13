# OnionChat Live Demo Script

Target length: **8–10 minutes** (7 minutes demo + 1–3 minutes Q&A).
Companion slide deck: [`presentation.md`](presentation.md).

## Before the session (5 minutes)

```bash
cd /home/azlan/Uni/InfoSec/Project
source .venv/bin/activate
pip install -r requirements.txt
python main.py web --host 127.0.0.1 --port 8080
```

Checklist:

- [ ] `GET /health` returns `{"status":"healthy","relays":3,...}`.
- [ ] The page loads at <http://127.0.0.1:8080>.
- [ ] Complete or skip the guided tour once so the layout is familiar.
- [ ] Open the **Keys & logs** section and verify all four services are online.
- [ ] Press **Clear demo data** so the inbox and event log start empty.
- [ ] Close unrelated tabs and disable notifications.
- [ ] Increase browser zoom to ~110% for projector readability.

If the live server cannot be used, record a short screen capture of the same
steps and keep the CLI fallback ready:

```bash
python main.py demo
```

## 1. Framing (45 seconds)

**Say:**

> Alice wants to send a message to Bob through three relays. The relays should
> not learn who is talking to whom, or what they are saying. OnionChat wraps
> the message in three encrypted layers; each relay removes only its own layer.

Point at the **Circuit** tab and the `AES-256-GCM`, `RSA-3072`, and
`Independent end-to-end encryption` chips.

## 2. Send a message (90 seconds)

1. Click the **Meeting plan** example (or type a short message).
2. Press **Seal & send onion**.
3. Narrate the animation:
   - Alice encrypts for Bob, then wraps layers for Relay C, B and A.
   - Relay A peels its layer and learns only Relay B.
   - Relay B peels its layer and learns only Relay C.
   - Relay C peels its layer and delivers the E2E envelope to Bob.
4. Point at the **Onion cross-section** as the packet shrinks.
5. Point at **Bob's inbox** and show the plaintext arrived.

**Say:**

> Notice the packet size falls at each hop. That is real: a layer carries one
> wrapped AES key and one routing instruction. It is also a metadata leak —
> production systems use fixed-size cells.

## 3. Inspect what each hop saw (75 seconds)

Scroll to **What each hop can see**.

- Alice: route and plaintext before encryption.
- Relay A: predecessor Alice, successor Relay B, packet size.
- Relay B: predecessor Relay A, successor Relay C.
- Relay C: predecessor Relay B, receiver Bob.
- Bob: E2E plaintext, but no authenticated sender identity.

**Say:**

> Every card is generated from the relay process that actually handled the
> request. No relay ever receives Bob's private key or the message plaintext.
> Relays use logical IDs, so a packet cannot inject an arbitrary URL.

## 4. Security lab (2 minutes)

Open **Security lab** and run, in this order:

1. **Tamper with the ciphertext** → expect HTTP 400.
   - Say: the GCM tag fails before anything is forwarded.
2. **Replay the exact same packet** → first 200, second 409.
   - Say: the replay cache stores a SHA-256 digest per relay.
3. **Put a URL in the next-hop field (SSRF attempt)** → 400.
   - Say: the registry only knows logical IDs; no request reaches the URL.
4. **Send an exit instruction to the entry relay** → 400.
   - Say: instructions are role-checked after decryption.
5. Optionally: **wrong recipient key** and **unknown receiver**.
6. Optionally: **oversized packet** → 413 with an empty hop trace.
   - Say: the body limit fires before parsing.

For each result, point at **Actual response**, **Expected**, and the hop trace.
Emphasise that the verdict comes from the HTTP response, not a mock.

## 5. How it works (60 seconds)

Open **How it works**.

- Click each onion shell (A, B, C, core) and let the explainer update.
- Show the building-blocks list and the **Who learns what** table.
- Read one trade-off aloud, for example: *No forward secrecy.*

**Say:**

> We use PyCryptodome, AES-256-GCM with domain-separated associated data, and
> RSA-3072 OAEP-SHA-256. There are no custom primitives. The honest limit is
> that static RSA key transport gives no forward secrecy.

## 6. Keys, logs and evidence (60 seconds)

Open **Keys & logs**.

- Point out key IDs, actual key size, truncated public fingerprints and `0o600`
  private-key file modes. No private key material is displayed.
- Show the **Operational event log**: outcomes and sanitised error categories,
  no message text or packet contents.
- Mention the **62 passing tests** and the reproduction command.

**Say:**

> The only endpoint that returns plaintext is Bob's inbox. Send responses,
> attack responses, traces and event rows are sanitised, and the tests assert
> that plaintext and key material never appear there.

## 7. Close (30 seconds)

**Say:**

> OnionChat shows the core onion-routing properties end to end: one authenticated
> layer per relay, an independent E2E key for Bob, trusted next hops, and real
> rejection of tampered, replayed and misaddressed packets. It is a teaching
> system, not Tor — the trade-offs are documented, especially metadata leakage,
> no forward secrecy, and the public demo API.

## Reset between runs

Press **Clear demo data** in **Keys & logs**, or:

```bash
curl -X POST http://127.0.0.1:8080/api/reset
```

Reset clears messages, events and replay records; key files are kept.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Address already in use` | Use another port: `python main.py web --port 8081`. |
| First start is slow | RSA-3072 keys are being generated in `data/keys/`. |
| Services show offline | Check the terminal log and reload the page. |
| Tour appears again | It is stored in `localStorage`; use **Guided tour** to restart it. |
| A send fails | Open **Keys & logs**, inspect the event category, then reset and retry. |
| Projector hides contrast | Increase browser zoom and use the dark theme as designed. |

## Anticipated questions

- **How is this different from Tor?** Tor has directory consensus, guard/
  middle/exit selection, fixed-size cells, cover traffic and years of hardening.
  This project implements the core onion construction only.
- **Can a relay read the message?** No. It can peel its own layer, but the
  message is encrypted separately for Bob. Tests verify this.
- **Why RSA instead of X25519?** RSA-OAEP is easy to demonstrate and available
  in PyCryptodome. X25519 plus a KEM would be the production choice and would
  also enable forward secrecy.
- **What happens if two relays collude?** An entry and exit relay can correlate
  traffic by timing and size. Onion routing does not stop a global observer.
- **Is the hosted demo secure?** It is a sandbox. The API is unauthenticated
  and rate-limit-free by design; see the threat model.
