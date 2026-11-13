# OnionChat Security Evaluation

This document evaluates the implemented OnionChat system, including the 2026
interactive web frontend. It records the evidence produced by the automated
suite and the Security Lab, the cryptographic properties that are actually
enforced, and the residual risks that remain by design.

It is an engineering evaluation, not a formal cryptographic proof or a
penetration test of a production deployment.

## 1. Scope and method

Evaluated components:

- sender onion construction and end-to-end encryption;
- entry, middle and exit relay processing;
- receiver authentication, decryption and storage;
- replay cache and event/log handling;
- HTTP input validation, allowlists and body-size limits;
- the web API, single-page UI and hosted single-port runtime;
- the seven Security Lab experiments.

Evidence sources:

1. The pytest suite (`62 passed`), including unit, integration and web tests.
2. The Security Lab, which sends hostile packets through the real relay code
   and reports the actual HTTP status and sanitised hop trace.
3. Manual inspection of the web output for secret/plaintext exposure.
4. Static review of the security headers, error responses and trust
   boundaries.

Reproduction:

```bash
./.venv/bin/python -m pytest -q
python main.py web
# open http://127.0.0.1:8080, then use the Security Lab
```

Tests generate RSA-2048 keys for speed. The runtime/CLI default is RSA-3072;
the key metadata page reports the actual key size, and no test weakens the
production default.

## 2. Attack experiments and observed results

Each experiment builds a deliberately invalid packet and submits it to Relay A
(or directly to Relay C for the unknown-receiver case). The verdict is derived
from the HTTP response, not from a mock of a validation rule.

| # | Experiment | What is sent | Observed | Expected | Control that fired |
|---|---|---|---|---|---|
| 1 | `tamper` | One ciphertext byte changed | HTTP 400 | 400 | AES-256-GCM authentication tag failure; packet rejected before forwarding |
| 2 | `replay` | Same valid packet twice | First 200, second 409 | 409 | Relay-scoped persistent replay cache keyed by SHA-256 packet digest |
| 3 | `wrong_key` | Relay A packet relabelled with Relay B's key ID | HTTP 400 | 400 | Recipient key ID checked before RSA unwrap/AES decryption |
| 4 | `wrong_layer` | Exit instruction sent to the entry relay | HTTP 400 | 400 | Role/instruction-shape validation (`relay` vs `exit`) |
| 5 | `unknown_next_hop` | URL placed in `next_hop_id` | HTTP 400 | 400 | Logical ID resolved through the trusted local registry; no outbound request |
| 6 | `unknown_receiver` | Valid onion for unregistered `mallory` | HTTP 400 | 400 | Exit relay resolves receiver IDs through the trusted registry |
| 7 | `oversized` | Ciphertext larger than the body limit | HTTP 413 | 413 | ASGI body-size middleware rejects before packet parsing; no relay trace |

The web tests assert all seven statuses and the `blocked` verdict. They also
assert that the replay's first submission succeeds (HTTP 200), that the
oversized request produces no hop trace, and that no attack response contains
the plaintext or raw packet fields.

## 3. Cryptographic properties

| Property | Implementation | Evaluation |
|---|---|---|
| Onion confidentiality | One AES-256-GCM layer per relay, unique 256-bit session key per layer | Each relay can decrypt only the layer addressed to its key ID. Tests peel all layers for metadata but verify relays cannot decrypt the E2E plaintext. |
| Key transport | RSA-3072, OAEP with SHA-256 | Fresh AES key wrapped per layer; private key required to unwrap. No custom primitives; PyCryptodome only. |
| Integrity/authenticity | GCM 128-bit tag over ciphertext and AAD | A single modified ciphertext byte produces an authentication failure and HTTP 400. |
| Domain separation | AAD = `onionchat:{onion,e2e}:v1:{key_id}` | Onion and E2E ciphertexts cannot be substituted for each other; version and recipient are bound. |
| End-to-end confidentiality | Independent AES-256-GCM message key, RSA-wrapped only for Bob | Relays never receive Bob's private key. Tests confirm that no relay can decrypt the E2E envelope. |
| Replay resistance | Relay-local SHA-256 digest cache with TTL | Duplicate packet is rejected with 409 within the retention window. |
| Randomness | `Crypto.Random.get_random_bytes` | Fresh keys/nonces from the library CSPRNG; nonces are not reused by construction. |
| Key storage | PEM private keys, directory `0700`, files `0600` | Loader rejects overly permissive private-key files; metadata API exposes only fingerprint, key ID and mode. |
| Key lifecycle | Per-service key ring: active → retired (grace) → expired, or → revoked | Relays/receiver resolve the private key by the layer's key ID and reject expired (`key_expired`) and revoked (`key_revoked`) keys before decryption. Expired/revoked private keys are destroyed. |

Known cryptographic limitation: static RSA key transport provides **no forward
secrecy**. If a relay or receiver private key is compromised later, recorded
packets addressed to that key can be decrypted. Key rotation **limits** this
exposure to the packets sent during that key's lifetime, and destroying retired
keys after the grace period means a later break-in cannot recover them. It does
not replace true forward secrecy, which would need an ephemeral key agreement
(for example, X25519) per circuit.

### 3.1 Key lifecycle experiments

Run from **Keys & logs → Key lifecycle** (or the CLI) against the real relays:

| Experiment | Expected | Observed |
|---|---|---|
| Rotate Relay B, then send a normal message | Delivered with the new key | Delivered; trace shows Relay B decrypting with its `active` key |
| Send a test onion with Relay B's old key during the grace period | Delivered | Delivered; trace shows `retired` key accepted |
| Revoke Relay B's old key, send the same test onion again | Rejected at Relay B | Relay B rejects with `key_revoked`; entry returns 502; nothing reaches Bob |
| Revoke Bob's active key | Replacement generated; old key rejected by Bob | New key active; test onion with the old key rejected by Bob with `key_revoked` |
| Wait past the grace period after a rotation | Old key rejected | Rejected with `key_expired`; archived private key file deleted |

**Trade-off:** a longer grace period loses fewer in-flight packets during
rotation, but keeps an old key usable for longer if it was stolen. Revocation
exists for that case: it skips the grace period entirely.

## 3.2 Traffic analysis: global passive observer

**Adversary.** Watches every link (Alice → A, A → B, B → C, C → Bob). It cannot
decrypt, modify, drop or delay packets, but sees each packet's size and time.
It also knows which user sent each packet into Relay A (their network address).
**Goal:** link each message that reaches Bob to its sender.

**Implementation.** `adversary/traffic_analysis.py` taps the in-process network
(`InProcessNetwork.taps`), sends one message from each of six simulated users
25 ms apart with different lengths, and runs two attacks:

- *Size attack:* rank packets by size at both ends and pair them up.
- *Timing attack:* assume first in, first out, and pair them up by time.

A "referee" decrypts Bob's copy only to score the guesses; the attacks never
see it. Run it from **Security lab → Traffic analysis** or
`python main.py traffic-analysis`.

**Defences.** `networking/traffic_policy.py`:

- *Fixed-size cells:* every packet on every link is padded with random filler
  to exactly 18 432 bytes (configurable). Padding sits outside the encrypted
  part, is regenerated at each hop, and is excluded from the replay digest, so
  re-padding a captured packet does not bypass replay protection (tested).
- *Mixing:* each relay waits a random 0..*N* ms before forwarding, so packets
  that are in flight together leave in a shuffled order.

**Observed results** (6 users × 3 rounds, RSA-3072; a blind guess is right 17%
of the time):

| Configuration | Size attack | Timing attack | Avg latency | Bytes per message |
|---|---|---|---|---|
| No defences | 100% | 100% | ~45–70 ms | ~14–16 KB |
| Fixed-size cells | ≈ random (6–33%) | 100% | ~45–65 ms | 73.7 KB |
| Cells + mixing (≤ 250 ms per relay) | ≈ random | ≈ random (11–29%) | ~430–500 ms | 73.7 KB |

Each defence stops one attack and not the other: padding removes the size
signal but leaves the order intact; mixing breaks the order but costs latency.
Without padding the packet also shrinks at every hop (≈ 4.4 → 2.8 → 1.6 →
0.7 KB for a short message), which reveals the hop position; with padding
every link shows the same size.

**Trade-offs** (measured by `python main.py benchmark`, see
[`results/benchmarks.md`](results/benchmarks.md)):

- Padding costs 1.7× bandwidth for a 4000-character message and 7.8× for a
  10-character one. A smaller cell would cost less but limit message length.
- About 100 ms of mixing per relay already pushes the timing attack close to
  random in this setup, while roughly quintupling latency. Real low-latency
  networks like Tor choose *not* to mix for exactly this reason.

**Limits.** Mixing only helps when several messages are in flight at once; a
single user on a quiet network is still easy to correlate. There is no cover
traffic, and a long-term observer can still use intersection attacks.

## 3.3 Two-way chat: end-to-end encryption in the browser

| Claim | Evidence |
|---|---|
| The server never sees chat plaintext | `test_server_never_stores_or_returns_plaintext`: the secret text is absent from the send response, the SQLite file and all event logs. |
| The mailbox cannot tell who sent a message | The stored envelope contains no sender id or name (same test). |
| Browser and Python crypto are compatible | `test_browser_client_onion_is_accepted_by_python_relays` runs `onion-client.js` in Node.js; the Python relays peel its padded 18 432-byte onion and the recipient decrypts it, including non-ASCII text. The reverse direction (Python → browser decrypt) is checked too. |
| Mailboxes are private | Wrong, missing or other users' tokens get HTTP 401; WebSocket logins with a bad token are closed. |
| Live delivery works | `test_websocket_pushes_new_mail_and_rejects_bad_tokens` receives and decrypts a pushed message. |
| Chat keeps working through key rotation | `test_chat_survives_relay_key_rotation`: the directory advertises the new relay key and messages still arrive. |
| Registration is safe | Private keys, keys under 2048 bits and unsafe display names are refused. |

## 4. Web-layer security controls

| Control | Evidence |
|---|---|
| Output encoding | Jinja2 autoescaping for the page; all dynamic data inserted with `textContent`, never `innerHTML`. |
| Secret non-exposure | Private keys are loaded server-side and never serialised. Tests assert that the page and `/api/overview` contain no PEM private key material. |
| Plaintext containment | The only endpoint that returns plaintext is Bob's inbox (`GET /api/messages`); traces, attacks and events are sanitised. Tests assert the acceptance message does not appear in send responses, attack responses, traces or event rows. |
| Input limits | Message length 1–4000 chars, a 256 KiB ASGI body cap, strict Pydantic models, bounded `limit` parameters and a fixed attack identifier allowlist. |
| Response hardening | `Content-Security-Policy` (self-only scripts/styles, no framing), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Permissions-Policy` (camera/microphone/geolocation disabled), `Cache-Control: no-store`. |
| Browser attack surface | No CDN, no third-party scripts, no inline executable script, no `eval`, no external fonts. JSON-only APIs reduce classic form CSRF; there is no permissive CORS configuration. |
| Error handling | Public handlers return generic messages (`Invalid onion packet`, `Internal demo error`); detailed categories stay in sanitised internal events. |
| Forwarding safety | Packet contents may only carry logical IDs; the registry resolves them. The SSRF experiment confirms a URL is rejected without a request. |
| Trace minimisation | Observers record service, role, stage, duration, recipient key ID, key status, next logical hop, byte counts, mixing delay and error category only. ContextVars isolate traces per request; observers cannot alter processing. |
| Reset safety | Reset clears messages, event rows and replay entries only; it never touches key files. |

The web tests also verify that all four services appear in aggregated events
and that the service filter and unknown-service rejection behave correctly.

## 5. Privacy and metadata observations

- **Relay A** learns the sender endpoint (in a real network), its own key ID,
  the successor Relay B, and packet size.
- **Relay B** learns Relay A and Relay C.
- **Relay C** learns Relay B and the receiver identity.
- **No relay** learns the full path, the message plaintext, or Bob's private
  key. The UI renders exactly this neighbour-only view.
- **Packet sizes shrink** at each hop because one RSA-wrapped AES key and one
  instruction are removed. The UI visualises the shrink, which is also a real
  metadata leak: a network observer can infer the hop position from size.
- **Timing** is observable in the local demo and is not obfuscated.
- **The receiver** stores plaintext in SQLite for demonstration; production
  storage would require at-rest encryption and retention controls.

## 6. Design trade-offs

| Decision | Benefit | Cost / limitation |
|---|---|---|
| Fixed three-relay path | Clear teaching model; deterministic traces and attack tests | No path selection, diversity, churn or guard nodes; not Tor-like anonymity. |
| Static RSA-OAEP key transport | Simple, widely understood, no custom protocol | No forward secrecy; long-term key compromise exposes recorded traffic. |
| One process for the hosted demo | Free single-port hosting; real service code still runs | No process isolation; ASGI transport is an internal trust boundary; a crash affects all services. |
| In-process ASGI network | Preserves real HTTP request/response semantics in tests and demo | Not a network attacker model; timing/CPU shared across services. |
| Relay-local replay cache | Simple, durable, per-relay correctness | Replicas do not coordinate; replays after TTL are accepted. |
| No sender signatures | Keeps the crypto surface small | Bob cannot authenticate Alice; anyone with Bob's public key can send. |
| SQLite | Zero-ops, easy inspection, adequate for a demo | Single-host; no distributed coordination or high throughput. |
| Public Security Lab and reset | Makes the demo tangible and self-service | No auth/rate limiting; anyone who reaches the app can send, probe or clear data. |
| Fixed-size cells (18 KiB) | Hides hop position and message length | 1.7–7.8× bandwidth; messages must fit in one cell. |
| Optional mixing delay (default off) | Breaks first-in-first-out timing correlation | Hundreds of ms of extra latency; useless without concurrent traffic. |
| Key-rotation grace period (default 120 s) | In-flight packets survive a rotation | A stolen retired key stays usable until the grace ends unless it is revoked. |
| Public key-lifecycle controls | Rotation and revocation can be demonstrated live | Anyone who reaches the demo can rotate or revoke keys; a 2 s cooldown limits CPU abuse from RSA generation. |
| Plaintext HTTP locally | Easy local development | Requires TLS/mTLS before any multi-host deployment. |

## 7. Residual risks and non-goals

Explicitly **not** provided:

- Tor-level anonymity, censorship resistance or protection from a global
  passive adversary.
- Cover traffic or batching. (Fixed-size cells and random mixing delays are
  implemented and measured; see §3.2.)
- Forward secrecy or post-compromise security.
- Sender authentication or signatures (chat names are self-claimed), key
  transparency for the chat directory, accounts or reputation.
- Malicious-relay detection, accountability or directory consensus.
- Production key management (HSM/KMS), at-rest encryption, backups or
  multi-replica replay coordination.
- Rate limiting, WAF, authentication or audit controls for the public demo.

A realistic deployment would also need TLS on every hop, network policy, secret
management, monitoring/alerting, dependency scanning, CSRF/rate-limit controls
for state-changing endpoints, and an independent cryptographic review.

## 8. Conclusion

Within its stated educational scope, the implementation enforces the intended
core properties: relays peel exactly one authenticated layer, cannot read the
end-to-end plaintext, cannot be redirected by packet-supplied URLs, and reject
tampered, misaddressed, replayed and oversized packets. The web frontend makes
those properties observable without exposing private keys or plaintext, while
the documented trade-offs make clear why this is a teaching system rather than
a production anonymity network.
