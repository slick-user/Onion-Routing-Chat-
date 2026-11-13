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

Known cryptographic limitation: static RSA key transport provides **no forward
secrecy**. If a relay or receiver private key is compromised later, recorded
packets addressed to that key can be decrypted. A production design would add
an ephemeral key agreement (for example, X25519) and rotate keys.

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
| Trace minimisation | Observers record service, role, stage, duration, recipient key ID, next logical hop, byte count and error category only. ContextVars isolate traces per request; observers cannot alter processing. |
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
| Plaintext HTTP locally | Easy local development | Requires TLS/mTLS before any multi-host deployment. |

## 7. Residual risks and non-goals

Explicitly **not** provided:

- Tor-level anonymity, censorship resistance or protection from a global
  passive adversary.
- Cover traffic, padding, fixed-size cells, batching or timing obfuscation.
- Forward secrecy or post-compromise security.
- Sender authentication, signatures, accounts or reputation.
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
