# OnionChat Threat Model

## Scope

This document describes the security properties and limitations of the
educational OnionChat implementation, including its interactive web frontend
and single-port hosted demo. It is not a production anonymity analysis.

## Assets

- Message plaintext.
- Receiver and relay RSA private keys.
- Per-packet AES session keys.
- Message metadata (sender/receiver endpoints, timing, circuit path).
- Relay configuration and allowlists.
- Replay state and operational events.
- Demo inbox contents, session traces and the key-metadata view served by the
  web API.

## Adversaries considered

1. **Network observer on localhost or a compromised host.** Can observe HTTP
   traffic between services and timing. Modelled explicitly as a *global
   passive adversary* in `adversary/traffic_analysis.py`: it sees the size and
   time of every packet on every link but cannot decrypt or modify them.
2. **Compromised relay.** Can read its own configuration and private key,
   observe packets it handles, and deviate from the protocol.
3. **Malicious sender/client.** Can submit malformed, oversized, replayed or
   tampered packets and attempt to influence routing.
4. **Malicious relay request.** Can attempt to make a relay fetch an arbitrary
   URL (SSRF).
5. **Offline attacker with recorded packets.** May later obtain a long-term
   private key.
6. **Local unprivileged user on the same host.** May attempt to read key files
   or databases.
7. **Malicious web client.** Can call the public JSON API directly to send
   messages, run attack experiments, read Bob's inbox, scrape key metadata, or
   reset demo state. Can also attempt XSS, content sniffing, framing and
   cross-site request patterns against the browser UI.
8. **Hosted-demo operator or process attacker.** Can reach the single-process
   topology, where all four services and the web app share one address space
   and filesystem.

## Mitigations

| Threat | Mitigation |
|---|---|
| Plaintext exposure at relays | Nested AES-256-GCM layers; relays peel one layer. E2E envelope is opaque. |
| Ciphertext tampering | AES-GCM authentication with domain-separated AAD. |
| Packet forgery/replay | Authenticated layers plus persistent relay-scoped replay cache. |
| SSRF via packet contents | Logical IDs only; local trusted registry maps IDs to endpoints. |
| Arbitrary receiver redirection | Exit relay resolves `receiver_id` through the local registry. |
| Oversized/malformed input | Pydantic `extra="forbid"`, field limits, ASGI body-size limit. |
| Error-based information leakage | Generic public errors; detailed categories only in sanitized internal events. |
| Secret leakage in logs | No plaintext, keys, session keys, raw packets, IPs or URLs in events. |
| Key file exposure | Private keys written `0600`, key directory `0700`, permissions tightened on load. |
| Hop position / message length leaking through packet size | Every packet on every link is padded to one fixed-size cell (`networking/traffic_policy.py`); padding is excluded from the replay digest. |
| Sender–receiver linking by timing order | Optional random mixing delay at each relay; measured in the traffic-analysis experiment. |
| Long-lived or stolen keys | Key rotation with a bounded grace period; retired keys expire and their private files are destroyed; compromised keys are revoked immediately and rejected by every hop (`key_revoked`). |
| Slow/unavailable peer | Explicit HTTP timeouts, no redirects, graceful 502 responses. |
| Unexpected crypto errors | Authentication failures fail closed; no partial acceptance. |
| XSS / content injection in the UI | Jinja2 autoescaping; all dynamic values inserted with `textContent`, never `innerHTML`; CSP restricts scripts and styles to same-origin. |
| Clickjacking and MIME sniffing | `X-Frame-Options: DENY`, `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`. |
| Secret exposure through the web API | Only public key IDs, algorithm, truncated SHA-256 fingerprints and file modes are returned. Private keys are loaded server-side and never serialised. |
| Plaintext leakage into traces/logs | Hop observers record sanitised metadata only; the sole plaintext endpoint is Bob's inbox (`GET /api/messages`). Web tests assert the message never appears in send/attack responses, traces or event rows. |
| Hostile web input | Pydantic `extra="forbid"`, message length 1–4000, bounded query limits, fixed attack allowlist, 256 KiB ASGI body cap, JSON-only handlers. |
| SSRF through the web runtime | The same logical-ID registry is used; there is no user-supplied URL parameter, and the SSRF experiment is rejected without an outbound request. |
| Demo-state destruction via the API | `POST /api/reset` only clears messages, events and replay rows; it never deletes keys. Public in the demo, documented as a residual risk. |
| Browser-driven cross-site requests | Same-origin JSON API, no permissive CORS, no inline executable script. A CSRF token and authentication are still required before any non-sandbox deployment. |

## Residual risks

- **No forward secrecy.** Static RSA-OAEP key transport means recorded traffic
  can be decrypted if a private key is later compromised. Rotation narrows this
  to traffic sent during that key's lifetime, but does not remove it.
- **Grace-period window.** A retired key that was stolen remains usable until
  its grace period ends unless an operator revokes it.
- **Traffic analysis.** Fixed-size cells remove the size signal, and mixing
  delays weaken (but do not remove) the timing signal, at a measured latency
  cost. There is no cover traffic or batching, so a lone user on a quiet
  network, or a long-term observer, can still correlate activity.
- **Endpoint metadata.** The entry relay sees the sender's address; the exit
  relay sees the receiver endpoint. Correlation is possible.
- **Compromised relays.** A compromised entry and exit relay can correlate
  traffic. Onion routing does not protect against a global passive adversary.
- **No sender authentication.** The receiver verifies ciphertext integrity,
  not the sender's identity. Messages are not signed.
- **Replay window.** Replays after the retention TTL are accepted.
- **Plaintext at rest.** The receiver stores decrypted messages in local
  SQLite without at-rest encryption in this demonstration.
- **Trusted configuration.** The registry, key IDs and ports are trusted local
  configuration. There is no directory consensus or key transparency.
- **No transport security.** Localhost HTTP is plaintext; multi-host
  deployment requires TLS/mTLS and a hardened network configuration.
- **SQLite limitations.** Single-host persistence and no distributed replay
  coordination between replicas.
- **Public demo API.** `/api/send`, `/api/attack`, `/api/messages` and
  `/api/reset` are unauthenticated. Anyone who can reach the app can send
  traffic, read Bob's inbox, probe attack outcomes or clear demo data. There is
  no rate limiting, quota, audit trail or CSRF token. The demo must not hold
  real secrets.
- **Single-process hosted topology.** In web/demo mode all services share one
  process, filesystem and event loop. The relay/receiver logic is real, but
  process isolation, host compromise and network-level attacker models do not
  apply to that mode.
- **Ephemeral hosted storage.** Free platforms usually reset keys, databases
  and inbox contents on redeploy or restart.

## Explicit non-goals

- Tor-level anonymity or censorship resistance.
- Protection against a global passive adversary.
- Cryptographic forward secrecy or post-compromise security.
- Malicious relay detection or accountability.
- Production key management, HSM integration, or at-rest encryption.
- User accounts, message signing, or multi-tenant authorisation.
- Production hardening of the demo API (authentication, rate limiting, WAF).
