# OnionChat Threat Model

## Scope

This document describes the security properties and limitations of the
educational OnionChat implementation. It is not a production anonymity
analysis.

## Assets

- Message plaintext.
- Receiver and relay RSA private keys.
- Per-packet AES session keys.
- Message metadata (sender/receiver endpoints, timing, circuit path).
- Relay configuration and allowlists.
- Replay state and operational events.

## Adversaries considered

1. **Network observer on localhost or a compromised host.** Can observe HTTP
   traffic between services and timing.
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
| Slow/unavailable peer | Explicit HTTP timeouts, no redirects, graceful 502 responses. |
| Unexpected crypto errors | Authentication failures fail closed; no partial acceptance. |

## Residual risks

- **No forward secrecy.** Static RSA-OAEP key transport means recorded traffic
  can be decrypted if a long-term private key is later compromised.
- **Traffic analysis.** No cover traffic, padding, batching or timing
  obfuscation. Localhost timing reveals the circuit to an observer.
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

## Explicit non-goals

- Tor-level anonymity or censorship resistance.
- Protection against a global passive adversary.
- Cryptographic forward secrecy or post-compromise security.
- Malicious relay detection or accountability.
- Production key management, HSM integration, or at-rest encryption.
- A frontend, user accounts, or message signing.
