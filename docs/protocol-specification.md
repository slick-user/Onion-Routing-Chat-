# OnionChat Protocol Specification (v1)

## 1. Cryptographic primitives

| Purpose | Primitive |
|---|---|
| Onion layer encryption | AES-256-GCM |
| Onion key transport | RSA-3072, RSA-OAEP with SHA-256 |
| E2E message encryption | AES-256-GCM |
| E2E key transport | RSA-OAEP-SHA-256 with the receiver's public key |
| Packet/replay digest | SHA-256 over canonical envelope JSON |

Each onion layer and each E2E message uses a randomly generated 32-byte AES
key. Nonces are 96 bits and tags are 128 bits. Onion keys and E2E keys are
independent and never reused.

## 2. AEAD associated data

```
onion AAD = "onionchat:onion:v1:<recipient_key_id>"
e2e   AAD = "onionchat:e2e:v1:<recipient_key_id>"
```

The AAD binds the protocol version, the encryption domain, and the recipient
key identifier to the authenticated ciphertext.

## 3. Envelope schema

```json
{
  "version": 1,
  "recipient_key_id": "relay-a-key",
  "wrapped_key": "<base64>",
  "nonce": "<base64, 12 bytes>",
  "ciphertext": "<base64>",
  "tag": "<base64, 16 bytes>"
}
```

Rules:

- `version` must be `1`.
- `recipient_key_id` is a configured logical key identifier.
- All binary fields are standard Base64 and are validated before use.
- Unknown JSON fields are rejected.
- The total HTTP request body is limited to 256 KiB by default; individual
  Base64 fields are limited to 200,000 characters.

## 4. End-to-end envelope

The sender builds an E2E envelope with the receiver's public key and key ID.
Its inner plaintext is the UTF-8 message. The envelope uses the same field
shape as an onion layer but a different AAD domain. It is placed inside the
exit instruction and is opaque to all relays.

## 5. Onion construction

Given a path `[relay-a, relay-b, relay-c]`, the sender constructs from the
inside out:

1. `E2E = encrypt_e2e(message, receiver_public_key, receiver_key_id)`
2. `C_instruction = {"receiver_id": receiver_id, "message": E2E}`
3. `C_envelope = seal(C_instruction, relay-c-key, relay-c-public-key)`
4. `B_instruction = {"next_hop_id": "relay-c", "envelope": C_envelope}`
5. `B_envelope = seal(B_instruction, relay-b-key, relay-b-public-key)`
6. `A_instruction = {"next_hop_id": "relay-b", "envelope": B_envelope}`
7. `A_envelope = seal(A_instruction, relay-a-key, relay-a-public-key)`

The sender submits `A_envelope` to Relay A.

## 6. Relay processing

For a packet received on `POST /relay`:

1. Pydantic validates the envelope and the body-size limit is enforced.
2. The relay checks that `recipient_key_id` matches its own key ID.
3. The relay computes a relay-scoped SHA-256 digest of the canonical envelope
   and rejects it if an unexpired digest already exists.
4. The relay unwraps `wrapped_key` with its RSA private key, verifies the
   AES-GCM tag with the AAD, and parses the routing instruction.
5. The relay validates the instruction shape for its role:
   - entry/middle: `{"next_hop_id", "envelope"}`
   - exit: `{"receiver_id", "message"}`
6. The relay records the digest in the replay cache (after successful
   authentication) and resolves the next logical peer through its local
   registry.
7. Entry/middle relays POST the next envelope to the trusted relay endpoint.
   The exit relay POSTs the E2E envelope to the trusted receiver endpoint.
8. The relay emits structured events and returns a generic status.

Relays do not accept URLs from packet contents and do not follow redirects.

## 7. Receiver processing

The receiver validates the E2E envelope, checks the recipient key ID, unwraps
the AES key with its private key, verifies the GCM tag with the E2E AAD, and
stores the UTF-8 plaintext in its local SQLite `messages` table. It returns
only a delivery status and message ID, never the plaintext.

## 8. Replay protection

- Digest: `SHA-256(canonical_json(envelope))`.
- Scope: one relay ID plus the digest.
- Storage: SQLite table `replay_cache` with `first_seen` and `expires_at`.
- Default retention: 300 seconds (configurable).
- A digest is inserted only after successful authentication and instruction
  validation.
- `INSERT OR IGNORE` makes concurrent duplicate submissions safe.
- Expired entries are purged opportunistically.

The digest is not a global correlatable identifier; it is scoped to a single
relay and is never logged.

## 9. Public endpoint status codes

| Status | Meaning |
|---|---|
| `200` | Packet accepted and forwarded/delivered |
| `400` | Invalid packet, bad key ID, authentication failure, unknown peer |
| `409` | Replayed packet |
| `413` | Body too large |
| `422` | Pydantic validation error |
| `502` | Trusted downstream relay or receiver unavailable |
| `500` | Unexpected internal error |

Error bodies are generic and do not include cryptographic details.

## 10. Operational events

Event rows include event ID, UTC timestamp, service ID/type, event type,
status, optional duration, sanitized error category and optional operational
detail. Sensitive values are never included.
