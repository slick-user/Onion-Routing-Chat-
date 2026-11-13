# Testing guide

A step-by-step checklist for testing OnionChat before a demo or submission.
Each step says what to run or click and what you should see. Tick the boxes as
you go; if a result differs, the step tells you what it means.

Time needed: about 10 minutes for Parts 1–2, 20 minutes for everything.

---

## Part 0 — Fresh setup

```bash
cd ~/OpenSource/Onion-Routing-Chat-
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt pytest-asyncio
node --version            # optional: v18+ enables the browser-crypto test
python main.py init-keys  # creates RSA-3072 keys in data/keys/
```

- [ ] `init-keys` prints four lines (relay-a, relay-b, relay-c, receiver-bob)
  and "Private keys are stored with mode 0600".

> To start completely fresh at any time: `python main.py init-keys --force`
> (new keys) and **Keys & logs → Clear demo data** in the web UI.

---

## Part 1 — Automated tests

```bash
python -m pytest -q
```

- [ ] **100 passed**. Without Node.js you get **99 passed, 1 skipped**; that is
  fine, because the skipped test is the browser-crypto interop check.

Run one area at a time with `-v` to see every test name:

| Command | What it proves |
|---|---|
| `pytest tests/test_crypto.py tests/test_onion.py -v` | AES-GCM, RSA-OAEP, layer building and peeling, tamper detection |
| `pytest tests/test_relay.py tests/test_replay.py tests/test_delivery.py -v` | Relays peel one layer, replay protection, full Alice → Bob delivery |
| `pytest tests/test_keyring.py -v` | Key rotation, grace period, expiry, revocation, file permissions |
| `pytest tests/test_traffic_analysis.py -v` | Fixed-size cells, replay with new padding rejected, mixing, both attacks |
| `pytest tests/test_chat.py -v` | Chat: server never sees plaintext, mailbox tokens, WebSocket, browser ↔ Python crypto |
| `pytest tests/test_web.py -v` | Web page, security headers, all 7 Security Lab attacks, logs, reset |

---

## Part 2 — Command line

### 2.1 Full delivery through separate processes

```bash
python main.py demo
```

- [ ] Ends with `Message received: Hello Bob! This is an OnionChat test.`
- [ ] In the status JSON, relay-a and relay-b show `packets_forwarded: 1` and
  relay-c shows `packets_delivered: 1`.

### 2.2 Key lifecycle

```bash
python main.py keys
python main.py rotate-key --id relay-b
python main.py keys
```

- [ ] After rotating, relay-b lists an `active` key with a new id
  (`relay-b-xxxxxxxx`) and the old `relay-b-key` as `retired`, with
  "accepted for …s more".

```bash
python main.py revoke-key --id relay-b --key-id relay-b-key --reason "laptop stolen"
python main.py demo
```

- [ ] The old key now shows `revoked (reason: laptop stolen)`.
- [ ] `demo` still delivers, because the sender always uses the active key.

Revoking an **active** key creates a replacement automatically:

```bash
python main.py keys          # copy receiver-bob's active key id
python main.py revoke-key --id receiver-bob --key-id <that id>
```

- [ ] The output says a replacement key was generated.

### 2.3 Traffic analysis and benchmarks

```bash
python main.py traffic-analysis
python main.py benchmark --quick     # full run: python main.py benchmark (~1 min)
```

- [ ] **No defences:** both attacks ≈ 100%.
- [ ] **Fixed-size cells:** size attack drops to around the random-guess level
  (17%); timing attack stays ≈ 100%.
- [ ] **Cells + mixing:** both attacks near random, but latency is several
  times higher.
- [ ] The benchmark writes `docs/results/benchmarks.md`.

> Exact percentages vary between runs, since the experiment involves random
> choices. The *pattern* above is what matters.

---

## Part 3 — Web UI, tab by tab

```bash
python main.py web           # open http://127.0.0.1:8080
```

- [ ] The header shows **4/4 services online**.

### 3.1 Guided tour

- [ ] The tour opens on the first visit (or click **Guided tour**). Step through all 5 steps.

### 3.2 Circuit tab

1. Type any message and click **Seal & send onion**.
   - [ ] The animation goes Alice → Relay A → Relay B → Relay C → Bob.
   - [ ] The hop inspector shows each relay knows only its neighbours.
   - [ ] The packet-size chart shows **18,432 B at every relay**, with the
     caption "Fixed-size cells hide which hop…".
   - [ ] The message appears in Bob's inbox.
2. Paste a very long message (close to the 4000-character limit, with accents
   or emoji).
   - [ ] Either it is delivered, or you see "Message is too long to fit in one
     fixed-size cell". Both are correct behaviour.

### 3.3 Security lab tab

Click each attack card. The verdict must match:

| Attack | Expected HTTP | Blocked? |
|---|---|---|
| Tamper with the ciphertext | 400 | ✅ |
| Replay the exact same packet | 409 (first send 200) | ✅ |
| Address a packet to the wrong relay | 400 | ✅ |
| Send an exit instruction to the entry relay | 400 | ✅ |
| Put a URL in the next-hop field (SSRF) | 400 | ✅ |
| Deliver to an unregistered receiver | 400 | ✅ |
| Send an oversized packet | 413 | ✅ |

- [ ] All seven verdicts are "blocked", with the expected codes.

**Traffic analysis card** (bottom of the tab):

1. Leave **Mixing delay** at *up to 250 ms* and click **Run experiment** (about 5 s).
   - [ ] Three rows. The "No defences" row is red for both attacks. The
     "Fixed-size cells" row is green for size and red for timing. The
     "Cells + mixing" row is mostly green, with much higher latency.
   - [ ] The "Packet size on each link" column shrinks in the first row and
     shows 18,432 on every link in the others.
2. Click **Run experiment** again immediately.
   - [ ] You get a "cooling down" message (rate limit). Wait 5 s and it works.

### 3.4 Keys & logs tab

1. In **Key lifecycle**, click **Rotate key** on **Relay B**.
   - [ ] A new `active` row appears; the old key becomes `retired`, with a countdown.
2. On the **retired** key, click **Send test onion**.
   - [ ] Green box: "Delivered. Relay B accepted retired key…". The steps
     show "Relay B · Decrypted with retired key".
3. On the same retired key, click **Revoke** and keep the default reason.
   - [ ] The row becomes `revoked`, with "private key destroyed".
4. Click **Send test onion** on the revoked key.
   - [ ] Red box: "Rejected by Relay B: Key revoked. The packet never reached Bob."
5. Click **Revoke** on **Bob's active** key.
   - [ ] A toast reports the new active key; Bob now has two rows.
6. Go back to **Circuit** and send a message.
   - [ ] It is still delivered, because the sender picked up the new keys.
7. **Operational event log:** pick "Relay B" in the filter.
   - [ ] You see `validation_failure` events with category `key_revoked`, and
     no message text anywhere.
8. **Clear demo data** → confirm.
   - [ ] Messages and logs are cleared; the keys stay.

### 3.5 Chat tab (two users)

1. Tab 1: open **Chat**, type `Alice`, click **Generate keys & join**.
   - [ ] "You · Alice", a key id, and a green dot: "live — new messages arrive instantly".
2. Open a **second browser tab** at the same address → **Chat** → join as `Bob`.
   - [ ] Each tab lists the other person with a green dot.
3. As Alice, click **Bob**, type a message, then press **Enter** or **Encrypt & send**.
   - [ ] Bob's tab shows an unread marker (●1) next to Alice, without refreshing.
   - [ ] Alice sees "What the network saw": your browser → Relay A 18,432 B,
     relay-a/b/c decrypted, mailbox stored, kept encrypted.
4. As Bob, open Alice's conversation and reply.
   - [ ] Alice receives it live.
5. **Reload** Bob's tab.
   - [ ] Bob is still logged in, and the conversation is still there.
6. In Keys & logs, rotate Relay A's key, then send another chat message.
   - [ ] It still arrives (the browser fetched the new relay key).
7. Click **Leave & forget my keys** in Bob's tab.
   - [ ] The tab returns to the join form.

**Prove the server cannot read chat messages:**

```bash
sqlite3 data/db/chat.db "SELECT envelope FROM mailbox LIMIT 1;"
```

- [ ] You see only base64 ciphertext; neither the message text nor Alice's
  name appears. (If `sqlite3` is missing: `sudo apt install sqlite3`.)

---

## Part 4 — Settings to try ("options")

Stop the server (Ctrl+C), start it with a setting in front of the command, and
repeat the indicated step. Settings only last for that one run.

| Command | What to check | Expected |
|---|---|---|
| `ONIONCHAT_PADDING=0 python main.py web` | Circuit → send | Packet sizes **shrink** at each hop (≈ 4.4 → 2.8 → 1.6 KB): the leak padding fixes |
| `ONIONCHAT_MIX_DELAY_MS=300 python main.py web` | Circuit → send | Delivery is noticeably slower (random wait at each relay) |
| `ONIONCHAT_KEY_GRACE_SECONDS=20 python main.py web` | Keys → rotate, wait 20 s, test the old key | The status changes `retired` → `expired`; the test onion is rejected with `key_expired` |
| `ONIONCHAT_CELL_BYTES=8192 python main.py web` | Circuit → send ~1500 characters | "Message is too long to fit in one fixed-size cell" |
| `ONIONCHAT_KEY_COOLDOWN_SECONDS=30 python main.py web` | Keys → rotate twice quickly | The second click says "Please wait a moment between key actions" |

---

## Part 5 — API and health checks

With `python main.py web` running:

```bash
curl -s localhost:8080/health
curl -s localhost:8080/api/traffic-policy
curl -s localhost:8080/api/chat/directory | head -c 300; echo
curl -sI localhost:8080/ | grep -i -E "content-security-policy|x-frame-options"
```

- [ ] `/health` reports `"status":"healthy"`.
- [ ] `traffic-policy` shows `{"padding":true,"cell_bytes":18432,"mix_delay_ms":0}`.
- [ ] The directory contains public keys only (no `PRIVATE KEY`).
- [ ] Security headers are present.
- [ ] http://127.0.0.1:8080/docs lists every endpoint (interactive API docs).

---

## Before the live demo

- [ ] Parts 1, 3.3, 3.4 and 3.5 all pass on the **deployed** URL, not just locally.
- [ ] On free hosting, open the site a minute early: it sleeps after 15 minutes
  idle, and the first request takes about 50 s.
- [ ] Prepare two browser windows for the chat demo (normal + private window).
- [ ] Run **Clear demo data** so the demo starts clean.
