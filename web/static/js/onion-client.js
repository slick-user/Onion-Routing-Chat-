/*
 * Browser side of OnionChat, using the Web Crypto API.
 * Generates the user's keys, encrypts messages end to end, wraps the three onion
 * layers and pads them, and decrypts received messages. The private key is
 * non-extractable and never leaves the browser. Formats match crypto/onion.py.
 * Also loaded by Node.js in tests/js/interop.mjs.
 */
(function (root, factory) {
  const api = factory(root.crypto || globalThis.crypto);
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.OnionClient = api;
})(typeof self !== "undefined" ? self : globalThis, function (webcrypto) {
  "use strict";

  const subtle = webcrypto.subtle;
  const PROTOCOL_VERSION = 1;
  const RSA_BITS = 3072;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  // RSA-OAEP with SHA-256: the same parameters PyCryptodome uses in wrap_key().
  const RSA_OAEP = { name: "RSA-OAEP", hash: "SHA-256" };

  // Small helpers: base64 and PEM
  function toBase64(bytes) {
    const view = new Uint8Array(bytes);
    let binary = "";
    for (let i = 0; i < view.length; i += 0x8000) {
      binary += String.fromCharCode.apply(null, view.subarray(i, i + 0x8000));
    }
    return btoa(binary);
  }

  function fromBase64(text) {
    const binary = atob(text);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function pemToDer(pem) {
    const body = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, "");
    return fromBase64(body);
  }

  function derToPem(der) {
    const lines = toBase64(der).match(/.{1,64}/g).join("\n");
    return "-----BEGIN PUBLIC KEY-----\n" + lines + "\n-----END PUBLIC KEY-----";
  }

  // Same as build_aad() in Python: binds the ciphertext to its purpose and key id.
  function buildAad(domain, keyId) {
    return encoder.encode("onionchat:" + domain + ":v" + PROTOCOL_VERSION + ":" + keyId);
  }

  // Keys
  async function generateIdentity() {
    const pair = await subtle.generateKey(
      Object.assign({ modulusLength: RSA_BITS, publicExponent: new Uint8Array([1, 0, 1]) }, RSA_OAEP),
      false, // extractable = false: applies to the private key
      ["encrypt", "decrypt"]
    );
    const spki = await subtle.exportKey("spki", pair.publicKey); // public keys are always exportable
    return { publicKey: pair.publicKey, privateKey: pair.privateKey, publicKeyPem: derToPem(spki) };
  }

  const importedKeys = new Map();

  async function importPublicKey(pem) {
    if (!importedKeys.has(pem)) {
      importedKeys.set(pem, subtle.importKey("spki", pemToDer(pem), RSA_OAEP, false, ["encrypt"]));
    }
    return importedKeys.get(pem);
  }

  // One encryption step = fresh AES-256-GCM key + RSA-OAEP wrap of that key
  async function hybridEncrypt(plaintextBytes, recipientPublicKey, domain, keyId) {
    const aesKey = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
    const nonce = webcrypto.getRandomValues(new Uint8Array(12));
    const sealed = new Uint8Array(
      await subtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: buildAad(domain, keyId), tagLength: 128 },
        aesKey,
        plaintextBytes
      )
    );
    // Web Crypto returns ciphertext || tag; the protocol stores them separately.
    const ciphertext = sealed.slice(0, sealed.length - 16);
    const tag = sealed.slice(sealed.length - 16);
    const rawKey = await subtle.exportKey("raw", aesKey);
    const wrappedKey = await subtle.encrypt(RSA_OAEP, recipientPublicKey, rawKey);

    // Alphabetical keys, so the JSON matches Python's canonical_json byte for byte.
    return {
      ciphertext: toBase64(ciphertext),
      nonce: toBase64(nonce),
      recipient_key_id: keyId,
      tag: toBase64(tag),
      version: PROTOCOL_VERSION,
      wrapped_key: toBase64(wrappedKey),
    };
  }

  async function encryptE2E(text, recipientPublicKey, recipientKeyId) {
    return hybridEncrypt(encoder.encode(text), recipientPublicKey, "e2e", recipientKeyId);
  }

  async function decryptE2E(envelope, privateKey) {
    const rawKey = await subtle.decrypt(RSA_OAEP, privateKey, fromBase64(envelope.wrapped_key));
    const aesKey = await subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
    const sealed = new Uint8Array([...fromBase64(envelope.ciphertext), ...fromBase64(envelope.tag)]);
    const plaintext = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: fromBase64(envelope.nonce),
        additionalData: buildAad("e2e", envelope.recipient_key_id),
        tagLength: 128,
      },
      aesKey,
      sealed
    );
    return decoder.decode(plaintext);
  }

  // Onion construction (mirror of build_onion in crypto/onion.py)
  function sortedCopy(value) {
    // Recursively sort object keys (Python's json.dumps(sort_keys=True)).
    if (Array.isArray(value)) return value.map(sortedCopy);
    if (value && typeof value === "object") {
      const out = {};
      Object.keys(value)
        .sort()
        .forEach((key) => {
          out[key] = sortedCopy(value[key]);
        });
      return out;
    }
    return value;
  }

  function canonicalJson(value) {
    return JSON.stringify(sortedCopy(value));
  }

  async function sealLayer(instruction, relay) {
    const publicKey = await importPublicKey(relay.public_key_pem);
    return hybridEncrypt(encoder.encode(canonicalJson(instruction)), publicKey, "onion", relay.key_id);
  }

  // options: text, from {user_id, name}, to {key_id, public_key_pem},
  // relays (entry first), mailboxId, cellBytes (null = no padding)
  async function buildChatOnion(options) {
    // 1. What the recipient will read. Relays never see any of this.
    const payload = JSON.stringify({
      type: "chat",
      from: options.from.user_id,
      from_name: options.from.name,
      text: options.text,
      sent_at: new Date().toISOString(),
    });
    const recipientKey = await importPublicKey(options.to.public_key_pem);
    const e2e = await encryptE2E(payload, recipientKey, options.to.key_id);

    // 2. Wrap from the inside out: the exit relay's layer first.
    const relays = options.relays;
    let envelope = await sealLayer({ receiver_id: options.mailboxId, message: e2e }, relays[relays.length - 1]);
    for (let i = relays.length - 2; i >= 0; i--) {
      envelope = await sealLayer({ next_hop_id: relays[i + 1].id, envelope: envelope }, relays[i]);
    }

    // 3. Pad to the fixed cell size, like networking/traffic_policy.py.
    return options.cellBytes ? padToCell(envelope, options.cellBytes) : envelope;
  }

  function randomFiller(length) {
    if (length <= 0) return "";
    const bytes = webcrypto.getRandomValues(new Uint8Array(Math.ceil((length * 3) / 4) + 3));
    return toBase64(bytes).slice(0, length);
  }

  function padToCell(packet, cellBytes) {
    const unpadded = Object.assign({}, packet);
    delete unpadded.padding;
    const baseSize = canonicalJson(Object.assign({}, unpadded, { padding: "" })).length;
    if (baseSize > cellBytes) {
      throw new Error("Message is too long to fit in one fixed-size cell");
    }
    return Object.assign(unpadded, { padding: randomFiller(cellBytes - baseSize) });
  }

  return {
    PROTOCOL_VERSION: PROTOCOL_VERSION,
    buildChatOnion: buildChatOnion,
    canonicalJson: canonicalJson,
    decryptE2E: decryptE2E,
    encryptE2E: encryptE2E,
    generateIdentity: generateIdentity,
    importPublicKey: importPublicKey,
    padToCell: padToCell,
  };
});
