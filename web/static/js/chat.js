/*
 * Chat tab. The crypto lives in onion-client.js; this file is the UI around it.
 * The private key is kept in IndexedDB (non-extractable). The user id, token and
 * sent messages are kept in sessionStorage, so each browser tab can be a different user.
 */
(function () {
  "use strict";

  const $ = (selector) => document.querySelector(selector);
  const SESSION_KEY = "onionchat.chat.session";
  const SENT_KEY = "onionchat.chat.sent";

  const state = {
    me: null, // { user_id, name, key_id, token }
    privateKey: null,
    directory: null,
    peer: null, // user_id we are talking to
    messages: [], // { with, mine, text, at } — at = milliseconds since 1970
    unread: {},
    lastInboxId: 0,
    socket: null,
  };

  // Small helpers
  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  async function api(url, options) {
    const opts = Object.assign({ headers: {} }, options || {});
    opts.headers = Object.assign({ Accept: "application/json" }, opts.headers);
    if (opts.body) opts.headers["Content-Type"] = "application/json";
    if (state.me && opts.auth) opts.headers.Authorization = "Bearer " + state.me.token;
    const response = await fetch(url, opts);
    const data = await response.json().catch(() => null);
    if (!response.ok) {
      const error = new Error((data && data.detail) || "Request failed (" + response.status + ")");
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function timeLabel(milliseconds) {
    return new Date(milliseconds).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }

  function userName(userId) {
    const user = state.directory && state.directory.users.find((entry) => entry.user_id === userId);
    return user ? user.name : "unknown user";
  }

  // Private key storage (IndexedDB holds CryptoKey objects directly)
  function keyStore(mode, action) {
    return new Promise((resolve, reject) => {
      const open = indexedDB.open("onionchat", 1);
      open.onupgradeneeded = () => open.result.createObjectStore("keys");
      open.onerror = () => reject(open.error);
      open.onsuccess = () => {
        const tx = open.result.transaction("keys", mode);
        const request = action(tx.objectStore("keys"));
        tx.oncomplete = () => resolve(request && request.result);
        tx.onerror = () => reject(tx.error);
      };
    });
  }
  const saveKey = (userId, key) => keyStore("readwrite", (store) => store.put(key, userId));
  const loadKey = (userId) => keyStore("readonly", (store) => store.get(userId));
  const deleteKey = (userId) => keyStore("readwrite", (store) => store.delete(userId));

  // Join / leave
  async function join(event) {
    event.preventDefault();
    const status = $("#chat-join-status");
    const button = $("#chat-join-button");
    button.disabled = true;
    try {
      status.textContent = "Generating your RSA-3072 key pair in this browser…";
      const identity = await OnionClient.generateIdentity();
      status.textContent = "Publishing your public key…";
      const me = await api("/api/chat/register", {
        method: "POST",
        body: JSON.stringify({ name: $("#chat-name").value, public_key_pem: identity.publicKeyPem }),
      });
      await saveKey(me.user_id, identity.privateKey);
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(me));
      await start(me, identity.privateKey);
      status.textContent = "";
    } catch (error) {
      status.textContent = "Could not join: " + error.message;
    } finally {
      button.disabled = false;
    }
  }

  async function leave() {
    if (state.socket) state.socket.close();
    if (state.me) await deleteKey(state.me.user_id).catch(() => {});
    sessionStorage.removeItem(SESSION_KEY);
    sessionStorage.removeItem(SENT_KEY);
    window.location.hash = "#chat";
    window.location.reload();
  }

  async function resume() {
    const saved = JSON.parse(sessionStorage.getItem(SESSION_KEY) || "null");
    if (!saved) return;
    const privateKey = await loadKey(saved.user_id).catch(() => null);
    if (!privateKey) {
      sessionStorage.removeItem(SESSION_KEY);
      return;
    }
    try {
      await start(saved, privateKey);
    } catch (error) {
      // e.g. the server restarted and forgot us: start over.
      sessionStorage.removeItem(SESSION_KEY);
      $("#chat-join").hidden = false;
      $("#chat-app").hidden = true;
    }
  }

  async function start(me, privateKey) {
    state.me = me;
    state.privateKey = privateKey;
    state.messages = JSON.parse(sessionStorage.getItem(SENT_KEY) || "[]");
    $("#chat-join").hidden = true;
    $("#chat-app").hidden = false;
    $("#chat-me").textContent = me.name;
    $("#chat-me-key").textContent = "key id " + me.key_id;
    await refreshDirectory();
    await fetchInbox(); // messages that arrived while we were away
    connect();
  }

  // Directory and people list
  async function refreshDirectory() {
    state.directory = await api("/api/chat/directory");
    renderPeople();
  }

  function renderPeople() {
    const list = $("#chat-people");
    list.textContent = "";
    const others = state.directory.users.filter((user) => user.user_id !== state.me.user_id);
    if (!others.length) {
      list.appendChild(el("li", "micro", "Nobody else yet. Open this page in another tab and join as someone else."));
    }
    others.forEach((user) => {
      const item = el("li");
      const button = el("button");
      button.type = "button";
      button.classList.toggle("is-active", user.user_id === state.peer);
      const dot = el("span", "chat-dot" + (user.online ? " is-online" : ""));
      button.append(dot, document.createTextNode(user.name));
      if (state.unread[user.user_id]) button.appendChild(el("span", "chat-unread", "● " + state.unread[user.user_id]));
      button.addEventListener("click", () => openConversation(user.user_id));
      item.appendChild(button);
      list.appendChild(item);
    });
  }

  function openConversation(userId) {
    state.peer = userId;
    state.unread[userId] = 0;
    $("#chat-with").textContent = "Chat with " + userName(userId);
    $("#chat-input").disabled = false;
    $("#chat-send").disabled = false;
    renderPeople();
    renderThread();
    $("#chat-input").focus();
  }

  function renderThread() {
    const thread = $("#chat-thread");
    thread.textContent = "";
    state.messages
      .filter((message) => message.with === state.peer)
      .sort((a, b) => a.at - b.at)
      .forEach((message) => {
        const bubble = el("li", "chat-bubble" + (message.mine ? " is-mine" : ""), message.text);
        bubble.appendChild(el("span", "micro", (message.mine ? "you · " : "") + timeLabel(message.at)));
        thread.appendChild(bubble);
      });
    thread.scrollTop = thread.scrollHeight;
  }

  // Sending
  async function send(event) {
    event.preventDefault();
    const input = $("#chat-input");
    const text = input.value.trim();
    if (!text || !state.peer) return;
    const button = $("#chat-send");
    button.disabled = true;
    try {
      // Fresh directory: relay keys may have been rotated since last time.
      await refreshDirectory();
      const to = state.directory.users.find((user) => user.user_id === state.peer);
      if (!to) throw new Error("That user has left");

      const packet = await OnionClient.buildChatOnion({
        text: text,
        from: { user_id: state.me.user_id, name: state.me.name },
        to: to,
        relays: state.directory.relays,
        mailboxId: state.directory.mailbox_id,
        cellBytes: state.directory.cell_bytes,
      });
      const result = await api("/api/chat/send", { method: "POST", body: JSON.stringify(packet) });
      showProof(result, OnionClient.canonicalJson(packet).length);
      if (!result.delivered) throw new Error("Rejected by " + result.rejected_by + " (" + result.error_category + ")");

      state.messages.push({ with: state.peer, mine: true, text: text, at: Date.now() });
      sessionStorage.setItem(SENT_KEY, JSON.stringify(state.messages.filter((message) => message.mine)));
      input.value = "";
      renderThread();
    } catch (error) {
      alertInline(error.message);
    } finally {
      button.disabled = false;
    }
  }

  function showProof(result, packetBytes) {
    const steps = $("#chat-proof-steps");
    steps.textContent = "";
    steps.appendChild(el("li", "", "Your browser → Relay A · " + packetBytes.toLocaleString() + " B of ciphertext"));
    (result.trace || [])
      .filter((event) => ["decrypted", "stored", "rejected"].indexOf(event.stage) !== -1)
      .forEach((event) => {
        let text = event.service_id + " · " + event.stage;
        if (event.next_hop_id) text += " → next hop " + event.next_hop_id;
        if (event.service_id === "mailbox" && event.stage === "stored") text += " · kept encrypted (cannot read it)";
        if (event.error_category) text += " · " + event.error_category;
        steps.appendChild(el("li", event.stage === "rejected" ? "is-rejected" : "", text));
      });
    $("#chat-proof").hidden = false;
  }

  function alertInline(message) {
    const thread = $("#chat-thread");
    thread.appendChild(el("li", "micro", "⚠ " + message));
    thread.scrollTop = thread.scrollHeight;
  }

  // Receiving
  async function receive(item) {
    if (item.id <= state.lastInboxId) return;
    state.lastInboxId = item.id;
    let message;
    try {
      message = JSON.parse(await OnionClient.decryptE2E(item.envelope, state.privateKey));
    } catch (error) {
      return; // not for us, tampered with, or for an old key: ignore it
    }
    if (message.type !== "chat") return;
    state.messages.push({ with: message.from, mine: false, text: message.text, at: item.received_at * 1000 });
    if (!state.directory.users.some((user) => user.user_id === message.from)) await refreshDirectory();
    if (message.from === state.peer) renderThread();
    else state.unread[message.from] = (state.unread[message.from] || 0) + 1;
    renderPeople();
  }

  async function fetchInbox() {
    const data = await api(
      "/api/chat/inbox?user_id=" + encodeURIComponent(state.me.user_id) + "&after=" + state.lastInboxId,
      { auth: true }
    );
    for (const item of data.messages) await receive(item);
  }

  function connect() {
    const scheme = window.location.protocol === "https:" ? "wss://" : "ws://";
    const socket = new WebSocket(scheme + window.location.host + "/ws/chat");
    state.socket = socket;
    const live = $("#chat-live");
    const dot = $("#chat-live-dot");

    socket.onopen = () => socket.send(JSON.stringify({ user_id: state.me.user_id, token: state.me.token }));
    socket.onmessage = async (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "ready") {
        live.textContent = "live — new messages arrive instantly";
        dot.classList.add("is-online");
      } else if (data.type === "message") {
        await receive(data);
      } else if (data.type === "directory") {
        await refreshDirectory();
      }
    };
    socket.onclose = () => {
      live.textContent = "offline — reconnecting…";
      dot.classList.remove("is-online");
      if (state.socket === socket) {
        window.setTimeout(() => {
          fetchInbox().catch(() => {});
          connect();
        }, 3000);
      }
    };
  }

  // Init
  function init() {
    if (!$("#panel-chat")) return;
    if (!window.crypto || !window.crypto.subtle || !window.indexedDB) {
      $("#chat-join-status").textContent = "This browser does not support the Web Crypto API (use HTTPS or localhost).";
      $("#chat-join-button").disabled = true;
      return;
    }
    $("#chat-join-form").addEventListener("submit", join);
    $("#chat-form").addEventListener("submit", send);
    $("#chat-leave").addEventListener("click", leave);
    $("#chat-input").addEventListener("keydown", (event) => {
      if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        $("#chat-form").requestSubmit();
      }
    });
    resume().catch(() => {});
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
