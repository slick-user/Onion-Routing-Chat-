/* OnionChat interactive demo — dependency-free front end. */
(function () {
  "use strict";

  // Utilities
  const $ = (selector, root) => (root || document).querySelector(selector);
  const $$ = (selector, root) => Array.from((root || document).querySelectorAll(selector));
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  const state = {
    sending: false,
    runId: 0,
    pendingSleeps: new Set(),
    tourIndex: 0,
    tourOpen: false,
    attacksRunning: false,
    eventsRequest: 0,
    inboxRequest: 0,
    keyActionBusy: false,
    hasRetiredKeys: false,
  };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function formatInt(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number.toLocaleString() : "0";
  }

  function formatTimestamp(iso) {
    if (!iso) return "—";
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return String(iso);
    return date.toLocaleString([], {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }

  function formatTimeOnly(iso) {
    if (!iso) return "—";
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return String(iso);
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function humanize(value) {
    if (!value) return "—";
    const text = String(value).replace(/_/g, " ");
    return text.charAt(0).toUpperCase() + text.slice(1);
  }

  async function api(url, options) {
    const opts = Object.assign({ headers: {} }, options || {});
    opts.headers = Object.assign({ Accept: "application/json" }, opts.headers);
    if (opts.body) opts.headers["Content-Type"] = "application/json";
    const response = await fetch(url, opts);
    let data = null;
    try {
      data = await response.json();
    } catch (error) {
      data = null;
    }
    if (!response.ok) {
      let message = "Request failed (" + response.status + ")";
      if (data && typeof data.detail === "string") message = data.detail;
      const failure = new Error(message);
      failure.status = response.status;
      failure.data = data;
      throw failure;
    }
    return data;
  }

  function toast(message, kind) {
    const region = $("#toasts");
    if (!region) return;
    const node = el("div", "toast " + (kind || ""), message);
    region.appendChild(node);
    window.setTimeout(() => {
      node.classList.add("is-leaving");
      window.setTimeout(() => node.remove(), 220);
    }, 4200);
  }

  async function withBusy(button, task) {
    if (!button) return task();
    button.disabled = true;
    try {
      return await task();
    } finally {
      button.disabled = false;
    }
  }

  // Cancellable animation delay. Cancelling resolves outstanding sleeps so a
  // replaced send never leaves an async task suspended forever.
  function sleep(ms) {
    if (reducedMotion.matches) return Promise.resolve();
    return new Promise((resolve) => {
      const entry = { id: 0, resolve: resolve };
      entry.id = window.setTimeout(() => {
        state.pendingSleeps.delete(entry);
        resolve();
      }, ms);
      state.pendingSleeps.add(entry);
    });
  }

  function cancelSleeps() {
    state.pendingSleeps.forEach((entry) => {
      window.clearTimeout(entry.id);
      entry.resolve();
    });
    state.pendingSleeps.clear();
  }

  // Tabs
  const tabs = $$(".tab");
  const panels = $$(".panel");

  function activateTab(name, options) {
    const opts = options || {};
    const target = tabs.find((tab) => tab.dataset.tab === name);
    if (!target) return;
    tabs.forEach((tab) => {
      const active = tab === target;
      tab.classList.toggle("is-active", active);
      tab.setAttribute("aria-selected", active ? "true" : "false");
      tab.tabIndex = active ? 0 : -1;
    });
    panels.forEach((panel) => {
      panel.hidden = panel.id !== "panel-" + name;
    });
    if (opts.focus) target.focus();
    if (opts.updateHash !== false) {
      try {
        history.replaceState(null, "", "#" + name);
      } catch (error) {
        /* history may be unavailable in sandboxed contexts */
      }
    }
  }

  function initTabs() {
    tabs.forEach((tab) => {
      tab.addEventListener("click", () => activateTab(tab.dataset.tab));
    });

    const list = $(".tabs");
    if (list) {
      list.addEventListener("keydown", (event) => {
        const keys = ["ArrowRight", "ArrowLeft", "Home", "End"];
        if (keys.indexOf(event.key) === -1) return;
        event.preventDefault();
        const current = tabs.findIndex((tab) => tab.classList.contains("is-active"));
        let next = current;
        if (event.key === "ArrowRight") next = (current + 1) % tabs.length;
        if (event.key === "ArrowLeft") next = (current - 1 + tabs.length) % tabs.length;
        if (event.key === "Home") next = 0;
        if (event.key === "End") next = tabs.length - 1;
        activateTab(tabs[next].dataset.tab, { focus: true });
      });
    }

    const initial = window.location.hash.replace("#", "");
    if (initial && $("#panel-" + initial)) activateTab(initial, { updateHash: false });

    $$("[data-goto]").forEach((button) => {
      button.addEventListener("click", () => activateTab(button.dataset.goto, { focus: true }));
    });
  }

  // Status and overview
  function setStatus(text, mode) {
    const pill = $("#app-status");
    $("#status-text").textContent = text;
    if (!pill) return;
    pill.classList.toggle("is-online", mode === "online");
    pill.classList.toggle("is-offline", mode === "offline");
  }

  function serviceLabel(serviceId) {
    const hop = $$(".hop").find((node) => node.dataset.service === serviceId);
    if (!hop) return serviceId;
    const name = $(".hop-name", hop);
    return name ? name.textContent : serviceId;
  }

  function roleLabel(service) {
    if (service.role) return service.role;
    if (service.service_type === "receiver") return "receiver";
    return "relay";
  }

  function pillFor(value) {
    const text = String(value || "");
    const node = el("span", "pill", text);
    if (text === "online" || text === "success") node.classList.add("success");
    else if (text === "offline" || text === "failure") node.classList.add("failure");
    else if (text === "rejected") node.classList.add("rejected");
    return node;
  }

  function cell(value, className) {
    const node = el("td", className || "");
    if (value instanceof Node) node.appendChild(value);
    else node.textContent = value === undefined || value === null ? "—" : String(value);
    return node;
  }

  function renderServices(services) {
    const body = $("#services-body");
    if (!body) return;
    clear(body);
    (services || []).forEach((service) => {
      const row = el("tr");
      const name = el("th", "", serviceLabel(service.service_id));
      name.scope = "row";
      row.appendChild(name);
      row.appendChild(cell(roleLabel(service)));
      const online = service.status !== "unavailable";
      row.appendChild(cell(pillFor(online ? "online" : "offline")));
      if (service.service_type === "receiver") {
        row.appendChild(cell(formatInt(service.messages_received)));
        row.appendChild(cell("—"));
        row.appendChild(cell(formatInt(service.messages_received)));
        row.appendChild(cell(formatInt(service.messages_failed)));
        row.appendChild(cell("—"));
      } else {
        row.appendChild(cell(formatInt(service.packets_received)));
        row.appendChild(cell(formatInt(service.packets_forwarded)));
        row.appendChild(cell(formatInt(service.packets_delivered)));
        row.appendChild(cell(formatInt(service.packets_failed)));
        row.appendChild(cell(formatInt(service.replays_detected)));
      }
      body.appendChild(row);
    });
    if (!body.children.length) {
      const row = el("tr");
      const data = cell("Service status unavailable.", "empty small");
      data.colSpan = 8;
      row.appendChild(data);
      body.appendChild(row);
    }
  }

  function renderKeys(keys) {
    const body = $("#keys-body");
    if (!body) return;
    clear(body);
    (keys || []).forEach((key) => {
      const row = el("tr");
      const name = el("th", "", serviceLabel(key.service_id));
      name.scope = "row";
      row.appendChild(name);
      row.appendChild(cell(key.role));
      row.appendChild(cell(el("span", "mode", key.key_id)));
      row.appendChild(cell(key.algorithm));
      row.appendChild(cell(el("span", "fingerprint", key.fingerprint)));
      const mode = el("span", "mode", key.private_key_mode);
      if (!/600$/.test(String(key.private_key_mode))) mode.classList.add("is-warn");
      row.appendChild(cell(mode));
      body.appendChild(row);
    });
    if (!body.children.length) {
      const row = el("tr");
      const data = cell("Key metadata unavailable.", "empty small");
      data.colSpan = 6;
      row.appendChild(data);
      body.appendChild(row);
    }
  }

  function updateInboxCount(total) {
    const badge = $("#inbox-count");
    if (!badge) return;
    const count = Number(total) || 0;
    badge.textContent = count + (count === 1 ? " message" : " messages");
  }

  async function loadOverview(options) {
    const opts = options || {};
    try {
      const data = await api("/api/overview");
      renderServices(data.services || []);
      renderKeys(data.keys || []);
      const services = data.services || [];
      const online = services.filter((service) => service.status !== "unavailable").length;
      setStatus(online + "/" + services.length + " services online", online === services.length ? "online" : "offline");
      if (data.counts) updateInboxCount(data.counts.messages);
      return data;
    } catch (error) {
      setStatus("Services unavailable", "offline");
      if (!opts.quiet) toast("Could not load service status.", "error");
      return null;
    }
  }

  // Circuit
  const DEFAULT_HOP_STATE = {
    alice: "builds the onion",
    "relay-a": "idle",
    "relay-b": "idle",
    "relay-c": "idle",
  };
  const DEFAULT_HOP_SEES = {
    alice: "knows the full route",
    "relay-a": "waiting for a packet",
    "relay-b": "waiting for a packet",
    "relay-c": "waiting for a packet",
  };

  function hops() {
    return $$(".hop");
  }

  function hopFor(serviceId) {
    return hops().find((hop) => hop.dataset.service === serviceId) || null;
  }

  function bobServiceId() {
    const node = $("#hop-bob");
    return node ? node.dataset.service : "receiver-bob";
  }

  function setHopState(serviceId, text, classes) {
    const hop = hopFor(serviceId);
    if (!hop) return;
    const stateNode = $(".hop-state", hop);
    if (stateNode) stateNode.textContent = text;
    hop.classList.remove("is-active", "is-done", "is-blocked");
    (classes || []).forEach((name) => hop.classList.add(name));
  }

  function setHopSees(serviceId, text) {
    const hop = hopFor(serviceId);
    if (!hop) return;
    const node = $(".hop-sees", hop);
    if (node) node.textContent = text;
  }

  function activateWire(index, done) {
    const wire = $('.wire[data-wire="' + index + '"]');
    if (!wire) return;
    wire.classList.add("is-active");
    if (done) wire.classList.add("is-done");
  }

  function resetCircuitVisuals() {
    state.runId += 1;
    cancelSleeps();
    hops().forEach((hop) => {
      hop.classList.remove("is-active", "is-done", "is-blocked");
      const id = hop.dataset.service;
      const stateNode = $(".hop-state", hop);
      const seesNode = $(".hop-sees", hop);
      if (stateNode) {
        if (id === bobServiceId()) stateNode.textContent = "waits for delivery";
        else stateNode.textContent = DEFAULT_HOP_STATE[id] || "idle";
      }
      if (seesNode) {
        if (id === bobServiceId()) seesNode.textContent = "owns the E2E key";
        else seesNode.textContent = DEFAULT_HOP_SEES[id] || "waiting";
      }
    });
    $$(".wire").forEach((wire) => wire.classList.remove("is-active", "is-done"));
    const badge = $("#circuit-badge");
    if (badge) badge.textContent = "idle";
    setCircuitSummary("Send a message to animate the circuit.", "");
  }

  function setCircuitSummary(text, mode) {
    const node = $("#circuit-summary");
    if (node) node.textContent = text;
    const wrap = $(".circuit-progress");
    if (wrap) {
      wrap.classList.toggle("is-live", mode === "live");
      wrap.classList.toggle("is-error", mode === "error");
    }
    const badge = $("#circuit-badge");
    if (badge && mode === "live") badge.textContent = "in transit";
    if (badge && mode === "error") badge.textContent = "blocked";
  }

  function stageText(event) {
    const receiver = bobServiceId();
    switch (event.stage) {
      case "received":
        return event.service_type === "receiver" ? "received E2E envelope" : "received onion packet";
      case "decrypted":
        if (event.service_type === "receiver") return "decrypted with Bob's key";
        if (event.instruction === "relay") return "peeled a layer · next " + (event.next_hop_id || "?");
        return "peeled final layer · for " + (event.receiver_id || receiver);
      case "forwarded":
        return "forwarded to " + (event.next_hop_id || "next hop");
      case "delivered":
        return "delivered to " + (event.receiver_id || receiver);
      case "stored":
        return "stored as message #" + formatInt(event.message_id);
      case "rejected":
        return "rejected: " + humanize(event.error_category || "policy");
      case "failed":
        return "downstream failure: " + humanize(event.error_category || "transport");
      default:
        return humanize(event.stage || "event");
    }
  }

  function isFailureStage(event) {
    return event.stage === "rejected" || event.stage === "failed";
  }

  function describeSees(event) {
    const allHops = hops();
    const index = allHops.findIndex((hop) => hop.dataset.service === event.service_id);
    if (index <= 0) return null;
    const previous = $(".hop-name", allHops[index - 1]);
    const previousName = previous ? previous.textContent : "previous hop";
    if (event.stage === "decrypted" && event.instruction === "relay") {
      return "from " + previousName + " · next " + (event.next_hop_id || "?");
    }
    if (event.stage === "decrypted" && event.instruction === "exit") {
      return "from " + previousName + " · for " + (event.receiver_id || bobServiceId());
    }
    return null;
  }

  async function playTrace(trace) {
    const runId = ++state.runId;
    resetCircuitVisuals();
    state.runId = runId;
    setCircuitSummary("Building three AES-256-GCM layers and wrapping each key…", "live");

    const alice = "alice";
    if (hopFor(alice)) {
      setHopState(alice, "building layers…", ["is-active"]);
    }
    await sleep(260);
    if (state.runId !== runId) return;
    if (hopFor(alice)) {
      setHopState(alice, "sealed for 3 relays + Bob", ["is-done"]);
      setHopSees(alice, "full route · plaintext before encryption");
    }
    activateWire(0, true);
    await sleep(180);
    if (state.runId !== runId) return;

    for (let index = 0; index < trace.length; index += 1) {
      if (state.runId !== runId) return;
      const event = trace[index];
      const serviceId = event.service_id;
      const failure = isFailureStage(event);
      const hop = hopFor(serviceId);
      const isLast = index === trace.length - 1;

      if (hop) {
        setHopState(serviceId, stageText(event), [failure ? "is-blocked" : "is-active"]);
        const sees = describeSees(event);
        if (sees) setHopSees(serviceId, sees);
        const hopIndex = hops().indexOf(hop);
        if ((event.stage === "forwarded" || event.stage === "delivered") && hopIndex >= 0) {
          activateWire(hopIndex, true);
        }
        if (serviceId === bobServiceId() && event.stage === "stored") {
          setHopState(serviceId, "message stored for Bob", ["is-done"]);
          setHopSees(serviceId, "E2E decrypted · message #" + formatInt(event.message_id));
        }
      }

      const summary = serviceLabel(serviceId) + ": " + stageText(event);
      setCircuitSummary(summary, failure ? "error" : "live");
      await sleep(isLast ? 0 : 150);
      if (state.runId !== runId) return;

      if (hop && !failure) {
        hop.classList.remove("is-active");
        hop.classList.add("is-done");
      }
    }

    const failed = trace.find(isFailureStage);
    if (failed) {
      setCircuitSummary(
        "Packet stopped at " + serviceLabel(failed.service_id) + " · " + humanize(failed.error_category || "rejected"),
        "error"
      );
      return;
    }

    const lastForwarded = trace
      .filter((event) => event.stage === "forwarded" && Number.isFinite(Number(event.duration_ms)))
      .sort((a, b) => Number(b.duration_ms) - Number(a.duration_ms))[0];
    const totalMs = lastForwarded ? Number(lastForwarded.duration_ms) : null;
    setCircuitSummary(
      "Delivered to Bob" +
        (totalMs !== null ? " · " + totalMs.toFixed(2) + " ms end-to-end (local demo)" : "") +
        " · " + trace.length + " hop observations",
      "live"
    );
    const badge = $("#circuit-badge");
    if (badge) badge.textContent = "delivered";
  }

  // Inspector and layer chart
  function setInspectorPlaceholder() {
    const inspector = $("#inspector");
    if (!inspector) return;
    clear(inspector);
    const wrap = el("div", "inspector-placeholder");
    wrap.appendChild(el("p", "", "Send a message, then inspect exactly what Alice, each relay, and Bob observed."));
    wrap.appendChild(el("p", "micro", "No plaintext, private keys, or raw packet bytes are ever rendered."));
    inspector.appendChild(wrap);
    const badge = $("#inspector-badge");
    if (badge) badge.textContent = "no packet yet";
  }

  function knowledgeLine(label, text) {
    const line = el("span");
    line.appendChild(el("b", "", label + ": "));
    line.appendChild(document.createTextNode(text));
    return line;
  }

  function reportStages(events) {
    const list = el("ol", "stage-list");
    events.forEach((event) => {
      const item = el("li", "stage" + (isFailureStage(event) ? " is-bad" : ""));
      item.appendChild(el("span", "stage-dot"));
      item.appendChild(el("span", "", stageText(event)));
      const duration = Number.isFinite(Number(event.duration_ms))
        ? Number(event.duration_ms).toFixed(1) + " ms"
        : "—";
      item.appendChild(el("span", "stage-time", duration));
      list.appendChild(item);
    });
    if (!list.children.length) list.appendChild(el("li", "stage", "no processing events recorded"));
    return list;
  }

  function renderInspector(trace) {
    const inspector = $("#inspector");
    if (!inspector) return;
    clear(inspector);

    const byService = new Map();
    trace.forEach((event) => {
      if (!byService.has(event.service_id)) byService.set(event.service_id, []);
      byService.get(event.service_id).push(event);
    });

    const order = hops();
    order.forEach((hop, index) => {
      const serviceId = hop.dataset.service;
      const name = $(".hop-name", hop).textContent;
      const role = $(".hop-role", hop).textContent;
      const events = byService.get(serviceId) || [];
      if (!events.length && serviceId !== "alice") return;

      const blocked = events.some(isFailureStage);
      const card = el("article", "hop-report" + (blocked ? " is-blocked" : ""));
      const head = el("div", "hop-report-head");
      head.appendChild(el("span", "hop-report-name", name));
      head.appendChild(el("span", "hop-report-role", role));
      card.appendChild(head);

      if (serviceId === "alice") {
        const synthetic = el("ol", "stage-list");
        ["built 3 AES-GCM layers", "encrypted the message for Bob"].forEach((text) => {
          const item = el("li", "stage");
          item.appendChild(el("span", "stage-dot"));
          item.appendChild(el("span", "", text));
          item.appendChild(el("span", "stage-time", "client"));
          synthetic.appendChild(item);
        });
        card.appendChild(synthetic);
      } else {
        card.appendChild(reportStages(events));
      }

      const knowledge = el("div", "knowledge");
      if (serviceId === "alice") {
        knowledge.appendChild(knowledgeLine("knows", "route, plaintext before encryption"));
        knowledge.appendChild(knowledgeLine("cannot know", "whether Bob reads it"));
      } else if (serviceId === bobServiceId()) {
        knowledge.appendChild(knowledgeLine("sees", "E2E plaintext after decrypting"));
        knowledge.appendChild(knowledgeLine("cannot verify", "an authenticated sender identity"));
      } else {
        const previous = order[index - 1];
        const previousName = previous ? $(".hop-name", previous).textContent : "previous hop";
        const decrypted = events.find((event) => event.stage === "decrypted");
        let successor = "?";
        if (decrypted) successor = decrypted.instruction === "exit" ? decrypted.receiver_id : decrypted.next_hop_id;
        const received = events.find((event) => event.stage === "received");
        knowledge.appendChild(
          knowledgeLine(
            "sees",
            previousName + " → " + (successor || "?") +
              (received && received.packet_bytes ? " · " + formatInt(received.packet_bytes) + " B" : "")
          )
        );
        knowledge.appendChild(knowledgeLine("cannot see", "message · receiver · hops beyond next"));
      }
      card.appendChild(knowledge);
      inspector.appendChild(card);
    });

    if (!inspector.children.length) setInspectorPlaceholder();
    const badge = $("#inspector-badge");
    if (badge) {
      const failed = trace.some(isFailureStage);
      badge.textContent = failed ? "packet blocked" : "3 relays · E2E delivered";
    }
  }

  function renderLayers(trace) {
    const chart = $("#layers-chart");
    const caption = $("#layers-caption");
    if (!chart) return;
    clear(chart);

    const received = trace.filter(
      (event) => event.service_type === "relay" && event.stage === "received" && Number(event.packet_bytes) > 0
    );
    if (!received.length) {
      chart.appendChild(el("p", "empty small", "Sizes appear after the first send."));
      if (caption) caption.textContent = "";
      return;
    }

    const max = Math.max.apply(null, received.map((event) => Number(event.packet_bytes)));
    received.forEach((event) => {
      const row = el("div", "layer-row");
      row.appendChild(el("span", "layer-label", serviceLabel(event.service_id) + " receives"));
      const track = el("span", "layer-track");
      const fill = el("span", "layer-fill");
      const share = Math.max(6, Math.round((Number(event.packet_bytes) / max) * 100));
      fill.style.width = share + "%";
      track.appendChild(fill);
      row.appendChild(track);
      row.appendChild(el("span", "layer-bytes", formatInt(event.packet_bytes) + " B"));
      chart.appendChild(row);
    });

    if (caption) {
      const first = Number(received[0].packet_bytes);
      const last = Number(received[received.length - 1].packet_bytes);
      caption.textContent =
        first === last
          ? "Every relay receives exactly " + formatInt(first) + " B. Fixed-size cells hide which hop a packet is on and how long the message is."
          : "The envelope shrinks from " + formatInt(first) + " B at Relay A to " + formatInt(last) +
            " B at the exit: each peel removes one wrapped AES key and one routing instruction.";
    }
  }

  // Send
  const form = $("#send-form");
  const input = $("#message-input");
  const sendButton = $("#send-button");
  const maxChars = input ? Number(input.getAttribute("maxlength")) || 4000 : 4000;

  function updateCounter() {
    const counter = $("#char-count");
    if (!counter || !input) return;
    const length = input.value.length;
    counter.textContent = formatInt(length) + " / " + formatInt(maxChars);
    counter.classList.toggle("is-warn", length > maxChars * 0.85 && length <= maxChars);
    counter.classList.toggle("is-over", length > maxChars);
  }

  function setFeedback(text, kind) {
    const feedback = $("#send-feedback");
    if (!feedback) return;
    feedback.textContent = text;
    feedback.classList.toggle("is-error", kind === "error");
    feedback.classList.toggle("is-success", kind === "success");
  }

  function setSendBusy(busy) {
    if (!sendButton) return;
    sendButton.disabled = busy;
    sendButton.classList.toggle("is-loading", busy);
    const label = $(".btn-label", sendButton);
    if (label) label.textContent = busy ? "Sealing the onion…" : "Seal & send onion";
    const badge = $("#composer-badge");
    if (badge) badge.textContent = busy ? "encrypting" : "ready";
  }

  async function handleSend(event) {
    event.preventDefault();
    if (state.sending || !input) return;
    const message = input.value.trim();
    if (!message) {
      setFeedback("Write a message first — even the demo needs plaintext to protect.", "error");
      input.focus();
      return;
    }
    if (message.length > maxChars) {
      setFeedback("Messages are limited to " + formatInt(maxChars) + " characters.", "error");
      return;
    }

    state.sending = true;
    setSendBusy(true);
    setFeedback("Building the onion — encrypting for Bob, then wrapping layers for Relay C, B and A…", "");
    setInspectorPlaceholder();
    try {
      const result = await api("/api/send", {
        method: "POST",
        body: JSON.stringify({ message: message }),
      });
      const trace = Array.isArray(result.trace) ? result.trace : [];
      await playTrace(trace);
      renderInspector(trace);
      renderLayers(trace);

      const failed = trace.some(isFailureStage);
      if (failed) {
        setFeedback("The packet was rejected before delivery. Inspect the blocked hop below.", "error");
        toast("The packet was blocked.", "error");
      } else {
        setFeedback(
          "Delivered to Bob as message #" + formatInt(result.message_id) + ". Only Bob can read the plaintext.",
          "success"
        );
        toast("Onion delivered to Bob.", "success");
        input.value = "";
        updateCounter();
      }

      loadInbox({ quiet: true });
      loadOverview({ quiet: true });
      loadEvents({ quiet: true });
    } catch (error) {
      setCircuitSummary("Send failed · " + error.message, "error");
      setFeedback(error.message + " Check the event log for the failure category.", "error");
      toast("Could not send the message: " + error.message, "error");
      loadEvents({ quiet: true });
    } finally {
      state.sending = false;
      setSendBusy(false);
    }
  }

  function initComposer() {
    if (form) form.addEventListener("submit", handleSend);
    if (input) {
      input.addEventListener("input", updateCounter);
      input.addEventListener("keydown", (event) => {
        if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
          event.preventDefault();
          if (form) form.requestSubmit();
        }
      });
      updateCounter();
    }
    $$(".example").forEach((button) => {
      button.addEventListener("click", () => {
        if (!input) return;
        input.value = button.dataset.message || button.textContent || "";
        updateCounter();
        input.focus();
        input.setSelectionRange(input.value.length, input.value.length);
      });
    });
  }

  // Inbox and events
  async function loadInbox(options) {
    const opts = options || {};
    const token = ++state.inboxRequest;
    const list = $("#inbox-list");
    if (!list) return;
    try {
      const data = await api("/api/messages?limit=20");
      if (token !== state.inboxRequest) return;
      const messages = data.messages || [];
      clear(list);
      if (!messages.length) {
        list.appendChild(el("p", "empty", "No messages delivered yet. Send one as Alice."));
      } else {
        messages.forEach((message) => {
          const card = el("article", "message");
          const head = el("div", "message-head");
          head.appendChild(el("span", "", "message #" + formatInt(message.id) + " · " + message.receiver_id));
          const time = el("time", "", formatTimestamp(message.received_at));
          if (message.received_at) time.dateTime = message.received_at;
          head.appendChild(time);
          card.appendChild(head);
          card.appendChild(el("p", "message-body", message.message));
          list.appendChild(card);
        });
      }
      updateInboxCount(Number.isFinite(Number(data.total)) ? data.total : messages.length);
    } catch (error) {
      if (!opts.quiet) toast("Could not load Bob's inbox.", "error");
    }
  }

  async function loadEvents(options) {
    const opts = options || {};
    const token = ++state.eventsRequest;
    const body = $("#event-body");
    if (!body) return;
    const filter = $("#event-filter");
    const service = filter ? filter.value : "";
    const url = "/api/events?limit=80" + (service ? "&service=" + encodeURIComponent(service) : "");
    try {
      const data = await api(url);
      if (token !== state.eventsRequest) return;
      const events = data.events || [];
      clear(body);
      if (!events.length) {
        const row = el("tr");
        const dataCell = cell("No events match this filter yet.", "empty small");
        dataCell.colSpan = 6;
        row.appendChild(dataCell);
        body.appendChild(row);
        return;
      }
      events.forEach((event) => {
        const row = el("tr");
        const time = cell(formatTimeOnly(event.timestamp));
        time.title = formatTimestamp(event.timestamp);
        row.appendChild(time);
        row.appendChild(cell(serviceLabel(event.service_id)));
        row.appendChild(cell(humanize(event.event_type), "mono"));
        row.appendChild(cell(pillFor(event.status)));
        row.appendChild(
          cell(
            Number.isFinite(Number(event.duration_ms)) ? Number(event.duration_ms).toFixed(1) + " ms" : "—",
            "mode"
          )
        );
        row.appendChild(cell(event.error_category ? humanize(event.error_category) : "—"));
        body.appendChild(row);
      });
    } catch (error) {
      if (!opts.quiet) toast("Could not load the event log.", "error");
    }
  }

  function initLogs() {
    const refresh = $("#events-refresh");
    if (refresh) {
      refresh.addEventListener("click", () => withBusy(refresh, () => loadEvents({ quiet: false })));
    }
    const filter = $("#event-filter");
    if (filter) filter.addEventListener("change", () => loadEvents({ quiet: false }));
    const servicesRefresh = $("#services-refresh");
    if (servicesRefresh) {
      servicesRefresh.addEventListener("click", () =>
        withBusy(servicesRefresh, () => loadOverview({ quiet: false }))
      );
    }
    const inboxRefresh = $("#inbox-refresh");
    if (inboxRefresh) {
      inboxRefresh.addEventListener("click", () => withBusy(inboxRefresh, () => loadInbox({ quiet: false })));
    }
  }

  // Security lab
  function setAttackResultPending(button) {
    const card = $("#attack-result");
    if (!card) return;
    card.hidden = false;
    card.classList.remove("is-blocked", "is-bypassed");
    $("#attack-verdict-label").textContent = "Running";
    $("#attack-code").textContent = "…";
    $("#attack-title").textContent = button.dataset.attackTitle || "Experiment";
    $("#attack-explanation").textContent = "Submitting the hostile packet to the real relay services…";
    $("#attack-actual").textContent = "pending";
    $("#attack-expected").textContent = "—";
    $("#attack-outcome").textContent = "pending";
    clear($("#attack-trace"));
    $("#attack-trace").appendChild(el("li", "trace-item", "Waiting for relay processing…"));
    $("#attack-trace-note").hidden = true;
  }

  function renderAttackResult(data) {
    const card = $("#attack-result");
    if (!card) return;
    card.hidden = false;
    const blocked = Boolean(data.blocked);
    card.classList.toggle("is-blocked", blocked);
    card.classList.toggle("is-bypassed", !blocked);

    $("#attack-verdict-label").textContent = blocked ? "Attack blocked" : "Attack not blocked";
    $("#attack-code").textContent = "HTTP " + data.status_code;
    $("#attack-title").textContent = data.title || "Experiment";
    $("#attack-explanation").textContent = data.explanation || "";
    $("#attack-actual").textContent = "HTTP " + data.status_code;
    $("#attack-expected").textContent = "HTTP " + data.expected;

    let outcome = blocked ? "Rejected before delivery" : "Packet may have progressed";
    if (data.attack === "replay" && data.first_status_code) {
      outcome = "First: HTTP " + data.first_status_code + " · second: HTTP " + data.status_code;
    }
    $("#attack-outcome").textContent = outcome;

    const trace = Array.isArray(data.trace) ? data.trace : [];
    const list = $("#attack-trace");
    clear(list);
    trace.forEach((event) => {
      const bad = isFailureStage(event);
      const item = el("li", "trace-item " + (bad ? "is-bad" : "is-good"));
      item.appendChild(el("span", "trace-service", serviceLabel(event.service_id)));
      item.appendChild(el("span", "trace-stage", stageText(event)));
      const duration = Number.isFinite(Number(event.duration_ms))
        ? Number(event.duration_ms).toFixed(1) + " ms"
        : "—";
      item.appendChild(el("span", "trace-time", duration));
      list.appendChild(item);
    });

    const note = $("#attack-trace-note");
    if (!trace.length) {
      note.hidden = false;
      note.textContent =
        "Rejected at the HTTP boundary before any relay stage ran — the body-size limit fires before packet parsing.";
      list.appendChild(el("li", "trace-item", "No hop trace: request rejected before relay processing."));
    } else {
      note.hidden = true;
    }

    if (window.matchMedia("(max-width: 1080px)").matches) {
      card.scrollIntoView({ block: "nearest", behavior: reducedMotion.matches ? "auto" : "smooth" });
    }
  }

  function appendAttackLog(data) {
    const log = $("#attack-log");
    if (!log) return;
    const empty = $("#attack-log-empty");
    if (empty) empty.remove();

    const entry = el("div", "log-entry");
    entry.appendChild(el("span", "log-entry-name", data.title || humanize(data.attack)));
    const code = el(
      "span",
      "log-entry-code " + (data.blocked ? "is-blocked" : "is-bypassed"),
      (data.blocked ? "blocked · " : "passed · ") + "HTTP " + data.status_code
    );
    entry.appendChild(code);
    log.prepend(entry);

    while (log.children.length > 8) log.removeChild(log.lastElementChild);
    const counter = $("#attack-log-count");
    if (counter) counter.textContent = String(log.children.length);
  }

  async function runAttack(button) {
    if (state.attacksRunning) return;
    const attack = button.dataset.attack;
    if (!attack) return;
    const runLabel = $(".attack-run", button);
    const originalRun = runLabel ? runLabel.textContent : null;
    state.attacksRunning = true;
    $$(".attack-card").forEach((card) => {
      card.disabled = true;
    });
    if (runLabel) runLabel.textContent = "Running…";
    button.dataset.attackTitle = $(".attack-title", button) ? $(".attack-title", button).textContent : "Experiment";
    setAttackResultPending(button);

    try {
      const data = await api("/api/attack", {
        method: "POST",
        body: JSON.stringify({ attack: attack }),
      });
      renderAttackResult(data);
      appendAttackLog(data);
      if (data.blocked) {
        toast("Attack blocked with HTTP " + data.status_code + ".", "success");
      } else {
        toast("Attack was not blocked — inspect the result.", "error");
      }
      loadEvents({ quiet: true });
      loadOverview({ quiet: true });
    } catch (error) {
      const card = $("#attack-result");
      if (card) {
        card.hidden = false;
        card.classList.remove("is-blocked", "is-bypassed");
        $("#attack-verdict-label").textContent = "Error";
        $("#attack-code").textContent = "—";
        $("#attack-title").textContent = "Experiment could not run";
        $("#attack-explanation").textContent = error.message;
        $("#attack-actual").textContent = "—";
        $("#attack-expected").textContent = "—";
        $("#attack-outcome").textContent = "error";
        clear($("#attack-trace"));
        $("#attack-trace").appendChild(el("li", "trace-item", "No relay response received."));
        $("#attack-trace-note").hidden = true;
      }
      toast("Experiment failed: " + error.message, "error");
    } finally {
      state.attacksRunning = false;
      $$(".attack-card").forEach((card) => {
        card.disabled = false;
      });
      if (runLabel && originalRun !== null) runLabel.textContent = originalRun;
    }
  }

  function initLab() {
    $$(".attack-card").forEach((button) => {
      button.addEventListener("click", () => runAttack(button));
    });
  }

  // Learn tab: layer explainer
  const LAYER_INFO = {
    a: {
      lead: "Relay A (entry)",
      body:
        " unwraps the outer layer with its private key. It learns that the previous hop is Alice and the next hop is Relay B, plus the packet size. It cannot see Relay C, Bob, or the message.",
    },
    b: {
      lead: "Relay B (middle)",
      body:
        " can only open the layer addressed to its key. It learns Relay A as predecessor and Relay C as successor. Alice, Bob, and the plaintext remain hidden.",
    },
    c: {
      lead: "Relay C (exit)",
      body:
        " peels the final onion layer and learns the receiver identity, Bob. It still only holds Bob's encrypted E2E envelope — never Bob's private key or the plaintext.",
    },
    core: {
      lead: "Bob (receiver)",
      body:
        " unwraps the E2E key with his own private key and decrypts the message. No relay ever possessed that key, so the message stayed confidential across all three hops.",
    },
  };

  function showOnionLayer(key) {
    const explain = $("#onion-explain");
    const stack = $("#onion-stack");
    if (!explain) return;
    const info = LAYER_INFO[key] || LAYER_INFO.core;
    explain.replaceChildren();
    const lead = el("strong", "", info.lead);
    explain.appendChild(lead);
    explain.appendChild(document.createTextNode(info.body));
    if (stack) {
      $$(".onion-shell", stack).forEach((shell) => shell.classList.remove("is-active"));
      const selected = $('[data-layer="' + key + '"]', stack);
      if (selected) selected.classList.add("is-active");
    }
  }

  function initLearn() {
    const stack = $("#onion-stack");
    if (!stack) return;
    stack.addEventListener("click", (event) => {
      const shell = event.target.closest(".onion-shell");
      if (!shell) return;
      showOnionLayer(shell.dataset.layer);
    });
    stack.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      const shell = event.target.closest(".onion-shell");
      if (!shell) return;
      event.preventDefault();
      showOnionLayer(shell.dataset.layer);
    });
  }

  // Tooltips
  function initTooltips() {
    const closeAll = () => $$(".info.is-open").forEach((node) => node.classList.remove("is-open"));
    $$(".info").forEach((node) => {
      node.addEventListener("click", (event) => {
        event.stopPropagation();
        const wasOpen = node.classList.contains("is-open");
        closeAll();
        if (!wasOpen) node.classList.add("is-open");
      });
      node.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
          node.classList.remove("is-open");
          node.blur();
        }
      });
    });
    document.addEventListener("click", closeAll);
  }

  // Reset
  async function handleReset(button) {
    const confirmed = window.confirm(
      "Clear all delivered messages, replay caches, and event logs? Key files are kept."
    );
    if (!confirmed) return;
    const result = $("#reset-result");
    if (result) result.textContent = "Clearing demo data…";
    try {
      const data = await api("/api/reset", { method: "POST" });
      const cleared = data.cleared || {};
      resetCircuitVisuals();
      setInspectorPlaceholder();
      renderLayers([]);
      setFeedback("Demo data cleared. New messages start with empty logs and replay caches.", "success");
      if (result) {
        result.textContent =
          "Cleared " + formatInt(cleared.messages) + " messages, " +
          formatInt(cleared.events) + " events, and " +
          formatInt(cleared.replays) + " replay records.";
      }
      const log = $("#attack-log");
      if (log) {
        clear(log);
        const empty = el("p", "empty small", "No experiments run yet.");
        empty.id = "attack-log-empty";
        log.appendChild(empty);
      }
      const count = $("#attack-log-count");
      if (count) count.textContent = "0";
      const resultCard = $("#attack-result");
      if (resultCard) resultCard.hidden = true;
      toast("Demo data cleared.", "success");
      await Promise.all([loadInbox({ quiet: true }), loadEvents({ quiet: true }), loadOverview({ quiet: true })]);
    } catch (error) {
      if (result) result.textContent = "Reset failed: " + error.message;
      toast("Reset failed: " + error.message, "error");
    }
  }

  function initReset() {
    const button = $("#reset-button");
    if (!button) return;
    button.addEventListener("click", () => withBusy(button, () => handleReset(button)));
  }

  // Traffic analysis experiment
  function percent(value) {
    return Math.round(Number(value) * 100) + "%";
  }

  function renderTrafficResult(data) {
    const body = $("#traffic-body");
    if (!body) return;
    clear(body);
    (data.scenarios || []).forEach((row) => {
      const tr = el("tr");
      const name = el("th", "", row.title);
      name.scope = "row";
      tr.appendChild(name);
      [row.size_attack_accuracy, row.timing_attack_accuracy].forEach((value) => {
        // Close to a blind guess = the attack learned nothing.
        const defended = Number(value) <= Number(data.random_guess) * 2;
        tr.appendChild(cell(el("span", "pill " + (defended ? "success" : "failure"), percent(value))));
      });
      tr.appendChild(cell(formatInt(Math.round(row.avg_latency_ms)) + " ms"));
      tr.appendChild(cell(formatInt(row.bytes_per_message) + " B"));
      tr.appendChild(
        cell((row.link_bytes || []).map((link) => formatInt(link.avg_bytes)).join(" → "), "small mono")
      );
      body.appendChild(tr);
    });
    const note = $("#traffic-note");
    if (note) {
      note.textContent =
        data.senders + " users × " + data.rounds + " rounds. A blind guess links " + percent(data.random_guess) +
        " of messages; green means the attack did no better than about twice that. Experiment messages are removed from Bob's inbox afterwards.";
    }
    $("#traffic-result").hidden = false;
  }

  function initTraffic() {
    const button = $("#traffic-run");
    if (!button) return;
    button.addEventListener("click", () =>
      withBusy(button, async () => {
        const status = $("#traffic-status");
        if (status) status.textContent = "Sending traffic through the relays… (a few seconds)";
        try {
          const mix = Number($("#traffic-mix").value) || 250;
          const data = await api("/api/traffic-analysis", {
            method: "POST",
            body: JSON.stringify({ senders: 6, rounds: 3, mix_delay_ms: mix }),
          });
          renderTrafficResult(data);
          if (status) status.textContent = "Done.";
          loadEvents({ quiet: true });
        } catch (error) {
          if (status) status.textContent = "";
          toast("Experiment failed: " + error.message, "error");
        }
      })
    );
  }

  // Key lifecycle (rotate / revoke / probe)
  const KEY_STATUS_PILL = {
    active: "success",
    retired: "rejected",
    expired: "",
    revoked: "failure",
  };

  function keyStatusPill(status) {
    const node = el("span", "pill", status);
    const extra = KEY_STATUS_PILL[status];
    if (extra) node.classList.add(extra);
    return node;
  }

  function epochToIso(seconds) {
    if (seconds === null || seconds === undefined) return null;
    return new Date(Number(seconds) * 1000).toISOString();
  }

  function keyNote(key) {
    if (key.status === "active") return "advertised to senders";
    if (key.status === "retired") return "accepted for " + formatInt(key.grace_remaining_seconds) + " s more";
    if (key.status === "expired") return "grace ended · private key destroyed";
    if (key.status === "revoked") return "revoked: " + (key.reason || "manual") + " · private key destroyed";
    return "—";
  }

  function lifecycleButton(label, action, data, extraClass) {
    const button = el("button", "btn ghost small" + (extraClass ? " " + extraClass : ""), label);
    button.type = "button";
    button.dataset.action = action;
    Object.keys(data).forEach((name) => {
      button.dataset[name] = data[name];
    });
    return button;
  }

  function renderLifecycle(services) {
    const list = $("#lifecycle-list");
    if (!list) return;
    clear(list);
    state.hasRetiredKeys = false;
    (services || []).forEach((service) => {
      const block = el("section", "lifecycle-service");
      const head = el("div", "lifecycle-head");
      const title = el("h3", "lifecycle-title", serviceLabel(service.service_id));
      title.appendChild(el("span", "lifecycle-role", service.role));
      head.appendChild(title);
      const rotate = lifecycleButton("Rotate key", "rotate", { service: service.service_id });
      rotate.setAttribute("aria-label", "Rotate the key of " + serviceLabel(service.service_id));
      head.appendChild(rotate);
      block.appendChild(head);

      const wrap = el("div", "table-wrap");
      const table = el("table", "table lifecycle-table");
      const thead = el("thead");
      const headRow = el("tr");
      ["Key ID", "Status", "Fingerprint", "Created", "Note", "Actions"].forEach((label) => {
        const th = el("th", "", label);
        th.scope = "col";
        headRow.appendChild(th);
      });
      thead.appendChild(headRow);
      table.appendChild(thead);
      const body = el("tbody");
      (service.keys || []).forEach((key) => {
        if (key.status === "retired") state.hasRetiredKeys = true;
        const row = el("tr");
        const id = el("th", "", "");
        id.scope = "row";
        id.appendChild(el("span", "mode", key.key_id));
        row.appendChild(id);
        row.appendChild(cell(keyStatusPill(key.status)));
        row.appendChild(cell(el("span", "fingerprint", key.fingerprint)));
        row.appendChild(cell(formatTimeOnly(epochToIso(key.created_at))));
        row.appendChild(cell(keyNote(key), "small"));
        const actions = el("td", "lifecycle-actions");
        actions.appendChild(
          lifecycleButton("Send test onion", "probe", { service: service.service_id, key: key.key_id })
        );
        if (key.status !== "revoked") {
          actions.appendChild(
            lifecycleButton("Revoke", "revoke", { service: service.service_id, key: key.key_id }, "danger-ghost")
          );
        }
        row.appendChild(actions);
        body.appendChild(row);
      });
      table.appendChild(body);
      wrap.appendChild(table);
      block.appendChild(wrap);
      list.appendChild(block);
    });
    if (!list.children.length) list.appendChild(el("p", "empty small", "Key rings unavailable."));
  }

  async function loadKeys(options) {
    const opts = options || {};
    try {
      const data = await api("/api/keys");
      renderLifecycle(data.services || []);
      const badge = $("#grace-badge");
      if (badge && data.grace_seconds !== undefined) badge.textContent = "grace " + data.grace_seconds + " s";
      return data;
    } catch (error) {
      if (!opts.quiet) toast("Could not load key rings.", "error");
      return null;
    }
  }

  function renderProbeResult(data) {
    const box = $("#probe-result");
    if (!box) return;
    clear(box);
    box.hidden = false;
    box.classList.toggle("is-ok", Boolean(data.delivered));
    box.classList.toggle("is-blocked", !data.delivered);

    const verdict = data.delivered
      ? "Delivered. " + serviceLabel(data.service_id) + " accepted " + data.key_status + " key " + data.key_id + "."
      : "Rejected by " + serviceLabel(data.rejected_by || data.service_id) + ": " +
        humanize(data.error_category || "rejected") + ". The packet never reached Bob.";
    box.appendChild(el("p", "probe-verdict", verdict));

    if (data.key_status === "retired" && data.delivered) {
      box.appendChild(
        el("p", "micro", "This key was rotated out but is still inside its grace period, so in-flight packets are not lost.")
      );
    }
    if (!data.delivered) {
      box.appendChild(
        el("p", "micro", "Entry relay HTTP status: " + data.status_code + ". Every hop before the rejecting one did its normal work; the stale key is caught exactly where it is used.")
      );
    }

    const steps = el("ol", "probe-steps");
    (data.trace || [])
      .filter((event) => ["decrypted", "rejected", "stored"].indexOf(event.stage) !== -1)
      .forEach((event) => {
        let text = serviceLabel(event.service_id) + " · " + humanize(event.stage);
        if (event.key_status) text += " with " + event.key_status + " key";
        if (event.error_category) text += " · " + humanize(event.error_category);
        steps.appendChild(el("li", event.stage === "rejected" ? "is-rejected" : "", text));
      });
    if (steps.children.length) box.appendChild(steps);
  }

  async function handleLifecycleAction(button) {
    const action = button.dataset.action;
    const service = button.dataset.service;
    const key = button.dataset.key;
    if (action === "rotate") {
      const data = await api("/api/keys/rotate", {
        method: "POST",
        body: JSON.stringify({ service_id: service }),
      });
      renderLifecycle(data.services);
      toast(serviceLabel(service) + " rotated to " + data.active.key_id + ".", "success");
      loadOverview({ quiet: true });
    } else if (action === "revoke") {
      const reason = window.prompt(
        "Revoke " + key + "? Packets using it will be rejected immediately and its private key destroyed.\n\nReason:",
        "suspected compromise"
      );
      if (reason === null) return;
      const data = await api("/api/keys/revoke", {
        method: "POST",
        body: JSON.stringify({ service_id: service, key_id: key, reason: reason || "manual revocation" }),
      });
      renderLifecycle(data.services);
      let message = key + " revoked.";
      if (data.replacement) message += " New active key: " + data.replacement.key_id + ".";
      toast(message, "success");
      loadOverview({ quiet: true });
    } else if (action === "probe") {
      const data = await api("/api/keys/probe", {
        method: "POST",
        body: JSON.stringify({ service_id: service, key_id: key }),
      });
      renderProbeResult(data);
      loadEvents({ quiet: true });
      loadInbox({ quiet: true });
    }
  }

  function initLifecycle() {
    const list = $("#lifecycle-list");
    if (!list) return;
    list.addEventListener("click", (event) => {
      const button = event.target.closest("button[data-action]");
      if (!button || state.keyActionBusy) return;
      state.keyActionBusy = true;
      button.classList.add("is-loading");
      withBusy(button, () => handleLifecycleAction(button))
        .catch((error) => toast("Key action failed: " + error.message, "error"))
        .finally(() => {
          state.keyActionBusy = false;
          button.classList.remove("is-loading");
        });
    });
    // Keep grace-period countdowns honest while the Keys tab is open.
    window.setInterval(() => {
      const panel = $("#panel-keys");
      if (panel && !panel.hidden && state.hasRetiredKeys && !state.keyActionBusy) loadKeys({ quiet: true });
    }, 5000);
  }

  // Guided tour
  const TOUR_KEY = "onionchat.tour.v1";
  const TOUR_STEPS = [
    {
      tab: "circuit",
      target: "#composer-card",
      title: "1 · Send your first onion",
      text:
        "Type a message as Alice, or pick an example. The message is encrypted for Bob first, then wrapped in three relay layers — one per hop.",
    },
    {
      tab: "circuit",
      target: "#circuit-card",
      title: "2 · Watch all three hops",
      text:
        "Press “Seal & send onion”. The animation follows the real relay events: Relay A peels layer one, Relay B layer two, and Relay C delivers to Bob.",
    },
    {
      tab: "circuit",
      target: "#hop-inspector",
      title: "3 · Inspect what each hop saw",
      text:
        "After the send, this panel shows each hop's view. Relays learn only their neighbours; none of them can read the message or see the whole path.",
    },
    {
      tab: "lab",
      target: "#attack-grid",
      title: "4 · Try to break the protocol",
      text:
        "The Security Lab runs real attacks: tampering, replay, wrong keys, SSRF-style next hops, oversized packets. Each verdict is based on the actual HTTP response.",
    },
    {
      tab: "keys",
      target: "#keys-card",
      title: "5 · Keys and logs, never plaintext",
      text:
        "Inspect public key fingerprints, service counters, and sanitised events. Rotate or revoke any key, then send a test onion to see the relays enforce it. Private keys stay on the server.",
    },
  ];

  function clearTourHighlights() {
    $$(".tour-target").forEach((node) => node.classList.remove("tour-target"));
  }

  function showTourStep(index) {
    if (!state.tourOpen) return;
    const bounded = Math.max(0, Math.min(index, TOUR_STEPS.length - 1));
    state.tourIndex = bounded;
    const step = TOUR_STEPS[bounded];
    clearTourHighlights();
    activateTab(step.tab, { updateHash: false });

    $("#tour-title").textContent = step.title;
    $("#tour-text").textContent = step.text;
    $("#tour-progress").textContent = "Step " + (bounded + 1) + " of " + TOUR_STEPS.length;
    $("#tour-back").disabled = bounded === 0;
    $("#tour-next").textContent = bounded === TOUR_STEPS.length - 1 ? "Finish" : "Next";

    const reveal = () => {
      const target = $(step.target);
      if (target) {
        target.scrollIntoView({ block: "center", behavior: reducedMotion.matches ? "auto" : "smooth" });
        target.classList.add("tour-target");
      }
      const next = $("#tour-next");
      if (next) next.focus({ preventScroll: true });
    };

    if (reducedMotion.matches) {
      reveal();
    } else {
      window.setTimeout(reveal, 80);
    }
  }

  function startTour(index) {
    state.tourOpen = true;
    state.tourIndex = index || 0;
    const overlay = $("#tour");
    if (overlay) overlay.hidden = false;
    document.body.classList.add("tour-open");
    showTourStep(state.tourIndex);
  }

  function endTour(completed) {
    if (!state.tourOpen) return;
    state.tourOpen = false;
    clearTourHighlights();
    const overlay = $("#tour");
    if (overlay) overlay.hidden = true;
    document.body.classList.remove("tour-open");
    try {
      localStorage.setItem(TOUR_KEY, completed ? "complete" : "skipped");
    } catch (error) {
      /* storage can be disabled; the tour still remains dismissible */
    }
    if (completed) toast("Tour complete. Send a message to try it yourself.", "success");
  }

  function initTour() {
    const overlay = $("#tour");
    if (!overlay) return;
    $("#tour-start").addEventListener("click", () => startTour(0));
    $("#tour-skip").addEventListener("click", () => endTour(false));
    $("#tour-back").addEventListener("click", () => showTourStep(state.tourIndex - 1));
    $("#tour-next").addEventListener("click", () => {
      if (state.tourIndex >= TOUR_STEPS.length - 1) endTour(true);
      else showTourStep(state.tourIndex + 1);
    });
    $$("[data-tour-close]").forEach((node) => node.addEventListener("click", () => endTour(false)));

    overlay.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        endTour(false);
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = $$(".tour-card button:not(:disabled)", overlay);
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    });

    let seen = null;
    try {
      seen = localStorage.getItem(TOUR_KEY);
    } catch (error) {
      seen = null;
    }
    if (!seen) {
      window.setTimeout(() => startTour(0), 850);
    }
  }

  // Init
  function init() {
    initTabs();
    initComposer();
    initLab();
    initLogs();
    initLearn();
    initTooltips();
    initReset();
    initLifecycle();
    initTraffic();
    initTour();
    resetCircuitVisuals();
    setInspectorPlaceholder();
    renderLayers([]);

    loadOverview({ quiet: false }).catch(() => {});
    loadInbox({ quiet: true });
    loadEvents({ quiet: true });
    loadKeys({ quiet: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
