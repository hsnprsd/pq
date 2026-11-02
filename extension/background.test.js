"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");
const PQSecurity = require("./security.js");

function harness() {
  let listener;
  const calls = [], fills = [];
  const state = {
    url: "https://example.com/login", active: true, navigateOnGet: false, deactivateOnGet: false,
    now: 0, locked: false, expireOnList: false, entries: [{ id: "entry", title: "Example", username: "alice" }]
  };
  const event = { addListener() {} };
  const browser = {
    runtime: {
      id: "pq@local", getURL: file => `moz-extension://test/${file}`,
      onMessage: { addListener(callback) { listener = callback; } },
      async sendNativeMessage(host, request) {
        assert.equal(host, "pq"); calls.push(structuredClone(request));
        switch (request.op) {
          case "status": return { status: { locked: state.locked, initialized: true } };
          case "browser.list":
            if (state.locked || state.expireOnList) { state.locked = true; return { error: "Vault locked", code: "locked" }; }
            return { entries: state.entries };
          case "browser.get":
            if (state.navigateOnGet) state.url = "https://evil.test";
            if (state.deactivateOnGet) state.active = false;
            return { entry: { username: "alice", password: "stored-secret" } };
          default: return {};
        }
      }
    },
    tabs: {
      async query() { return [{ id: 1, url: state.url }]; },
      async get() { return { id: 1, url: state.url, active: state.active }; },
      async sendMessage(id, message, options) { fills.push({ id, message: structuredClone(message), options }); return { ok: true }; },
      onRemoved: event, onUpdated: event
    },
    browserAction: { async setBadgeText() {}, async setBadgeBackgroundColor() {} }
  };
  const context = vm.createContext({ browser, PQSecurity, URL, TextEncoder, btoa, Date: { now: () => state.now }, setTimeout: () => 1, clearTimeout() {} });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "background.js"), "utf8"), context);
  return { calls, fills, state, send: (message, sender = { id: "pq@local", url: "moz-extension://test/popup.html" }) => listener(message, sender) };
}

const contentSender = { tab: { id: 1, url: "https://example.com" }, frameId: 0, url: "https://example.com/login" };

test("content scripts cannot request stored credentials or spoof popup messages", async () => {
  const h = harness();
  assert.ok((await h.send({ type: "ui.fill", id: "entry" }, contentSender)).error);
  assert.ok((await h.send({ type: "ui.fill", id: "entry" }, { id: "other", url: "moz-extension://test/popup.html" })).error);
  assert.equal(h.calls.length, 0);
});

test("filling uses the active tab's origin and only its top frame", async () => {
  const h = harness();
  assert.ok((await h.send({ type: "ui.fill", id: "entry", origin: "https://evil.test" })).ok);
  assert.equal(h.calls[0].origin, "https://example.com");
  assert.equal(h.fills[0].message.password, "stored-secret");
  assert.equal(h.fills[0].options.frameId, 0);
});

test("autofill selects the sole exact-origin login without returning credentials to its caller", async () => {
  const h = harness();
  const response = await h.send({ type: "autofill", id: "attacker-chosen", origin: "https://evil.test" }, contentSender);
  assert.equal(response.ok, true);
  assert.equal(response.entry, undefined);
  assert.equal(response.password, undefined);
  assert.deepEqual(h.calls, [
    { op: "browser.list", origin: "https://example.com" },
    { op: "browser.get", origin: "https://example.com", id: "entry" }
  ]);
  assert.equal(h.fills[0].message.automatic, true);
  assert.equal(h.fills[0].message.password, "stored-secret");
  assert.equal(h.fills[0].id, contentSender.tab.id);
  assert.equal(h.fills[0].options.frameId, 0);
});

test("autofill does nothing when no login matches", async () => {
  const h = harness(); h.state.entries = [];
  assert.equal((await h.send({ type: "autofill" }, contentSender)).ok, true);
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].op, "browser.list");
  assert.equal(h.fills.length, 0);
});

test("multiple matches open a chooser without fetching any passwords", async () => {
  const h = harness();
  h.state.entries = [{ id: "first", title: "First", username: "alice", password: "never-forward" }, { id: "second", title: "Second", username: "bob" }];
  assert.equal((await h.send({ type: "autofill" }, contentSender)).ok, true);
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].op, "browser.list");
  const chooser = h.fills[0];
  assert.equal(chooser.id, contentSender.tab.id);
  assert.equal(chooser.options.frameId, 0);
  assert.equal(chooser.message.type, "choose");
  assert.equal(chooser.message.origin, "https://example.com");
  assert.deepEqual(chooser.message.entries, [
    { id: "first", title: "First", username: "alice" }, { id: "second", title: "Second", username: "bob" }
  ]);
  assert.equal((await h.send({ type: "autofill.select", id: "second", origin: "https://evil.test" }, contentSender)).ok, true);
  assert.deepEqual(h.calls[1], { op: "browser.get", origin: "https://example.com", id: "second" });
  assert.equal(h.fills[1].message.type, "fill");
  assert.equal(h.fills[1].message.automatic, true);
  assert.ok((await h.send({ type: "autofill.select", id: "second" }, contentSender)).error, "selections cannot be replayed");
});

test("chooser selections must come from the offered logins and the original active top frame", async () => {
  const fresh = harness();
  assert.ok((await fresh.send({ type: "autofill.select", id: "entry" }, contentSender)).error);
  assert.equal(fresh.calls.length, 0);
  for (const [id, sender, change] of [
    ["unlisted", contentSender, {}],
    ["first", { ...contentSender, frameId: 1 }, {}],
    ["first", { ...contentSender, url: "https://evil.test" }, {}],
    ["first", contentSender, { active: false }],
    ["first", contentSender, { now: 120001 }],
    ["first", contentSender, { url: "https://evil.test" }]
  ]) {
    const h = harness(); h.state.entries = [{ id: "first" }, { id: "second" }];
    await h.send({ type: "autofill" }, contentSender);
    Object.assign(h.state, change);
    assert.ok((await h.send({ type: "autofill.select", id }, sender)).error);
    assert.equal(h.calls.length, 1, "invalid selections never fetch a password");
  }
});

test("autofill refuses locked vaults and inactive, navigated, or untrusted senders", async () => {
  for (const change of [{ locked: true }, { active: false }, { url: "https://evil.test" }, { navigateOnGet: true }, { deactivateOnGet: true }]) {
    const h = harness(); Object.assign(h.state, change);
    assert.ok((await h.send({ type: "autofill" }, contentSender)).error);
    assert.equal(h.fills.length, 0);
  }
  for (const sender of [
    { ...contentSender, frameId: 1 },
    { ...contentSender, url: "https://evil.test" },
    { ...contentSender, url: "http://example.com", tab: { id: 1, url: "http://example.com" } }
  ]) {
    const h = harness();
    assert.ok((await h.send({ type: "autofill" }, sender)).error);
    assert.equal(h.calls.length, 0);
  }
});

test("unlocking asks the active top frame to retry autofill", async () => {
  const h = harness();
  assert.equal((await h.send({ type: "ui.unlock", password: "synthetic master" })).ok, true);
  assert.equal(h.calls[0].op, "unlock");
  assert.equal(h.fills[0].message.type, "autofill");
  assert.equal(h.fills[0].message.origin, "https://example.com");
  assert.equal(h.fills[0].options.frameId, 0);
});

test("expiry during popup loading returns a locked state rather than stranding the UI", async () => {
  const h = harness(); h.state.expireOnList = true;
  const response = await h.send({ type: "ui.state" });
  assert.equal(response.status.locked, true);
  assert.equal(response.entries.length, 0);
});

test("navigation while fetching a credential prevents filling", async () => {
  const h = harness(); h.state.navigateOnGet = true;
  assert.ok((await h.send({ type: "ui.fill", id: "entry" })).error);
  assert.equal(h.fills.length, 0);
});

test("capturing never writes until the popup confirms save", async () => {
  const h = harness();
  assert.ok((await h.send({ type: "candidate", username: "alice", password: "new-secret", origin: "https://evil.test" }, contentSender)).ok);
  assert.equal(h.calls.length, 0);
  assert.ok((await h.send({ type: "ui.save" })).ok);
  const save = h.calls.find(call => call.op === "browser.save");
  assert.equal(save.origin, "https://example.com");
  assert.equal(save.entry.id, "entry");
  assert.equal(save.entry.password, "new-secret");
  assert.ok((await h.send({ type: "ui.save" })).error);
});

test("cross-origin or iframe save candidates are rejected", async () => {
  const h = harness();
  for (const sender of [{ ...contentSender, frameId: 1 }, { ...contentSender, url: "https://evil.test" }]) {
    assert.ok((await h.send({ type: "candidate", username: "alice", password: "a" }, sender)).error);
  }
  assert.ok((await h.send({ type: "ui.save" })).error);
  assert.equal(h.calls.length, 0);
});
