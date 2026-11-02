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
  const state = { url: "https://example.com/login", navigateOnGet: false };
  const event = { addListener() {} };
  const browser = {
    runtime: {
      id: "pq@local", getURL: file => `moz-extension://test/${file}`,
      onMessage: { addListener(callback) { listener = callback; } },
      async sendNativeMessage(host, request) {
        assert.equal(host, "pq"); calls.push(structuredClone(request));
        switch (request.op) {
          case "status": return { status: { locked: false, initialized: true } };
          case "browser.list": return { entries: [{ id: "entry", title: "Example", username: "alice" }] };
          case "browser.get":
            if (state.navigateOnGet) state.url = "https://evil.test";
            return { entry: { username: "alice", password: "stored-secret" } };
          default: return {};
        }
      }
    },
    tabs: {
      async query() { return [{ id: 1, url: state.url }]; },
      async get() { return { id: 1, url: state.url }; },
      async sendMessage(id, message, options) { fills.push({ id, message: structuredClone(message), options }); return { ok: true }; },
      onRemoved: event, onUpdated: event
    },
    browserAction: { async setBadgeText() {}, async setBadgeBackgroundColor() {} }
  };
  const context = vm.createContext({ browser, PQSecurity, URL, TextEncoder, btoa, setTimeout: () => 1, clearTimeout() {} });
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
