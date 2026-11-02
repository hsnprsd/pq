"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const path = require("node:path");

function harness({ empty = false, protocol = "https:", iframe = false } = {}) {
  let listener, observer;
  const requests = [], timers = new Map(), events = new Map();
  let timerId = 0;
  const inputs = [];
  class Element {
    constructor(tag) { this.tag = tag; this.children = []; this.events = new Map(); }
    setAttribute(name, value) { this[name] = value; }
    append(...children) { for (const child of children) { child.parent = this; this.children.push(child); } }
    remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); }
    addEventListener(name, callback) { this.events.set(name, callback); }
    attachShadow(options) { this.shadow = new Element("shadow"); this.shadow.mode = options.mode; return this.shadow; }
  }
  class Input {
    constructor(type, autocomplete) {
      Object.assign(this, {
        type, autocomplete, form: null, isConnected: true, disabled: false, readOnly: false,
        style: { display: "block", visibility: "visible", opacity: "1" }, _value: ""
      });
    }
    get value() { return this._value; }
    set value(value) { this._value = value; }
    checkVisibility() { return true; }
    getBoundingClientRect() { return { width: 100, height: 20, top: 0, left: 0, right: 100, bottom: 20 }; }
    compareDocumentPosition(other) { return inputs.indexOf(this) < inputs.indexOf(other) ? 4 : 0; }
    dispatchEvent(event) { if (event.type === "input") this.oninput?.(); }
    hasAttribute() { return false; }
  }
  function query(selector) {
    return inputs.filter(input => input.isConnected && (selector === 'input[type="password"]' ? input.type === "password" : input.type === "text"));
  }
  class Form {
    constructor() { this.action = "https://example.com/login"; this.elements = inputs; }
    querySelectorAll(selector) { return query(selector); }
  }
  const form = new Form();
  const username = new Input("text", "username"), password = new Input("password", "current-password");
  username.form = password.form = form;
  if (!empty) inputs.push(username, password);
  const document = {
    activeElement: null, visibilityState: "visible", documentElement: new Element("html"), querySelectorAll: query,
    createElement(tag) { return new Element(tag); },
    addEventListener(name, callback) { events.set(name, callback); }
  };
  const window = { addEventListener(name, callback) { events.set(name, callback); } };
  window.top = iframe ? {} : window;
  const context = vm.createContext({
    window, document, location: { protocol, href: `${protocol}//example.com/login`, origin: `${protocol}//example.com` },
    URL, WeakSet, Event, HTMLInputElement: Input, HTMLFormElement: Form, Node: { DOCUMENT_POSITION_FOLLOWING: 4 },
    innerWidth: 1024, innerHeight: 768, getComputedStyle: input => input.style,
    MutationObserver: class { constructor(callback) { observer = callback; } observe() {} },
    setTimeout(callback) { timers.set(++timerId, callback); return timerId; },
    clearTimeout(id) { timers.delete(id); },
    browser: { runtime: {
      async sendMessage(message) { requests.push(message); return { ok: true }; },
      onMessage: { addListener(callback) { listener = callback; } }
    } }
  });
  vm.runInContext(fs.readFileSync(path.join(__dirname, "content.js"), "utf8"), context);
  return {
    requests, username, password, form, inputs, document,
    chooser() { return document.documentElement.children.find(child => child.id === "pq-login-chooser"); },
    choose(entries) { return listener({ type: "choose", origin: "https://example.com", entries }); },
    mutate() { observer?.(); },
    event(name) { events.get(name)?.(); },
    async flush() {
      const callbacks = [...timers.values()]; timers.clear();
      for (const callback of callbacks) await callback();
    },
    fill(automatic = true) { return listener({ type: "fill", origin: "https://example.com", username: "alice", password: "stored-secret", automatic }); }
  };
}

test("an empty login form requests autofill on load and is filled without submitting", async () => {
  const h = harness();
  await h.flush();
  assert.equal(h.requests.length, 1);
  assert.equal(h.requests[0].type, "autofill");
  assert.equal((await h.fill()).ok, true);
  assert.equal(h.username.value, "alice");
  assert.equal(h.password.value, "stored-secret");
  h.username.value = h.password.value = "";
  h.mutate(); await h.flush();
  assert.equal(h.requests.length, 1, "a cleared autofilled field is not refilled");
});

test("dynamically added and newly visible forms trigger debounced autofill", async () => {
  const h = harness({ empty: true });
  await h.flush();
  assert.equal(h.requests.length, 0);
  h.inputs.push(h.username, h.password);
  h.mutate(); h.mutate(); h.mutate();
  await h.flush();
  assert.equal(h.requests.length, 1);
  h.document.visibilityState = "hidden";
  h.event("visibilitychange"); await h.flush();
  assert.equal(h.requests.length, 1);
  h.document.visibilityState = "visible";
  h.event("visibilitychange"); await h.flush();
  assert.equal(h.requests.length, 2);
  h.event("focus"); await h.flush();
  assert.equal(h.requests.length, 3);
});

test("automatic filling never overwrites values, including input entered during retrieval", async () => {
  for (const field of ["username", "password"]) {
    const h = harness();
    h[field].value = "user input";
    await h.flush();
    assert.equal(h.requests.length, 0);
    assert.ok((await h.fill()).error);
    assert.equal(h[field].value, "user input");
    assert.equal((await h.fill(false)).ok, true, "manual selection may replace values");
  }
  const h = harness(); await h.flush();
  h.username.value = "typed while waiting";
  assert.ok((await h.fill()).error);
  assert.equal(h.password.value, "");
});

test("autofill refuses unsafe, hidden, registration, and ambiguous forms", async () => {
  for (const configure of [
    h => { h.form.action = "https://evil.test"; },
    h => { h.password.style.display = "none"; },
    h => { h.password.style.opacity = "0"; },
    h => { h.password.disabled = true; },
    h => { h.password.readOnly = true; },
    h => { h.password.autocomplete = "new-password"; },
    h => { h.password.autocomplete = ""; h.inputs.push(h.password); }
  ]) {
    const h = harness(); configure(h);
    await h.flush();
    assert.equal(h.requests.length, 0);
    assert.ok((await h.fill()).error);
    assert.equal(h.password.value, "");
  }
});

test("username input handlers cannot redirect, detach, or overwrite the password field", async () => {
  for (const mutate of [
    h => { h.form.action = "https://evil.test"; },
    h => { h.password.isConnected = false; },
    h => { h.password.value = "website value"; }
  ]) {
    const h = harness();
    h.username.oninput = () => mutate(h);
    assert.ok((await h.fill()).error);
    assert.notEqual(h.password.value, "stored-secret");
  }
});

test("multiple logins appear in a closed-shadow chooser and only trusted clicks select an account", async () => {
  const h = harness(); await h.flush();
  const entries = [{ id: "first", username: "alice", title: "Personal" }, { id: "second", username: "bob", title: "Work" }];
  assert.equal((await h.choose(entries)).ok, true);
  const host = h.chooser();
  assert.equal(host.shadow.mode, "closed");
  const panel = host.shadow.children[1];
  assert.equal(panel.role, "dialog");
  const buttons = panel.children.filter(child => child.tag === "button");
  assert.deepEqual(buttons.map(button => button.textContent), ["alice — Personal", "bob — Work"]);
  const click = buttons[1].events.get("click");
  await click({ isTrusted: false });
  assert.equal(h.requests.length, 1, "website-generated clicks cannot request credentials");
  await click({ isTrusted: true, stopPropagation() {} });
  assert.equal(h.requests.length, 2);
  assert.equal(h.requests[1].type, "autofill.select");
  assert.equal(h.requests[1].id, "second");
  assert.equal(h.chooser(), undefined);
});

test("dismissing the chooser does not repeatedly reopen it", async () => {
  const h = harness(); await h.flush();
  await h.choose([{ id: "first" }, { id: "second" }]);
  const panel = h.chooser().shadow.children[1];
  panel.children[0].children[1].events.get("click")();
  assert.equal(h.chooser(), undefined);
  h.mutate(); h.event("focusin"); await h.flush();
  assert.equal(h.requests.length, 1);
});

test("an open chooser cannot overwrite values typed before account selection", async () => {
  const h = harness(); await h.flush();
  await h.choose([{ id: "first" }, { id: "second" }]);
  h.username.value = "typed username";
  const panel = h.chooser().shadow.children[1];
  await panel.children[2].events.get("click")({ isTrusted: true, stopPropagation() {} });
  assert.equal(h.requests.length, 1);
  assert.equal(h.password.value, "");
  assert.equal(h.username.value, "typed username");
});

test("content scripts do not request autofill on HTTP pages or in iframes", async () => {
  for (const options of [{ protocol: "http:" }, { iframe: true }]) {
    const h = harness(options); await h.flush();
    assert.equal(h.requests.length, 0);
  }
});
