"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const { origin, senderOrigin, validCandidate } = require("./security.js");

test("origins require HTTPS and canonicalize default ports", () => {
  assert.equal(origin("https://Example.COM:443/login"), "https://example.com");
  for (const url of ["http://example.com", "https://alice:password@example.com", "javascript:alert(1)", "file:///tmp/x"]) assert.equal(origin(url), null);
  assert.notEqual(origin("https://example.com"), origin("https://example.com.evil.test"));
});

test("only same-origin top-frame content senders are trusted", () => {
  const sender = { tab: { id: 1, url: "https://example.com/login" }, frameId: 0, url: "https://example.com/form" };
  assert.equal(senderOrigin(sender), "https://example.com");
  assert.equal(senderOrigin({ ...sender, frameId: 1 }), null);
  assert.equal(senderOrigin({ ...sender, url: "https://evil.test" }), null);
  assert.equal(senderOrigin({ ...sender, tab: undefined }), null);
  assert.equal(senderOrigin({ ...sender, url: "about:blank" }), null);
});

test("save candidates have bounded, nonempty credential fields", () => {
  assert.ok(validCandidate({ username: "", password: "a" }));
  for (const candidate of [{}, { username: "a", password: "" }, { username: {}, password: "a" }, { username: "a", password: "a".repeat(65537) }]) assert.ok(!validCandidate(candidate));
});
