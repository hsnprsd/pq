/* global browser, PQSecurity */
"use strict";

const pending = new Map();
const candidateTTL = 120000;

async function native(request) {
  const response = await browser.runtime.sendNativeMessage("pq", request);
  if (response.error) throw new Error(response.error);
  return response;
}

async function activePage() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  if (!tab || !Number.isInteger(tab.id)) throw new Error("No active tab.");
  const origin = PQSecurity.origin(tab.url);
  if (!origin) throw new Error("Filling and saving are restricted to HTTPS websites.");
  return { tab, origin };
}

async function verifyPage(tabId, origin) {
  const tab = await browser.tabs.get(tabId);
  if (PQSecurity.origin(tab.url) !== origin) throw new Error("The page changed; try again.");
}

function forget(tabId) {
  const old = pending.get(tabId);
  if (old) { clearTimeout(old.timer); old.password = ""; pending.delete(tabId); }
  browser.browserAction.setBadgeText({ tabId, text: "" }).catch(() => {});
}

function remember(tabId, origin, candidate) {
  if (!PQSecurity.validCandidate(candidate)) throw new Error("No usable login found.");
  forget(tabId);
  const value = { origin, username: candidate.username, password: candidate.password, expires: Date.now() + candidateTTL };
  value.timer = setTimeout(() => forget(tabId), candidateTTL);
  pending.set(tabId, value);
  browser.browserAction.setBadgeBackgroundColor({ tabId, color: "#245b39" }).catch(() => {});
  browser.browserAction.setBadgeText({ tabId, text: "+" }).catch(() => {});
}

function currentCandidate(tabId, origin) {
  const value = pending.get(tabId);
  if (!value || value.expires <= Date.now() || value.origin !== origin) return null;
  return value;
}

browser.tabs.onRemoved.addListener(forget);
browser.tabs.onUpdated.addListener((tabId, change) => {
  if (change.url) {
    const value = pending.get(tabId);
    if (value && value.origin !== PQSecurity.origin(change.url)) forget(tabId);
  }
});

browser.runtime.onMessage.addListener(async (message, sender) => {
  try {
    // Content scripts can suggest a save, never request stored credentials.
    if (sender.tab) {
      const origin = PQSecurity.senderOrigin(sender);
      if (message.type !== "candidate" || !origin || !PQSecurity.validCandidate(message)) throw new Error("Untrusted content request.");
      remember(sender.tab.id, origin, message);
      return { ok: true };
    }
    if (sender.id !== browser.runtime.id || sender.url !== browser.runtime.getURL("popup.html")) throw new Error("Untrusted extension request.");
    switch (message.type) {
      case "ui.state": {
        const response = await native({ op: "status" });
        let page;
        try { page = await activePage(); } catch (error) { return { status: response.status, pageError: error.message, entries: [] }; }
        const candidate = currentCandidate(page.tab.id, page.origin);
        let entries = [];
        if (!response.status.locked) entries = (await native({ op: "browser.list", origin: page.origin })).entries || [];
        return { status: response.status, origin: page.origin, entries, candidate: candidate ? { username: candidate.username } : null };
      }
      case "ui.unlock": {
        if (typeof message.password !== "string") throw new Error("Enter the master password.");
        const bytes = new TextEncoder().encode(message.password);
        message.password = "";
        if (bytes.length > 4096) { bytes.fill(0); throw new Error("Master password is too long."); }
        let encoded = btoa(String.fromCharCode(...bytes));
        bytes.fill(0);
        try { await native({ op: "unlock", password: encoded, ttl: message.ttl || "" }); }
        finally { encoded = ""; }
        return { ok: true };
      }
      case "ui.lock":
        await native({ op: "lock" });
        for (const tabId of pending.keys()) forget(tabId);
        return { ok: true };
      case "ui.fill": {
        const { tab, origin } = await activePage();
        const response = await native({ op: "browser.get", origin, id: message.id });
        try {
          await verifyPage(tab.id, origin);
          const result = await browser.tabs.sendMessage(tab.id, { type: "fill", origin, username: response.entry.username || "", password: response.entry.password || "" }, { frameId: 0 });
          if (!result || result.error) throw new Error(result?.error || "Could not fill the login.");
        } finally { if (response.entry) response.entry.password = ""; }
        return { ok: true };
      }
      case "ui.capture": {
        const { tab, origin } = await activePage();
        const candidate = await browser.tabs.sendMessage(tab.id, { type: "capture", origin }, { frameId: 0 });
        await verifyPage(tab.id, origin);
        if (!candidate || candidate.error) throw new Error(candidate?.error || "No login form found.");
        remember(tab.id, origin, candidate);
        return { ok: true };
      }
      case "ui.save": {
        const { tab, origin } = await activePage();
        const candidate = currentCandidate(tab.id, origin);
        if (!candidate) throw new Error("The suggested login expired. Capture the form again.");
        const matches = ((await native({ op: "browser.list", origin })).entries || []).filter(entry => (entry.username || "") === candidate.username);
        if (matches.length > 1) throw new Error("Multiple logins have that username. Update the desired entry using the CLI.");
        await verifyPage(tab.id, origin);
        await native({ op: "browser.save", origin, entry: { id: matches[0]?.id || "", title: origin, username: candidate.username, password: candidate.password } });
        forget(tab.id);
        return { ok: true };
      }
      default: throw new Error("Unknown extension operation.");
    }
  } catch (error) { return { error: error.message || "pq operation failed." }; }
});
