/* global browser, PQSecurity */
"use strict";

const pending = new Map();
const loginChoices = new Map();
const candidateTTL = 120000;

async function native(request) {
  const response = await browser.runtime.sendNativeMessage("pq", request);
  if (response.error) { const error = new Error(response.error); error.code = response.code; throw error; }
  return response;
}

async function activePage() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  if (!tab || !Number.isInteger(tab.id)) throw new Error("No active tab.");
  const origin = PQSecurity.origin(tab.url);
  if (!origin) throw new Error("Filling and saving are restricted to HTTPS websites.");
  return { tab, origin };
}

async function verifyPage(tabId, origin, automatic = false) {
  const tab = await browser.tabs.get(tabId);
  if (PQSecurity.origin(tab.url) !== origin || (automatic && !tab.active)) throw new Error("The page changed; try again.");
}

async function fill(tabId, origin, id, automatic = false) {
  const response = await native({ op: "browser.get", origin, id });
  try {
    await verifyPage(tabId, origin, automatic);
    const result = await browser.tabs.sendMessage(tabId, {
      type: "fill", origin, automatic,
      username: response.entry.username || "", password: response.entry.password || ""
    }, { frameId: 0 });
    if (!result || result.error) throw new Error(result?.error || "Could not fill the login.");
  } finally { if (response.entry) response.entry.password = ""; }
}

async function requestAutofill() {
  try {
    const { tab, origin } = await activePage();
    await browser.tabs.sendMessage(tab.id, { type: "autofill", origin }, { frameId: 0 });
  } catch (_) { /* Unlock still succeeds if the current page has no content script. */ }
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

browser.tabs.onRemoved.addListener(tabId => { forget(tabId); loginChoices.delete(tabId); });
browser.tabs.onUpdated.addListener((tabId, change) => {
  if (change.url) {
    loginChoices.delete(tabId);
    const value = pending.get(tabId);
    if (value && value.origin !== PQSecurity.origin(change.url)) forget(tabId);
  }
});

browser.runtime.onMessage.addListener(async (message, sender) => {
  try {
    // Content scripts may signal a login form or select a previously offered
    // login, but never receive passwords in a response. Use Firefox's origin.
    if (sender.tab) {
      const origin = PQSecurity.senderOrigin(sender);
      if (!origin) throw new Error("Untrusted content request.");
      if (message.type === "autofill") {
        await verifyPage(sender.tab.id, origin, true);
        const entries = (await native({ op: "browser.list", origin })).entries || [];
        loginChoices.delete(sender.tab.id);
        if (entries.length === 1) await fill(sender.tab.id, origin, entries[0].id, true);
        else if (entries.length > 1) {
          await verifyPage(sender.tab.id, origin, true);
          loginChoices.set(sender.tab.id, { origin, ids: new Set(entries.map(entry => entry.id)), expires: Date.now() + candidateTTL });
          const result = await browser.tabs.sendMessage(sender.tab.id, {
            type: "choose", origin,
            entries: entries.map(entry => ({ id: entry.id, title: entry.title, username: entry.username }))
          }, { frameId: 0 });
          if (!result || result.error) {
            loginChoices.delete(sender.tab.id);
            throw new Error(result?.error || "Could not show the login chooser.");
          }
        }
      } else if (message.type === "autofill.select") {
        const choices = loginChoices.get(sender.tab.id);
        if (!choices || choices.origin !== origin || choices.expires <= Date.now() || !choices.ids.has(message.id)) throw new Error("The login choices expired. Use the pq toolbar popup or reload the page.");
        await verifyPage(sender.tab.id, origin, true);
        loginChoices.delete(sender.tab.id);
        await fill(sender.tab.id, origin, message.id, true);
      } else if (message.type === "candidate" && PQSecurity.validCandidate(message)) {
        remember(sender.tab.id, origin, message);
      } else throw new Error("Untrusted content request.");
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
        if (!response.status.locked) {
          try { entries = (await native({ op: "browser.list", origin: page.origin })).entries || []; }
          catch (error) {
            if (error.code !== "locked") throw error;
            response.status = (await native({ op: "status" })).status;
          }
        }
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
        await requestAutofill();
        return { ok: true };
      }
      case "ui.lock":
        await native({ op: "lock" });
        loginChoices.clear();
        for (const tabId of pending.keys()) forget(tabId);
        return { ok: true };
      case "ui.fill": {
        const { tab, origin } = await activePage();
        await fill(tab.id, origin, message.id);
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
