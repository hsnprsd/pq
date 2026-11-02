/* global browser */
"use strict";
const $ = id => document.getElementById(id);
let expiryTimer;

async function request(message) {
  const response = await browser.runtime.sendMessage(message);
  if (!response || response.error) throw new Error(response?.error || "No response from pq.");
  return response;
}
function showError(error) { $("error").textContent = error.message; $("error").hidden = false; }

async function refresh() {
  const state = await request({ type: "ui.state" });
  const { status } = state;
  clearTimeout(expiryTimer);
  if (!status.locked) expiryTimer = setTimeout(() => refresh().catch(showError), Math.max(1, Date.parse(status.expires_at) - Date.now() + 50));
  $("unlock").hidden = !status.locked || !status.initialized;
  $("lock").hidden = status.locked;
  $("vault").hidden = status.locked || !state.origin;
  $("status").textContent = !status.initialized ? "Run pq init in a terminal first." : status.locked ? "Vault locked" : `Unlocked until ${new Date(status.expires_at).toLocaleTimeString()}`;
  $("ttl").placeholder = status.default_ttl;
  $("origin").textContent = state.origin || "";
  $("entries").replaceChildren();
  if (!status.locked && state.origin) {
    if (state.entries.length === 0) $("entries").textContent = "No matching logins.";
    for (const entry of state.entries) {
      const button = document.createElement("button");
      button.textContent = `${entry.title} — ${entry.username || "(no username)"}`;
      button.addEventListener("click", () => perform(async () => { await request({ type: "ui.fill", id: entry.id }); window.close(); }));
      $("entries").append(button);
    }
    $("pending").hidden = !state.candidate;
    $("candidate").textContent = state.candidate ? `Ready to save login for ${state.candidate.username || "(no username)"}. Expires after two minutes.` : "";
  }
  if (state.pageError && !status.locked) $("status").textContent += ` · ${state.pageError}`;
}

async function perform(action) {
  $("error").hidden = true;
  for (const button of document.querySelectorAll("button")) button.disabled = true;
  try { await action(); await refresh(); } catch (error) { await refresh().catch(() => {}); showError(error); }
  finally { for (const button of document.querySelectorAll("button")) button.disabled = false; }
}

$("unlock").addEventListener("submit", event => {
  event.preventDefault();
  let password = $("master").value;
  $("master").value = "";
  const operation = request({ type: "ui.unlock", password, ttl: $("ttl").value.trim() });
  password = "";
  perform(() => operation);
});
$("lock").addEventListener("click", () => perform(() => request({ type: "ui.lock" })));
$("capture").addEventListener("click", () => perform(() => request({ type: "ui.capture" })));
$("save").addEventListener("click", () => perform(() => request({ type: "ui.save" })));
refresh().catch(showError);
