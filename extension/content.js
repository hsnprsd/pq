/* global browser */
(() => {
  "use strict";
  if (window.top !== window || location.protocol !== "https:") return;

  const autofilled = new WeakSet();
  const offered = new WeakSet();
  let chooser;
  let autofillTimer;
  let autofillPending = false;

  function visible(input) {
    const style = getComputedStyle(input);
    const rect = input.getBoundingClientRect();
    return !input.disabled && !input.readOnly && style.display !== "none" && style.visibility !== "hidden" && Number(style.opacity) !== 0 &&
      input.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true }) &&
      rect.width > 0 && rect.height > 0 && rect.bottom > 0 && rect.right > 0 && rect.top < innerHeight && rect.left < innerWidth;
  }

  function safeForm(form) {
    const page = new URL(location.href);
    if (page.protocol !== "https:") throw new Error("HTTPS is required.");
    if (form) {
      const actions = [form.action, ...[...form.elements].filter(element => element.hasAttribute("formaction")).map(element => element.formAction)];
      for (const raw of actions) {
        const action = new URL(raw || page.href, page.href);
        if (action.origin !== page.origin || action.username || action.password) throw new Error("Cross-origin form actions are not supported.");
      }
    }
  }

  function passwordFields(root) {
    return [...root.querySelectorAll('input[type="password"]')].filter(visible);
  }

  function usernameField(root, password) {
    const inputs = [...root.querySelectorAll('input[autocomplete="username"], input[type="email"], input[type="text"], input:not([type])')].filter(visible);
    const explicit = inputs.find(input => input.autocomplete === "username");
    if (explicit) return explicit;
    return inputs.filter(input => input.compareDocumentPosition(password) & Node.DOCUMENT_POSITION_FOLLOWING).at(-1) || inputs[0];
  }

  function selectFields(forCapture, submittedForm) {
    const focused = document.activeElement;
    const focusedForm = focused instanceof HTMLInputElement ? focused.form : null;
    const root = submittedForm || focusedForm || document;
    const passwords = passwordFields(root);
    if (passwords.length === 0) throw new Error("No visible password field found.");
    let password;
    if (forCapture) {
      password = passwords.filter(input => input.autocomplete === "new-password").at(-1) || passwords.at(-1);
    } else {
      const current = passwords.filter(input => input.autocomplete === "current-password");
      if (current.length === 1) password = current[0];
      else if (passwords.length === 1 && passwords[0].autocomplete !== "new-password") password = passwords[0];
      else throw new Error("Multiple or registration password fields found; select a login form first.");
    }
    safeForm(password.form);
    const username = usernameField(password.form || root, password);
    return { username, password };
  }

  function autofillFields() {
    if (document.visibilityState !== "visible") throw new Error("The page is not visible.");
    const fields = selectFields(false, chooser?.password.form);
    if (fields.password.value || fields.username?.value || autofilled.has(fields.password)) throw new Error("The login form is already filled.");
    if (fields.username) safeForm(fields.username.form);
    return fields;
  }

  function scheduleAutofill() {
    clearTimeout(autofillTimer);
    autofillTimer = setTimeout(async () => {
      if (autofillPending) return;
      try {
        if (chooser && !chooser.password.isConnected) closeChooser();
        const { password } = autofillFields();
        if (offered.has(password)) return;
        autofillPending = true;
        await browser.runtime.sendMessage({ type: "autofill" });
      } catch (_) { /* Locked, ambiguous, and unsafe forms require no prompt. */ }
      finally { autofillPending = false; }
    }, 150);
  }

  function closeChooser() {
    chooser?.host.remove();
    chooser = null;
  }

  function showChoices(entries) {
    const { password } = autofillFields();
    if (offered.has(password)) return;
    closeChooser();
    const host = document.createElement("div");
    host.id = "pq-login-chooser";
    const shadow = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style");
    style.textContent = `
      :host { all: initial; position: fixed; bottom: 16px; right: 16px; z-index: 2147483647; }
      section { box-sizing: border-box; width: min(340px, calc(100vw - 32px)); max-height: min(420px, calc(100vh - 32px)); overflow: auto;
        padding: 16px; border: 1px solid #a7b5ad; border-radius: 10px; background: #fff; color: #17201c;
        box-shadow: 0 4px 24px #0003; font: 500 13px/1.5 "IBM Plex Mono Medium", "IBM Plex Mono", monospace; }
      header { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
      p { margin: 8px 0; overflow-wrap: anywhere; }
      button { box-sizing: border-box; display: block; width: 100%; margin-top: 8px; padding: 8px; text-align: left;
        font: inherit; color: inherit; background: #f1f5f2; border: 1px solid #a7b5ad; border-radius: 5px; cursor: pointer; overflow-wrap: anywhere; }
      button:hover { background: #e0ebe3; } button:focus-visible { outline: 2px solid #245b39; }
      header button { width: auto; margin: 0; } [role="alert"] { color: #9b2020; }
    `;
    const panel = document.createElement("section");
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-label", "pq: choose a login");
    const header = document.createElement("header");
    const title = document.createElement("strong");
    title.textContent = "pq · Choose a login";
    const close = document.createElement("button");
    close.type = "button";
    close.textContent = "×";
    close.setAttribute("aria-label", "Dismiss login chooser");
    close.addEventListener("click", closeChooser);
    header.append(title, close);
    const origin = document.createElement("p");
    origin.textContent = location.origin;
    const error = document.createElement("p");
    error.setAttribute("role", "alert");
    panel.append(header, origin);
    const buttons = [];
    for (const entry of entries) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = `${entry.username || "(no username)"} — ${entry.title || location.origin}`;
      button.addEventListener("click", async event => {
        if (!event.isTrusted) return;
        event.stopPropagation();
        for (const item of buttons) item.disabled = true;
        try {
          if (autofillFields().password !== password) throw new Error("The login form changed; reload the page.");
          const response = await browser.runtime.sendMessage({ type: "autofill.select", id: entry.id });
          if (!response || response.error) throw new Error(response?.error || "Could not fill the login.");
          closeChooser();
        } catch (failure) { error.textContent = failure.message; }
        finally { for (const item of buttons) item.disabled = false; }
      });
      buttons.push(button);
      panel.append(button);
    }
    panel.append(error);
    panel.addEventListener("keydown", event => { if (event.key === "Escape") { event.stopPropagation(); closeChooser(); } });
    shadow.append(style, panel);
    offered.add(password);
    chooser = { host, password };
    document.documentElement.append(host);
  }

  function capture(form) {
    const { username, password } = selectFields(true, form);
    if (!password.value || password.value.length > 65536) throw new Error("The password field is empty or too long.");
    return { username: username?.value || "", password: password.value };
  }

  function setValue(input, value) {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  document.addEventListener("submit", event => {
    if (!(event.target instanceof HTMLFormElement)) return;
    try {
      const candidate = capture(event.target);
      browser.runtime.sendMessage({ type: "candidate", ...candidate }).catch(() => {});
    } catch (_) { /* Never interfere with website submission. */ }
  }, true);

  browser.runtime.onMessage.addListener(message => {
    if (message.origin !== location.origin || location.protocol !== "https:") return Promise.resolve({ error: "The website origin changed." });
    try {
      if (message.type === "capture") return Promise.resolve(capture());
      if (message.type === "autofill") { scheduleAutofill(); return Promise.resolve({ ok: true }); }
      if (message.type === "choose") { showChoices(message.entries); return Promise.resolve({ ok: true }); }
      if (message.type !== "fill") return undefined;
      const { username, password } = message.automatic ? autofillFields() : selectFields(false);
      if (username) { safeForm(username.form); setValue(username, message.username); }
      // Website input handlers may mutate or replace the form. Recheck before
      // releasing the password, and refuse fields detached by those handlers.
      if (!password.isConnected || !visible(password) || (message.automatic && password.value)) throw new Error("The login form changed; try again.");
      safeForm(password.form);
      if (message.automatic) autofilled.add(password);
      setValue(password, message.password);
      closeChooser();
      return Promise.resolve({ ok: true });
    } catch (error) { return Promise.resolve({ error: error.message }); }
  });

  new MutationObserver(scheduleAutofill).observe(document.documentElement, {
    subtree: true, childList: true, attributes: true,
    attributeFilter: ["type", "autocomplete", "style", "class", "hidden", "disabled", "readonly", "action", "formaction"]
  });
  document.addEventListener("visibilitychange", scheduleAutofill);
  document.addEventListener("focusin", scheduleAutofill);
  window.addEventListener("focus", scheduleAutofill);
  window.addEventListener("pageshow", scheduleAutofill);
  scheduleAutofill();
})();
