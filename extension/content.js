/* global browser */
(() => {
  "use strict";
  if (window.top !== window) return;

  function visible(input) {
    const style = getComputedStyle(input);
    const rect = input.getBoundingClientRect();
    return !input.disabled && !input.readOnly && style.display !== "none" && style.visibility !== "hidden" && Number(style.opacity) !== 0 && rect.width > 0 && rect.height > 0;
  }

  function safeForm(form) {
    const page = new URL(location.href);
    if (page.protocol !== "https:") throw new Error("HTTPS is required.");
    if (form) {
      const action = new URL(form.action || page.href, page.href);
      if (action.origin !== page.origin || action.username || action.password) throw new Error("Cross-origin form actions are not supported.");
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
      if (message.type !== "fill") return undefined;
      const { username, password } = selectFields(false);
      if (username) { safeForm(username.form); setValue(username, message.username); }
      // Website input handlers may mutate or replace the form. Recheck before
      // releasing the password, and refuse fields detached by those handlers.
      if (!password.isConnected || !visible(password)) throw new Error("The login form changed; try again.");
      safeForm(password.form);
      setValue(password, message.password);
      return Promise.resolve({ ok: true });
    } catch (error) { return Promise.resolve({ error: error.message }); }
  });
})();
