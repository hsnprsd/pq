/* Shared pure checks, also exercised with Node's built-in test runner. */
(function (root) {
  "use strict";
  function origin(raw) {
    try {
      const url = new URL(raw);
      if (url.protocol !== "https:" || url.username || url.password) return null;
      return url.origin;
    } catch (_) { return null; }
  }
  function senderOrigin(sender) {
    if (!sender.tab || !Number.isInteger(sender.tab.id) || sender.frameId !== 0) return null;
    const page = origin(sender.url);
    return page && page === origin(sender.tab.url) ? page : null;
  }
  function validCandidate(candidate) {
    return candidate && typeof candidate.username === "string" && candidate.username.length <= 4096 &&
      typeof candidate.password === "string" && candidate.password.length > 0 && candidate.password.length <= 65536;
  }
  const api = Object.freeze({ origin, senderOrigin, validCandidate });
  root.PQSecurity = api;
  if (typeof module !== "undefined") module.exports = api;
})(globalThis);
