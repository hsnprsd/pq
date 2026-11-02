# Implementation plan

Build a Linux-first, local password manager in Go. A systemd user daemon owns an encrypted SQLCipher vault. A CLI and a Firefox native-messaging host communicate with it over a private Unix socket. The daemon starts locked and enforces an absolute, configurable unlock TTL.

## Milestones

1. [x] Validate SQLCipher and native-messaging dependencies; establish project structure.
2. [x] Implement encrypted storage, transactional CRUD/import, password changes, and encrypted backups.
3. [x] Implement the daemon, secure local protocol, TTL, CLI, and systemd integration.
4. [x] Implement Firefox CSV and read-only NSS profile imports.
5. [x] Implement the Firefox extension and native host, with origin-restricted credential access.
6. [x] Test the complete workflow, harden edge cases, and document installation and security boundaries.

Verification: Go race tests and vet, Node extension tests, web-ext lint, synthetic NSS profile imports, CLI/native-host subprocess tests, and a real headless Firefox HTTPS form fill/save and native-messaging smoke test all pass on Fedora. See [README.md](README.md) for reproducible commands and [SECURITY.md](SECURITY.md) for remaining security/release work. A signed Firefox release and independent security review are not part of this completed implementation milestone.

Commit each working milestone separately. Run automated tests and real CLI smoke tests before considering the implementation complete.

## Security decisions

- Use system SQLCipher's key API and supported password KDF, not custom cryptography.
- Keep credentials out of command arguments, environment variables, logs, and unencrypted files.
- Cache an unlocked database connection, not the master password. Close it on lock, expiry, and shutdown.
- Restrict the Unix socket and vault directory to the current user; validate peer credentials.
- Use absolute unlock expiry, defaulting to 15 minutes. Browser activity cannot extend it.
- Automatically prefill unambiguous empty login forms, enforce exact origin matching, and require confirmed save/update operations.
- Never expose generic secret entries through the browser API.
- No cloud sync, sharing, passkeys, or TOTP in this initial implementation.

## Limitations to document

Firefox extensions cannot replace Firefox's internal login-storage backend. The extension supplies a third-party autofill/save experience. Unlocked secrets cannot be protected against a compromised user account, root, or a compromised browser. Memory erasure in Go is best effort. The initial release needs independent security review before use with important credentials.
