# Implementation plan

Build a Linux-first, local password manager in Go. A systemd user daemon owns an encrypted SQLCipher vault. A CLI and a Firefox native-messaging host communicate with it over a private Unix socket. The daemon starts locked and enforces an absolute, configurable unlock TTL.

## Milestones

1. Validate SQLCipher and native-messaging dependencies; establish project structure.
2. Implement encrypted storage, transactional CRUD/import, password changes, and encrypted backups.
3. Implement the daemon, secure local protocol, TTL, CLI, and systemd integration.
4. Implement Firefox CSV and read-only NSS profile imports.
5. Implement the Firefox extension and native host, with origin-restricted credential access.
6. Test the complete workflow, harden edge cases, and document installation and security boundaries.

Commit each working milestone separately. Run automated tests and real CLI smoke tests before considering the implementation complete.

## Security decisions

- Use system SQLCipher's key API and supported password KDF, not custom cryptography.
- Keep credentials out of command arguments, environment variables, logs, and unencrypted files.
- Cache an unlocked database connection, not the master password. Close it on lock, expiry, and shutdown.
- Restrict the Unix socket and vault directory to the current user; validate peer credentials.
- Use absolute unlock expiry, defaulting to 15 minutes. Browser activity cannot extend it.
- Use explicit browser filling, exact origin matching, and confirmed save/update operations.
- Never expose generic secret entries through the browser API.
- No cloud sync, sharing, passkeys, or TOTP in this initial implementation.

## Limitations to document

Firefox extensions cannot replace Firefox's internal login-storage backend. The extension supplies a third-party autofill/save experience. Unlocked secrets cannot be protected against a compromised user account, root, or a compromised browser. Memory erasure in Go is best effort. The initial release needs independent security review before use with important credentials.
