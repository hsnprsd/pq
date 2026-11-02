# Security model

pq is an early implementation, not an audited password manager. Automated tests are useful evidence of behavior, not proof of cryptographic or application security. Use synthetic/low-value credentials until the implementation has received independent review.

## What encryption protects

The vault is a SQLCipher 4 database. The system SQLCipher library supplies its standard password KDF, page encryption, and page authentication. pq supplies passwords through `sqlite3_key` / `sqlite3_rekey`, never SQL strings or command arguments. It requires SQLCipher 4 and fails closed otherwise.

The encrypted database contains titles, usernames, URLs, notes, tags, generic text, passwords, timestamps, and the schema. SQLite uses memory-backed temporary storage, encrypted rollback journals, DELETE journal mode, full synchronous commits, secure deletion, and exclusive locking. SQLCipher memory-security wiping is enabled. A single daemon serializes all database access, imports, rekeying, and snapshot backups.

A locked database copied by an attacker should require the master password to decrypt. Weak master passwords remain vulnerable to offline guessing. File presence, approximate size, access patterns, timestamps, permissions, configuration, and runtime lock files are not hidden. A filesystem attacker can delete or replace the database or roll it back to an older authentic version; there is no external rollback-protection service.

## Unlock lifecycle

The daemon always starts locked. The master password is used to open the encrypted database and is then cleared from application-owned byte buffers as soon as practical. The daemon retains an unlocked database connection and its internal key material, not a deliberately cached plaintext master password.

The default absolute TTL is 15 minutes and is configurable. Requests do not renew it. Both monotonic and wall-clock deadlines are checked, including on every request and after operations. A background timer closes the connection on expiry even without client activity. Locking and shutdown also close it. Operations are serialized; a long operation may delay physical closure until it finishes, but cannot return a decrypted result if it finishes after expiry. An operation that committed just before expiry may report expiry instead of success; inspect the vault after unlocking before retrying a write.

Locking cannot retract credentials already printed, filled into a page, or delivered to a client. It does not erase another process's buffers, terminal history/scrollback, clipboard, or page DOM.

Go and JavaScript cannot guarantee erasure of every immutable string or runtime/GC copy. pq clears mutable buffers where practical, asks SQLCipher to wipe released allocations, disables core dumps, and marks its processes nondumpable on Linux. It does **not** promise locked/non-swappable memory or protection against hibernation images, privileged memory access, or forensic recovery of every old allocation. Use full-disk encryption and an appropriate swap/hibernation policy as additional safeguards.

## Local trust boundary

The daemon runs as the current user, never requiring root. It exposes no TCP or HTTP listener. Its Unix socket is in an owner-only directory, with owner-only permissions. Both client and server check peer UID; clients also check socket ownership, type, symlink status, and directory permissions before sending passwords. Exclusive locks prevent duplicate daemons from taking over a live socket/vault. Framed JSON messages have explicit size limits, deadlines, bounded connection concurrency, and a protocol version.

The socket is a **user-account boundary, not an application sandbox**. Any malicious process running as your user may use the socket, replace your binaries/configuration, or interfere with your input. Root can bypass filesystem restrictions. pq cannot protect an unlocked vault from a compromised user account, root, a keylogger, or a compromised browser/extension. Same-UID checks are not executable authentication.

Do not run pq under shell tracing or external tools that record its secret input/output. File paths and normal operational errors may be visible; secret values must not be logged. `pq get` intentionally reveals secrets to its caller.

## Firefox boundary

Firefox allows only the declared extension ID to invoke the registered native host through its extension API. The native host additionally allowlists status, lock/unlock, and origin-restricted login operations. It rejects generic-secret APIs, bulk imports, database backups, initialization, and master-password changes.

Background code validates content-script tab/frame origins. A top-frame content script may signal that an empty login form is ready; the background derives the origin from Firefox's sender data and automatically fills only if the tab is active and exactly one stored login matches. When several logins match, the background sends only their IDs, titles, and usernames to an on-page chooser in a closed shadow root. Selection requires a trusted click in that UI; the background accepts only previously offered IDs for the original active top-frame origin, with a two-minute expiry. Content requests never receive passwords in the response. Manual credential selection is also available from the extension's own popup, using the active tab's origin. Both paths recheck navigation before filling and send credentials only to the top frame. The daemon independently checks exact HTTPS origins and entry kinds before returning a browser credential. Domain suffix matching is never used.

Content scripts are restricted to top-level HTTPS pages. Filling checks visible fields and same-origin form actions and never submits a form. Automatic filling also requires empty username/password fields, skips fields already automatically filled, and rechecks those conditions when credentials arrive. Multiple matching logins open a chooser and require selection before any password is retrieved. Credentials filled into a website can be read by that website and its scripts, including malicious scripts on an otherwise matching origin. Automatic filling releases matching credentials without a per-fill user gesture while the vault is unlocked. Origin matching is not protection against a compromised website.

Save suggestions come from website form contents, are untrusted, expire after two minutes in extension memory, and require user confirmation before a database write. They are not cached decrypted-vault entries. The master password may be entered only into a terminal prompt or the extension's own popup, never a website field. There is no browser storage of master passwords or vault credentials. The extension has broad HTTPS content-script permission to detect forms; review the extension code and the signed build you install.

An independent signing/release process is still needed. The repository does not include a Mozilla-signed extension or reproducible signed-release pipeline.

## Imports and backups

Firefox CSV exports are plaintext. pq does not create additional CSV copies and warns before importing, but cannot guarantee secure deletion of the original file, SSD blocks, snapshots, or backups.

Direct Firefox import uses NSS with a read-only database and disables loading third-party profile PKCS#11 modules. Close Firefox first for a consistent profile. Only import profiles you trust; NSS and its parsers remain part of the attack surface.

Encrypted backups retain their original key. Updating the live master password does not revoke old backups or already copied database versions. Deletion and password changes cannot guarantee erasure of older encrypted versions from storage snapshots.

There is no recovery key or password-reset backdoor. Keep independent encrypted backups and verify restore procedures.

## Before a production release

- Independent review of SQLCipher integration, memory/key lifetimes, IPC, import handling, browser messaging, and origin/form validation.
- Broader browser/site compatibility and adversarial DOM tests.
- A signed extension release and a reviewed update/distribution process.
- Packaging and dependency update policies for supported distributions.
- Explicit consideration of session-lock/suspend hooks, stronger memory handling, and desired recovery behavior.

Do not include real passwords, master passwords, plaintext exports, or private vault files in bug reports. Reproduce issues using synthetic credentials and a temporary vault/profile.
