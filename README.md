# pq

A local password manager in Go: an encrypted SQLite vault, a user daemon, a CLI, and a Firefox extension.

**Early implementation, not independently security-audited. Start with test credentials and keep independent backups before trusting it with important secrets.** See [SECURITY.md](SECURITY.md).

## What works

- Login entries and arbitrary UTF-8 secret text, including multiline text.
- SQLCipher 4 encryption of the entire database, including entry metadata and schema.
- A daemon that starts locked, shares an unlocked session between clients, and locks after a configurable absolute TTL.
- CLI CRUD, metadata search, transactional Firefox imports, master-password changes, and encrypted backups.
- Firefox CSV import and direct, read-only NSS import from `logins.json` / `key4.db`, including Primary Password support.
- Firefox credential selection and filling, login-save suggestions, and confirmed saves/updates through native messaging.
- No cloud account, remote service, telemetry, or TCP listener.

Linux is the initial supported platform. The extension requires desktop Firefox 142 or later. Firefox integration supplies a third-party password-manager experience; it cannot replace Firefox's internal login-storage backend.

## Build and install

Requirements: Go 1.25+, a C compiler, pkg-config, SQLCipher **4**, and Mozilla NSS development libraries. Node.js is needed for extension unit tests; zip is needed to package the extension.

On Fedora, install build dependencies with elevated privileges:

```sh
pkexec dnf install golang gcc make pkgconf-pkg-config sqlcipher-devel nss-devel
```

Then build and install as your normal user, **without `sudo` or `pkexec`**:

```sh
make check
make install
export PATH="$HOME/.local/bin:$PATH"
```

`make install` installs `pq` and `pq-native` under `~/.local/bin`, and the service under `~/.config/systemd/user/pq.service`. It does not start the daemon or initialize a vault. If you override `PREFIX`, also override the service's `ExecStart` to match.

These are CGO builds dynamically linked against the system SQLCipher and NSS libraries. Keep those libraries updated. Ordinary SQLite is not a substitute for SQLCipher; pq fails closed without SQLCipher 4.

### Start the daemon

**pq is a systemd user service, not a system-wide service. Run these commands as your normal login user, without `sudo` or `pkexec`.** Using `sudo systemctl --user` changes the user context and may target a different user manager, which will not find your installed `pq.service`.

```sh
systemctl --user daemon-reload
systemctl --user enable --now pq.service
pq status
pq init
```

`pq init` asks for a new master password and confirmation, creates the encrypted vault, and unlocks it. New master passwords must contain 12–4096 bytes. There is **no password recovery**.

For development, without installing a service:

```sh
make build
./bin/pq daemon
# In a second terminal:
./bin/pq init
```

The foreground daemon handles SIGINT/SIGTERM and drops its unlocked session when it exits. The systemd service also starts locked after a crash/restart.

### Troubleshooting the user service

If you see **`Unit pq.service does not exist`**:

- Remove `sudo` or `pkexec` from the `systemctl --user` command.
- Check that `~/.config/systemd/user/pq.service` exists. If it is missing, run `make install` as your normal user from this checkout.
- Run the `daemon-reload` and `enable --now` commands above again, without elevation.

Inspect service discovery, state, and recent logs with:

```sh
systemctl --user list-unit-files pq.service
systemctl --user status pq.service
journalctl --user -u pq.service -n 50 --no-pager
```

## CLI

Global flags precede the command; command flags follow its positional arguments.

```sh
pq unlock
pq unlock --ttl 30m
pq status
pq lock

pq add login --title GitHub --username alice --url https://github.com
pq add secret --title 'Recovery codes' --text-stdin < /path/to/secret-text
pq list
pq list --json
pq search github

pq get ENTRY_ID
pq get ENTRY_ID --field password
pq get ENTRY_ID --field text
pq edit ENTRY_ID --username new-name
pq edit ENTRY_ID --prompt
pq delete ENTRY_ID
pq delete ENTRY_ID --yes

pq passwd
pq backup /absolute/path/to/pq-backup.db
```

`add login` prompts for a hidden password. `add secret` without `--text-stdin` prompts for a hidden single-line secret. `--password-stdin` explicitly reads a login password from stdin and removes one trailing LF or CRLF; `--text-stdin` preserves text exactly. Entry fields are limited to 1 MiB each, with smaller limits for metadata.

`list` and `search` return metadata only. **`get` deliberately prints secrets**, including all fields by default. `--field password`, `text`, `username`, or `notes` prints the exact field without an added newline. Be careful with terminal scrollback, shell tracing, redirection, and clipboard tools.

For structured entry input:

```sh
pq add login --json-stdin < /path/to/login.json
pq edit ENTRY_ID --json-stdin < /path/to/replacement-entry.json
```

JSON fields: `kind` (`login` or `secret`), `title`, `username`, `password`, `text`, `origins` (website URL array), `notes`, and `tags` (string array). The daemon generates IDs and timestamps. `--json-stdin` supplies a complete replacement on edit; omitted optional fields are cleared. It cannot be combined with other entry flags. Do not leave plaintext input files behind unnecessarily.

For automation, `init`, `unlock`, and `passwd` also accept `--password-stdin`. This skips new-password confirmation. Prefer an interactive prompt; never put real passwords in shell commands, arguments, environment variables, or scripts.

## TTL and paths

The default TTL is **15 minutes from unlock**, not 15 minutes of inactivity. Reading a password or using Firefox never extends it. A TTL must be a positive Go duration, such as `30s`, `15m`, or `2h`; there is no infinite-unlock setting.

Optionally create `~/.config/pq/config.json` (or `$XDG_CONFIG_HOME/pq/config.json`) with mode `0600`:

```json
{
  "unlock_ttl": "30m"
}
```

Restart the daemon after changing its configuration. An individual `pq unlock --ttl ...` overrides the default for that session. The daemon uses both wall and monotonic deadlines so a suspend or backward wall-clock adjustment does not silently extend a session.

Default paths:

| Purpose | Location |
| --- | --- |
| Vault | `$XDG_DATA_HOME/pq/vault.db`, default `~/.local/share/pq/vault.db` |
| Configuration | `$XDG_CONFIG_HOME/pq/config.json`, default `~/.config/pq/config.json` |
| Socket | `$XDG_RUNTIME_DIR/pq/pq.sock` |
| Runtime fallback | `/tmp/pq-UID/pq/pq.sock` when `XDG_RUNTIME_DIR` is unset |
| Firefox native manifest | `~/.mozilla/native-messaging-hosts/pq.json` |

Vault/socket directories must be owner-only (`0700`), and sensitive files owner-only (`0600`). Existing insecure files/directories are rejected rather than silently changing their permissions. Never point `--data-dir` at a general-purpose shared directory.

The CLI supports `--data-dir`, `--socket`, and `--config`. For example:

```sh
./bin/pq --data-dir /private/test-vault --socket /private/test-run/pq.sock daemon --ttl 1m
./bin/pq --socket /private/test-run/pq.sock status
```

The native host uses the default XDG paths inherited from Firefox. A daemon on a custom socket is CLI-only unless the host is launched with matching XDG runtime settings. Prefer the defaults for normal use.

## Import Firefox passwords

Unlock pq first. Imports are transactional: failure does not retain a partial import. Duplicate detection uses website origin plus username; the default policy is `skip`. Use `--duplicates update` to replace matching entries, or `--duplicates error` to reject duplicates and roll back.

### Direct profile import — no plaintext CSV

1. Find the profile directory through Firefox's `about:support` page.
2. **Close Firefox** so the login file and key database are consistent.
3. Run:

```sh
pq unlock
pq import firefox --profile /absolute/path/to/your/firefox-profile
```

If the profile has a Firefox Primary Password, pq prompts for it separately from the pq master password. NSS opens the profile read-only and does not load third-party PKCS#11 modules. This supports modern `key4.db` profiles, not legacy `key3.db` profiles.

### CSV export import

Export passwords from Firefox's password page, then:

```sh
pq import firefox --csv /path/to/firefox-passwords.csv
pq import firefox --csv /path/to/firefox-passwords.csv --duplicates update --yes
```

**The Firefox CSV export is plaintext.** Remove it when finished and account for editor copies, trash, filesystem snapshots, and backups. Deleting it does not guarantee secure erasure on an SSD.

Only HTTP/HTTPS website logins are supported. Import authorizes the original login origin, not a different form-action origin. Firefox GUIDs, realms, and original timestamps are not preserved. Imports are limited to 10,000 entries, a 32 MiB source file, and a 16 MiB serialized daemon request.

## Firefox integration

Register the native host after installing the binaries:

```sh
pq firefox install
# Or, from a development checkout:
./bin/pq firefox install --host "$PWD/bin/pq-native"
```

The manifest intentionally uses Firefox's legacy `~/.mozilla/native-messaging-hosts` discovery path, including on newer Firefox versions that store profiles under the XDG configuration directory.

### Load the extension for development

1. Open `about:debugging#/runtime/this-firefox`.
2. Choose **Load Temporary Add-on** and select `extension/manifest.json`.
3. Reload already-open website tabs so the content script is installed.
4. Click the **pq** toolbar button. Unlock there or with `pq unlock`.
5. On an HTTPS login page, click a matching credential to fill it. pq never submits the form automatically.

When a form is submitted, a `+` badge indicates a possible login to save. Open the popup and confirm **save / update**. On JavaScript-only forms, use **Capture current login form** first. Suggestions are kept only in extension memory for up to two minutes and are never written to browser storage. Saving updates a unique matching username on that origin; ambiguous matches require CLI editing.

For persistent installation in standard Firefox, package the extension with `make extension`, obtain a Mozilla-signed build through AMO's unlisted distribution workflow, and install the signed XPI. **An unsigned XPI will not install persistently on standard Firefox.** Temporary add-ons disappear on browser restart. No signed build is included in this repository.

Consider disabling Firefox's own password-save/autofill features to avoid competing prompts; pq does not change those settings automatically.

### Deliberate browser restrictions

- HTTPS only, exact scheme/host/port matching, and explicit user-triggered filling.
- Top-frame forms only; cross-origin form actions, hidden/off-screen fields, and ambiguous registration forms are refused.
- No generic-secret retrieval through the native host.
- No password persistence in extension storage and no external network access from extension pages.
- Same-origin login flows work best. Cross-origin/iframe logins, shadow DOM forms, some multi-step flows, HTTP sites, passkeys, and TOTP are not implemented.
- Sandboxed Firefox distributions, such as Flatpak, may need additional native-messaging integration and are not tested. Native RPM Firefox is tested.

## Backups and recovery

`pq backup DESTINATION` creates a new, owner-only, encrypted snapshot. It refuses to overwrite an existing destination. The daemon serializes the copy against all vault operations and enforces SQLite DELETE journal mode and synchronous commits.

Backups retain the master password used **when they were made**. Changing the current master password does not change old backups. Store backups separately and test restoring them.

To restore, stop `pq.service` (or the foreground daemon), preserve the current vault separately, and copy the chosen backup to the vault path with mode `0600` inside an owner-only directory. Do not overwrite a running database or combine a backup with stale journal files. Start the daemon and unlock with the backup's original master password.

There is no recovery if both the master password and an accessible independent backup are lost.

## Development and verification

```sh
make check                   # Go race tests, go vet, and Node unit tests
make extension               # Build pq-firefox.xpi (unsigned)
npx --yes web-ext lint --source-dir extension --ignore-files '*.test.js'
python3 scripts/browser-smoke.py  # Optional real Firefox test, after make build
```

The browser test additionally needs Firefox, Python 3, openssl, certutil (`nss-tools` on Fedora), and Node/npm. It may download `web-ext` through npx. It creates a temporary HOME, Firefox profile, test-only certificate authority, HTTPS server, native manifest, and vault, using only synthetic credentials. It does not access your existing vault/profile. A test-only hook invokes the real background handlers; native messaging and DOM filling/saving execute in real Firefox.

Automated tests cover encrypted database/journal contents, tampering, wrong passwords, transactional imports, backup/restore, rekeying, concurrent-safe IPC, socket permissions, TTL, restart locking, real CLI/native-host round trips, NSS decryption with/without a Primary Password, and extension origin/message boundaries.

Project layout:

```text
cmd/pq/             CLI and daemon entry point
cmd/pq-native/      Restricted Firefox native-messaging bridge
internal/vault/    Encrypted entry operations and backups
internal/sqlcipher/ Minimal binding to the system SQLCipher C API
internal/daemon/   Serialized vault access and unlock lifecycle
internal/firefox/  CSV and NSS profile imports
extension/         Firefox extension, no bundler required
packaging/         systemd user service and example configuration
scripts/           Optional real-browser smoke test
```
