#!/usr/bin/env python3
"""Optional real-Firefox test. Uses only synthetic secrets and a temporary HOME.
Requires make build, Firefox, Node/npm, openssl, and certutil. npx may download
web-ext. No existing Firefox profiles, vaults, or native manifests are touched.
"""
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import ssl
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
MASTER = "synthetic browser test master"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'<!doctype html><form method="post"><input name="username" autocomplete="username"><input name="password" type="password" autocomplete="current-password"><button>Sign in</button></form>'
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def main():
    with tempfile.TemporaryDirectory(prefix="pq-browser-") as temp:
        tmp = Path(temp)
        home = tmp / "home"
        home.mkdir(mode=0o700)
        env = dict(os.environ, HOME=str(home), XDG_DATA_HOME=str(tmp / "data"),
                   XDG_RUNTIME_DIR=str(tmp / "run"), XDG_CONFIG_HOME=str(tmp / "config"),
                   npm_config_cache=str(Path.home() / ".npm"), MOZ_HEADLESS="1")
        cert, key = tmp / "cert.pem", tmp / "key.pem"
        ca, ca_key, csr = tmp / "ca.pem", tmp / "ca-key.pem", tmp / "leaf.csr"
        commands = [
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=pq temporary test CA", "-keyout", str(ca_key), "-out", str(ca)],
            ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(csr)],
        ]
        extensions = tmp / "leaf.ext"
        extensions.write_text("basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
        commands.append(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key), "-CAcreateserial", "-days", "1", "-extfile", str(extensions), "-out", str(cert)])
        for command in commands:
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        origin = f"https://localhost:{server.server_port}"
        profile = tmp / "profile"
        profile.mkdir()
        subprocess.run(["certutil", "-N", "-d", "sql:" + str(profile), "--empty-password"], check=True)
        subprocess.run(["certutil", "-A", "-d", "sql:" + str(profile), "-n", "pq-test-localhost", "-t", "CT,,", "-i", str(ca)], check=True)
        manifests = home / ".mozilla" / "native-messaging-hosts"
        manifests.mkdir(parents=True)
        (manifests / "pq.json").write_text(json.dumps({"name": "pq", "description": "pq temporary browser test", "path": str(ROOT / "bin/pq-native"), "type": "stdio", "allowed_extensions": ["pq@local"]}))
        source = tmp / "extension"
        shutil.copytree(ROOT / "extension", source, ignore=shutil.ignore_patterns("*.test.js"))
        background = (source / "background.js").read_text().replace(
            "browser.runtime.onMessage.addListener(async (message, sender) => {",
            "browser.runtime.onMessage.addListener(globalThis.pqTestHandler = async (message, sender) => {")
        (source / "background.js").write_text(background)
        manifest = json.loads((source / "manifest.json").read_text())
        manifest["background"]["scripts"].append("smoke.js")
        (source / "manifest.json").write_text(json.dumps(manifest))
        bootstrap = r'''
(async () => {
  const origin = ORIGIN;
  const sender = { id: browser.runtime.id, url: browser.runtime.getURL("popup.html") };
  const invoke = async message => { const r = await pqTestHandler(message, sender); if (r.error) throw new Error(r.error); return r; };
  const raw = request => browser.runtime.sendNativeMessage("pq", request);
  try {
    const tab = await browser.tabs.create({ url: origin, active: true });
    for (let i = 0; i < 100; i++) {
      await new Promise(resolve => setTimeout(resolve, 100));
      if ((await browser.tabs.get(tab.id)).status === "complete") break;
    }
    await new Promise(resolve => setTimeout(resolve, 1000));
    await invoke({ type: "ui.fill", id: ENTRY_ID });
    let [values] = await browser.tabs.executeScript(tab.id, { code: "[document.querySelector('[name=username]').value, document.querySelector('[name=password]').value]" });
    if (values[0] !== "alice" || values[1] !== "synthetic password") throw new Error("Real form filling failed");
    await browser.tabs.executeScript(tab.id, { code: "document.querySelector('[name=password]').value = 'updated synthetic password'" });
    await invoke({ type: "ui.capture" });
    await invoke({ type: "ui.save" });
    const saved = await raw({ op: "browser.get", id: ENTRY_ID, origin });
    if (saved.entry?.password !== "updated synthetic password") throw new Error("Real form saving failed");
    if (!(await raw({ op: "get", id: ENTRY_ID })).error) throw new Error("Native host allowed generic access");
    if (!(await raw({ op: "browser.get", id: ENTRY_ID, origin: "https://evil.test" })).error) throw new Error("Origin isolation failed");
    await invoke({ type: "ui.lock" });
    await invoke({ type: "ui.unlock", password: MASTER });
    await raw({ op: "browser.save", origin, entry: { title: "smoke-pass", username: "passed", password: "test-only" } });
  } catch (error) {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    await raw({ op: "browser.save", origin, entry: { title: "smoke-fail", username: `${error.message}; ${tab?.url}; ${tab?.title}`, password: "test-only" } });
  }
})();
'''
        daemon = browser = None
        log = tmp / "browser.log"
        with log.open("w+") as output:
            try:
                daemon = subprocess.Popen([str(ROOT / "bin/pq"), "daemon"], env=env, stdout=output, stderr=output)

                def pq(*args, secret=None):
                    return subprocess.check_output([str(ROOT / "bin/pq"), *args], input=secret, env=env, stderr=subprocess.DEVNULL).decode()

                for _ in range(100):
                    try:
                        pq("status")
                        break
                    except subprocess.CalledProcessError:
                        time.sleep(0.05)
                pq("init", "--password-stdin", secret=MASTER.encode())
                entry_id = pq("add", "login", "--title", "Browser test", "--username", "alice", "--url", origin,
                              "--password-stdin", secret=b"synthetic password").strip()
                bootstrap = bootstrap.replace("ORIGIN", json.dumps(origin)).replace("ENTRY_ID", json.dumps(entry_id)).replace("MASTER", json.dumps(MASTER))
                (source / "smoke.js").write_text(bootstrap)
                browser = subprocess.Popen(["npx", "--yes", "web-ext", "run", "--no-config-discovery", "--no-input", "--no-reload",
                                            "--source-dir", str(source), "--firefox-profile", str(profile), "--keep-profile-changes",
                                            "--args=-headless"], env=env, stdout=output, stderr=output, start_new_session=True)
                for _ in range(300):
                    time.sleep(0.2)
                    if browser.poll() is not None:
                        raise RuntimeError("web-ext exited unexpectedly")
                    try:
                        entries = json.loads(pq("list", "--json"))
                    except subprocess.CalledProcessError:
                        continue  # The extension briefly locks before testing unlock.
                    for entry in entries:
                        if entry["title"] == "smoke-fail":
                            raise RuntimeError(entry.get("username", "Browser test failed"))
                        if entry["title"] == "smoke-pass":
                            print("PASS: real Firefox native messaging, HTTPS form fill/save, popup unlock, and origin isolation")
                            return
                raise RuntimeError("Timed out waiting for Firefox")
            except Exception:
                output.flush()
                print(log.read_text())
                raise
            finally:
                if browser and browser.poll() is None:
                    os.killpg(browser.pid, signal.SIGTERM)
                    try:
                        browser.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(browser.pid, signal.SIGKILL)
                        browser.wait()
                if daemon:
                    daemon.terminate()
                    daemon.wait(timeout=10)
                server.shutdown()


if __name__ == "__main__":
    main()
