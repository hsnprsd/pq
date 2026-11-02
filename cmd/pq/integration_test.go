package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"pq/internal/model"
	"pq/internal/protocol"
	"pq/internal/vault"
)

func TestCLIAndNativeHost(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	build := t.TempDir()
	pq := filepath.Join(build, "pq")
	native := filepath.Join(build, "pq-native")
	for binary, pkg := range map[string]string{pq: "./cmd/pq", native: "./cmd/pq-native"} {
		cmd := exec.Command("go", "build", "-o", binary, pkg)
		cmd.Dir = root
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build: %v %s", err, output)
		}
	}
	state := t.TempDir()
	env := append(os.Environ(), "XDG_RUNTIME_DIR="+filepath.Join(state, "run"), "XDG_DATA_HOME="+filepath.Join(state, "data"), "XDG_CONFIG_HOME="+filepath.Join(state, "config"))
	call := func(input string, args ...string) (string, error) {
		cmd := exec.Command(pq, args...)
		cmd.Env = env
		cmd.Stdin = strings.NewReader(input)
		var out, stderr bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &stderr
		err := cmd.Run()
		if err != nil {
			return stderr.String(), err
		}
		return out.String(), nil
	}
	daemon := exec.Command(pq, "daemon")
	daemon.Env = env
	var log bytes.Buffer
	daemon.Stderr = &log
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	stopped := false
	defer func() {
		if !stopped {
			daemon.Process.Signal(syscall.SIGTERM)
			daemon.Wait()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := call("", "status"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("daemon not ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	must := func(input string, args ...string) string {
		t.Helper()
		out, err := call(input, args...)
		if err != nil {
			t.Fatalf("%v: %v: %s", args, err, out)
		}
		return out
	}
	must("integration test master password\n", "init", "--password-stdin")
	id := strings.TrimSpace(must("fixture password\n", "add", "login", "--title", "Example", "--username", "alice", "--url", "https://example.com/login", "--password-stdin"))
	if got := must("", "get", id, "--field", "password"); got != "fixture password" {
		t.Fatal("CLI password mismatch")
	}
	secretID := strings.TrimSpace(must("line one\nline two\n", "add", "secret", "--title", "Token", "--text-stdin"))
	if got := must("", "get", secretID, "--field", "text"); got != "line one\nline two\n" {
		t.Fatal("multiline secret was changed")
	}
	if got := must("", "list", "--json"); strings.Contains(got, "fixture password") || strings.Contains(got, "line one") {
		t.Fatal("listing exposed a secret")
	}
	must("replacement\n", "edit", id, "--password-stdin")
	csv := filepath.Join(state, "import.csv")
	if err := os.WriteFile(csv, []byte("url,username,password\nhttps://other.test,bob,imported\n"), 0600); err != nil {
		t.Fatal(err)
	}
	must("", "import", "firefox", "--csv", csv, "--yes")
	backup := filepath.Join(state, "backup.db")
	must("", "backup", backup)
	// Exercise the actual executable using Firefox's framed protocol.
	var frames bytes.Buffer
	for _, request := range []protocol.Request{{Op: "status"}, {Op: "browser.get", ID: id, Origin: "https://example.com"}, {Op: "get", ID: secretID}} {
		if err := protocol.Write(&frames, request, protocol.NativeMaxMessage); err != nil {
			t.Fatal(err)
		}
	}
	host := exec.Command(native)
	host.Env = env
	host.Stdin = &frames
	output, err := host.Output()
	if err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(output)
	for i := 0; i < 3; i++ {
		var response protocol.Response
		if err := protocol.Read(reader, &response, protocol.NativeMaxMessage); err != nil {
			t.Fatal(err)
		}
		if i == 1 && (response.Entry == nil || response.Entry.Password != "replacement") {
			t.Fatal("native host failed credential roundtrip")
		}
		if i == 2 && response.Code != "forbidden" {
			t.Fatal("native host exposed generic secret API")
		}
	}
	must("a replacement integration master\n", "passwd", "--password-stdin")
	must("", "lock")
	if _, err := call("", "get", id); err == nil {
		t.Fatal("locked get succeeded")
	}
	must("a replacement integration master\n", "unlock", "--password-stdin", "--ttl", "100ms")
	time.Sleep(150 * time.Millisecond)
	var status protocol.Status
	if err := json.Unmarshal([]byte(must("", "status")), &status); err != nil || !status.Locked {
		t.Fatal("TTL did not lock vault")
	}
	must("a replacement integration master\n", "unlock", "--password-stdin")
	must("", "delete", secretID, "--yes")
	// A clean restart must discard the unlocked session.
	daemon.Process.Signal(syscall.SIGTERM)
	if err := daemon.Wait(); err != nil {
		t.Fatal(err)
	}
	stopped = true
	daemon = exec.Command(pq, "daemon")
	daemon.Env = env
	if err := daemon.Start(); err != nil {
		t.Fatal(err)
	}
	stopped = false
	deadline = time.Now().Add(5 * time.Second)
	for {
		output, err := call("", "status")
		if err == nil {
			if err := json.Unmarshal([]byte(output), &status); err != nil || !status.Locked {
				t.Fatal("restart restored unlocked session")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("restart failed")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// The encrypted snapshot still uses the OLD key and contains the deleted entry.
	snapshot, err := vault.Open(backup, []byte("integration test master password"))
	if err != nil {
		t.Fatal(err)
	}
	if all, err := snapshot.List(); err != nil || len(all) != 3 {
		t.Fatal("backup did not preserve the original entries")
	}
	snapshot.Close()
	var listing []model.Entry
	if err := json.Unmarshal([]byte(must("a replacement integration master\n", "unlock", "--password-stdin")), &status); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(must("", "list", "--json")), &listing); err != nil || len(listing) != 2 {
		t.Fatalf("unexpected final list: %v", err)
	}
}
