package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if s, err := Load(path); err != nil || s.UnlockTTL != "15m" {
		t.Fatal("missing file should use defaults")
	}
	for _, data := range []string{`{"unlock_ttl":"30m"}`, `{}`} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err != nil {
			t.Fatal(err)
		}
	}
	for _, data := range []string{`null`, `[]`, `{"unlock_ttl":"0s"}`, `{"unlock_ttl":"-1m"}`, `{"unknown":true}`, `{} {}`, `{}` + strings.Repeat(" ", 4096)} {
		os.WriteFile(path, []byte(data), 0600)
		if _, err := Load(path); err == nil {
			t.Fatalf("accepted invalid configuration %q", data)
		}
	}
	os.WriteFile(path, []byte(`{}`), 0600)
	os.Chmod(path, 0644)
	if _, err := Load(path); err == nil {
		t.Fatal("accepted unsafe config permissions")
	}
}
