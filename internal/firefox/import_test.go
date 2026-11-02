package firefox

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCSV(t *testing.T) {
	entries, err := CSV(strings.NewReader("url,username,password,httpRealm,formActionOrigin\nhttps://example.com/login,alice,\"a,b\nsecond line\",,https://evil.test\n"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("import: %v", err)
	}
	if entries[0].Password != "a,b\nsecond line" || len(entries[0].Origins) != 1 || entries[0].Origins[0] != "https://example.com" {
		t.Fatal("CSV fields or origin authorization incorrect")
	}
	for _, input := range []string{"url,username\nhttps://example.com,alice\n", "url,username,password\nhttps://example.com,alice\n", "url,username,password\nfile:///tmp/a,alice,b\n", "url,url,password\na,b,c\n"} {
		if _, err := CSV(strings.NewReader(input)); err == nil {
			t.Fatalf("accepted invalid CSV %q", input)
		}
	}
}

func TestNSSProfile(t *testing.T) {
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("C compiler is required for synthetic NSS fixture")
	}
	binary := filepath.Join(t.TempDir(), "fixture")
	output, err := exec.Command("pkg-config", "--cflags", "--libs", "nss").Output()
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{"testdata/profile.c", "-o", binary}, strings.Fields(string(output))...)
	if output, err := exec.Command("cc", args...).CombinedOutput(); err != nil {
		t.Fatalf("compile fixture: %v %s", err, output)
	}
	for _, mode := range []string{"empty", "primary"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			output, err := exec.Command(binary, "sql:"+dir, mode).CombinedOutput()
			if err != nil {
				t.Fatalf("fixture: %v %s", err, output)
			}
			fields := strings.Fields(string(output))
			if len(fields) != 2 {
				t.Fatalf("fixture output: %s", output)
			}
			data, _ := json.Marshal(map[string]any{"logins": []any{map[string]string{"hostname": "https://example.com", "encryptedUsername": fields[0], "encryptedPassword": fields[1]}}})
			if err := os.WriteFile(filepath.Join(dir, "logins.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			password := []byte(nil)
			if mode == "primary" {
				if _, err := Profile(dir, nil); !errors.Is(err, ErrPrimaryPassword) {
					t.Fatalf("expected primary password prompt, got %v", err)
				}
				password = []byte("fixture primary password")
			}
			entries, err := Profile(dir, password)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Username != "fixture-user" || entries[0].Password != "fixture-password" {
				t.Fatal("incorrect NSS decryption")
			}
		})
	}
}
