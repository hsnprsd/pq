package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"pq/internal/model"
)

var password = []byte("a long test master password")

func TestVaultLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	v, err := Create(path, password)
	if err != nil {
		t.Fatal(err)
	}
	e, err := v.Put(model.Entry{Kind: "login", Title: "private-sentinel-title", Username: "alice", Password: "private-sentinel-password", Origins: []string{"https://example.com/login"}})
	if err != nil {
		t.Fatal(err)
	}
	if e.ID == "" || e.Origins[0] != "https://example.com" {
		t.Fatal("entry not normalized")
	}
	secret, err := v.Put(model.Entry{Kind: "secret", Title: "token", Text: "private-sentinel-text\nsecond line"})
	if err != nil {
		t.Fatal(err)
	}
	all, err := v.List()
	if err != nil || len(all) != 2 {
		t.Fatalf("list: %v %v", all, err)
	}
	if found := Search(all, "ALICE"); len(found) != 1 || found[0].Password != "" {
		t.Fatal("search exposed a password or did not match")
	}
	e.Password = "changed"
	if _, err := v.Put(e); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "backup.db")
	if err := v.Backup(backup); err != nil {
		t.Fatal(err)
	}
	if err := v.Delete(secret.ID); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	for _, sentinel := range []string{"SQLite format 3", "private-sentinel", "alice"} {
		if bytes.Contains(data, []byte(sentinel)) {
			t.Fatalf("plaintext found: %s", sentinel)
		}
	}
	if bad, err := Open(path, []byte("incorrect master")); err == nil {
		bad.Close()
		t.Fatal("wrong password accepted")
	}
	v, err = Open(path, password)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Get(e.ID)
	if err != nil || got.Password != "changed" {
		t.Fatalf("reopen: %v", err)
	}
	newPassword := []byte("a different long master password")
	if err := v.Rekey(newPassword); err != nil {
		t.Fatal(err)
	}
	v.Close()
	if bad, err := Open(path, password); err == nil {
		bad.Close()
		t.Fatal("old master accepted after rekey")
	}
	v, err = Open(path, newPassword)
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	v, err = Open(backup, password)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if _, err := v.Get(secret.ID); err != nil {
		t.Fatalf("backup lost entry: %v", err)
	}
}

func TestImportAtomicity(t *testing.T) {
	v, err := Create(filepath.Join(t.TempDir(), "vault.db"), password)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	e := model.Entry{Kind: "login", Title: "example", Username: "alice", Password: "first", Origins: []string{"https://example.com"}}
	if result, err := v.Import([]model.Entry{e, e}, "error"); err == nil || result.Added != 0 {
		t.Fatal("expected rollback")
	}
	if all, _ := v.List(); len(all) != 0 {
		t.Fatal("partial import persisted")
	}
	if result, err := v.Import([]model.Entry{e, e}, "skip"); err != nil || result.Added != 1 || result.Skipped != 1 {
		t.Fatalf("skip: %+v %v", result, err)
	}
	e.Password = "second"
	if result, err := v.Import([]model.Entry{e}, "update"); err != nil || result.Updated != 1 {
		t.Fatalf("update: %+v %v", result, err)
	}
	all, _ := v.List()
	if len(all) != 1 || all[0].Password != "second" {
		t.Fatal("update failed")
	}
}

func TestPermissionsAndExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.db")
	v, err := Create(path, password)
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	if v, err := Create(path, password); err == nil {
		v.Close()
		t.Fatal("overwrote existing vault")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if v, err := Open(path, password); err == nil {
		v.Close()
		t.Fatal("opened insecure vault")
	}
}
