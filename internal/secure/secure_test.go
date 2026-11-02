package secure

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateFilesAndLocks(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	if err := Dir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "file")
	f, err := NewFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := Check(path, false); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFile(path); err == nil {
		t.Fatal("overwrote existing file")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := Check(link, false); err == nil {
		t.Fatal("accepted symlink")
	}
	if _, err := Lock(link); err == nil {
		t.Fatal("followed lock symlink")
	}
	lockPath := filepath.Join(dir, "daemon.lock")
	first, err := Lock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := Lock(lockPath); err == nil {
		second.Close()
		t.Fatal("acquired second exclusive lock")
	}
	if err := Socket(path); err == nil {
		t.Fatal("accepted ordinary file as socket")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := Dir(dir); err == nil {
		t.Fatal("accepted public directory")
	}
}
