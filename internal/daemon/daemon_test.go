package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pq/internal/client"
	"pq/internal/config"
	"pq/internal/model"
	"pq/internal/protocol"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return &Server{Paths: config.Paths{DataDir: dir, Socket: filepath.Join(dir, "run", "pq.sock")}, Settings: config.Settings{UnlockTTL: "15m"}}
}
func master() []byte { return []byte("a sufficiently long test master") }

func TestTTLAndBrowserIsolation(t *testing.T) {
	s := testServer(t)
	if response := s.Handle(protocol.Request{Op: "get", ID: "x"}); response.Code != "locked" {
		t.Fatal("not initially locked")
	}
	if response := s.Handle(protocol.Request{Op: "init", Password: master()}); response.Error != "" {
		t.Fatal(response.Error)
	}
	entry := model.Entry{Kind: "login", Title: "example", Username: "alice", Password: "secret", Origins: []string{"https://example.com"}}
	put := s.Handle(protocol.Request{Op: "put", Entry: &entry})
	if put.Error != "" {
		t.Fatal(put.Error)
	}
	id := put.Entry.ID
	secret := model.Entry{Kind: "secret", Title: "private", Text: "not for the browser"}
	putSecret := s.Handle(protocol.Request{Op: "put", Entry: &secret})
	if putSecret.Error != "" {
		t.Fatal(putSecret.Error)
	}
	for _, origin := range []string{"https://example.com.evil.test", "https://sub.example.com", "http://example.com"} {
		if response := s.Handle(protocol.Request{Op: "browser.get", ID: id, Origin: origin}); response.Error == "" {
			t.Fatalf("accepted %s", origin)
		}
	}
	if response := s.Handle(protocol.Request{Op: "browser.get", ID: putSecret.Entry.ID, Origin: "https://example.com"}); response.Error == "" {
		t.Fatal("browser retrieved generic secret")
	}
	if response := s.Handle(protocol.Request{Op: "browser.list", Origin: "https://example.com"}); len(response.Entries) != 1 || response.Entries[0].Password != "" {
		t.Fatal("browser listing leaked password")
	}
	if response := s.Handle(protocol.Request{Op: "browser.get", ID: id, Origin: "https://example.com"}); response.Entry == nil || response.Entry.Password != "secret" {
		t.Fatal("valid browser get failed")
	}
	s.expires = time.Now().Add(-time.Second)
	if response := s.Handle(protocol.Request{Op: "get", ID: id}); response.Code != "locked" {
		t.Fatal("expired key was usable")
	}
	if response := s.Handle(protocol.Request{Op: "unlock", Password: master(), TTL: "50ms"}); response.Error != "" {
		t.Fatal(response.Error)
	}
	time.Sleep(60 * time.Millisecond)
	if response := s.Handle(protocol.Request{Op: "status"}); !response.Status.Locked {
		t.Fatal("TTL not enforced on status")
	}
}

func TestSocketLifecycle(t *testing.T) {
	s := testServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("daemon exited before listening: %v", err)
		default:
		}
		if _, err := os.Stat(s.Paths.Socket); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket did not appear")
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	response, err := client.Call(s.Paths.Socket, protocol.Request{Op: "init", Password: master()})
	if err != nil || response.Status.Locked {
		t.Fatalf("init: %v", err)
	}
	info, _ := os.Stat(s.Paths.Socket)
	if info.Mode().Perm() != 0600 {
		t.Fatal("socket permissions")
	}
	if _, err := client.Call(s.Paths.Socket, protocol.Request{Op: "lock"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Call(s.Paths.Socket, protocol.Request{Op: "get", ID: "x"}); err == nil {
		t.Fatal("locked get accepted")
	}
	// A second server must not remove the live socket or take over the vault.
	if err := testServerWithPaths(s).Run(ctx); err == nil {
		t.Fatal("duplicate daemon accepted")
	}
}

func testServerWithPaths(s *Server) *Server { return &Server{Paths: s.Paths, Settings: s.Settings} }
