package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"pq/internal/config"
	"pq/internal/model"
	"pq/internal/protocol"
	"pq/internal/secure"
	"pq/internal/vault"
)

type Server struct {
	Paths    config.Paths
	Settings config.Settings
	mu       sync.Mutex
	vault    *vault.Vault
	expires  time.Time
}

func (s *Server) vaultPath() string { return filepath.Join(s.Paths.DataDir, "vault.db") }

func (s *Server) lock() {
	if s.vault != nil {
		_ = s.vault.Close()
		s.vault = nil
	}
	s.expires = time.Time{}
}
func (s *Server) expire() {
	if s.vault != nil && !time.Now().Before(s.expires) {
		s.lock()
	}
}
func (s *Server) status() *protocol.Status {
	_, err := os.Stat(s.vaultPath())
	status := &protocol.Status{Initialized: err == nil, Locked: s.vault == nil, DefaultTTL: s.Settings.UnlockTTL}
	if s.vault != nil {
		expiry := s.expires
		status.ExpiresAt = &expiry
	}
	return status
}

func failure(code string, err error) protocol.Response {
	return protocol.Response{Code: code, Error: err.Error()}
}

// Handle serializes all database operations, including expiry and backups.
func (s *Server) Handle(req protocol.Request) protocol.Response {
	defer secure.Wipe(req.Password)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire()
	switch req.Op {
	case "status":
		return protocol.Response{Status: s.status()}
	case "lock":
		s.lock()
		return protocol.Response{Status: s.status()}
	case "init", "unlock":
		if s.vault != nil {
			return failure("invalid", errors.New("vault is already unlocked; lock it before unlocking again"))
		}
		if len(req.Password) == 0 || len(req.Password) > 4096 {
			return failure("invalid", errors.New("master password must contain 1–4096 bytes"))
		}
		ttl := s.Settings.UnlockTTL
		if req.TTL != "" {
			ttl = req.TTL
		}
		duration, err := config.Duration(ttl)
		if err != nil {
			return failure("invalid", err)
		}
		var opened *vault.Vault
		if req.Op == "init" {
			opened, err = vault.Create(s.vaultPath(), req.Password)
		} else {
			opened, err = vault.Open(s.vaultPath(), req.Password)
		}
		if err != nil {
			return failure("invalid", err)
		}
		s.vault, s.expires = opened, time.Now().Add(duration)
		return protocol.Response{Status: s.status()}
	}
	if s.vault == nil {
		return failure("locked", errors.New("vault is locked; run pq unlock"))
	}
	var response protocol.Response
	var err error
	switch req.Op {
	case "list":
		var entries []model.Entry
		entries, err = s.vault.List()
		if err == nil {
			response.Entries = vault.Search(entries, req.Query)
		}
	case "get":
		var entry model.Entry
		entry, err = s.vault.Get(req.ID)
		if err == nil {
			response.Entry = &entry
		}
	case "put":
		if req.Entry == nil {
			return failure("invalid", errors.New("entry is required"))
		}
		var entry model.Entry
		entry, err = s.vault.Put(*req.Entry)
		if err == nil {
			summary := entry.Summary()
			response.Entry = &summary
		}
	case "delete":
		err = s.vault.Delete(req.ID)
	case "import":
		var result model.ImportResult
		result, err = s.vault.Import(req.Entries, req.Duplicates)
		if err == nil {
			response.Import = &result
		}
	case "passwd":
		err = s.vault.Rekey(req.Password)
	case "backup":
		if !filepath.IsAbs(req.Destination) {
			return failure("invalid", errors.New("backup destination must be an absolute path"))
		}
		err = s.vault.Backup(req.Destination)
	case "browser.list", "browser.get", "browser.save":
		response, err = s.browser(req)
	default:
		return failure("invalid", errors.New("unknown operation"))
	}
	if err != nil {
		return failure("invalid", err)
	}
	// An operation that ran past expiry must not return any decrypted result.
	if !time.Now().Before(s.expires) {
		s.lock()
		return failure("locked", errors.New("unlock TTL expired during the operation"))
	}
	return response
}

func (s *Server) browser(req protocol.Request) (protocol.Response, error) {
	var response protocol.Response
	origin, err := model.Origin(req.Origin)
	if err != nil || !strings.HasPrefix(origin, "https://") {
		return response, errors.New("browser integration requires an HTTPS origin")
	}
	switch req.Op {
	case "browser.list":
		entries, err := s.vault.List()
		if err != nil {
			return response, err
		}
		response.Entries = []model.Entry{}
		for _, e := range entries {
			if e.Matches(origin) {
				response.Entries = append(response.Entries, model.Entry{ID: e.ID, Kind: e.Kind, Title: e.Title, Username: e.Username})
			}
		}
	case "browser.get":
		e, err := s.vault.Get(req.ID)
		if err != nil {
			return response, err
		}
		if !e.Matches(origin) {
			return response, errors.New("credential does not match the website origin")
		}
		response.Entry = &model.Entry{ID: e.ID, Kind: e.Kind, Username: e.Username, Password: e.Password}
	case "browser.save":
		if req.Entry == nil {
			return response, errors.New("entry is required")
		}
		e := model.Entry{ID: req.Entry.ID, Kind: "login", Title: req.Entry.Title, Username: req.Entry.Username, Password: req.Entry.Password, Origins: []string{origin}}
		if e.ID != "" {
			old, err := s.vault.Get(e.ID)
			if err != nil {
				return response, err
			}
			if !old.Matches(origin) {
				return response, errors.New("credential does not match the website origin")
			}
			old.Username, old.Password = e.Username, e.Password
			e = old
		}
		saved, err := s.vault.Put(e)
		if err != nil {
			return response, err
		}
		summary := saved.Summary()
		response.Entry = &summary
	}
	return response, nil
}

func sameUser(conn *net.UnixConn) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	valid := false
	err = raw.Control(func(fd uintptr) {
		cred, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		valid = e == nil && cred.Uid == uint32(os.Getuid())
	})
	return err == nil && valid
}

func (s *Server) Run(ctx context.Context) error {
	if _, err := config.Duration(s.Settings.UnlockTTL); err != nil {
		return err
	}
	if !filepath.IsAbs(s.Paths.DataDir) || !filepath.IsAbs(s.Paths.Socket) {
		return errors.New("data directory and socket paths must be absolute")
	}
	for _, dir := range []string{s.Paths.DataDir, filepath.Dir(s.Paths.Socket)} {
		if err := secure.Dir(dir); err != nil {
			return err
		}
	}
	dataLock, err := secure.Lock(filepath.Join(s.Paths.DataDir, "daemon.lock"))
	if err != nil {
		return err
	}
	defer dataLock.Close()
	socketLock, err := secure.Lock(s.Paths.Socket + ".lock")
	if err != nil {
		return err
	}
	defer socketLock.Close()
	if info, err := os.Lstat(s.Paths.Socket); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) || info.Mode()&os.ModeSocket == 0 {
			return errors.New("refusing to remove an unsafe socket path")
		}
		if err := os.Remove(s.Paths.Socket); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.Paths.Socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(s.Paths.Socket, 0600); err != nil {
		return err
	}
	defer func() { s.mu.Lock(); s.lock(); s.mu.Unlock() }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { <-ctx.Done(); listener.Close() }()
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.mu.Lock()
				s.expire()
				s.mu.Unlock()
			}
		}
	}()
	var workers sync.WaitGroup
	defer workers.Wait()
	slots := make(chan struct{}, 16)
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		if !sameUser(conn) {
			conn.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			defer func() { <-slots }()
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
			done := make(chan struct{})
			defer close(done)
			go func() {
				select {
				case <-ctx.Done():
					conn.Close()
				case <-done:
				}
			}()
			var req protocol.Request
			if err := protocol.Read(conn, &req, protocol.MaxMessage); err != nil {
				_ = protocol.Write(conn, failure("invalid", errors.New("invalid request")), protocol.MaxMessage)
				return
			}
			response := s.Handle(req)
			if err := protocol.Write(conn, response, protocol.MaxMessage); err != nil {
				_ = protocol.Write(conn, failure("invalid", errors.New("response exceeds size limit")), protocol.MaxMessage)
			}
		}()
	}
}
