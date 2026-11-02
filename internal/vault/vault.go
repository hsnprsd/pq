package vault

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"pq/internal/model"
	"pq/internal/secure"
	"pq/internal/sqlcipher"
)

var ErrNotFound = errors.New("entry not found")

type Vault struct {
	db   *sqlcipher.DB
	path string
}
type ImportResult = model.ImportResult

func Create(path string, password []byte) (*Vault, error) {
	if len(password) < 12 {
		return nil, errors.New("master password must contain at least 12 bytes")
	}
	f, err := secure.NewFile(path)
	if err != nil {
		return nil, err
	}
	f.Close()
	v, err := open(path, password, true)
	if err != nil {
		os.Remove(path)
		os.Remove(path + "-journal")
		return nil, err
	}
	if err = secure.SyncDir(path); err != nil {
		v.Close()
		return nil, err
	}
	return v, nil
}

func Open(path string, password []byte) (*Vault, error) { return open(path, password, false) }

func open(path string, password []byte, create bool) (*Vault, error) {
	if err := secure.Check(path, false); err != nil {
		return nil, err
	}
	db, err := sqlcipher.Open(path, password)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			db.Close()
		}
	}()
	if create {
		if err = db.Exec("CREATE TABLE entries (id TEXT PRIMARY KEY NOT NULL, payload TEXT NOT NULL)"); err != nil {
			return nil, err
		}
		if err = db.Exec("PRAGMA user_version = 1"); err != nil {
			return nil, err
		}
	}
	version, err := db.Query("PRAGMA user_version")
	if err != nil || len(version) != 1 || version[0][0] != "1" {
		return nil, errors.New("unsupported vault schema")
	}
	ok = true
	return &Vault{db: db, path: path}, nil
}

func (v *Vault) Close() error                { return v.db.Close() }
func (v *Vault) Rekey(password []byte) error { return v.db.Rekey(password) }

func (v *Vault) Get(id string) (model.Entry, error) {
	rows, err := v.db.Query("SELECT payload FROM entries WHERE id = ?", id)
	if err != nil {
		return model.Entry{}, err
	}
	if len(rows) == 0 {
		return model.Entry{}, ErrNotFound
	}
	var e model.Entry
	if err = json.Unmarshal([]byte(rows[0][0]), &e); err != nil {
		return e, errors.New("invalid entry in vault")
	}
	return e, nil
}

func (v *Vault) List() ([]model.Entry, error) {
	rows, err := v.db.Query("SELECT payload FROM entries ORDER BY id")
	if err != nil {
		return nil, err
	}
	entries := make([]model.Entry, 0, len(rows))
	for _, row := range rows {
		var e model.Entry
		if err := json.Unmarshal([]byte(row[0]), &e); err != nil {
			return nil, errors.New("invalid entry in vault")
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (v *Vault) Put(e model.Entry) (model.Entry, error) {
	if err := e.Validate(); err != nil {
		return e, err
	}
	now := time.Now().UTC()
	if e.ID == "" {
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return e, err
		}
		e.ID, e.CreatedAt = hex.EncodeToString(id[:]), now
	} else {
		old, err := v.Get(e.ID)
		if err != nil {
			return e, err
		}
		e.CreatedAt = old.CreatedAt
	}
	e.UpdatedAt = now
	payload, err := json.Marshal(e)
	if err != nil {
		return e, err
	}
	defer secure.Wipe(payload)
	err = v.db.Exec("INSERT INTO entries(id, payload) VALUES(?, ?) ON CONFLICT(id) DO UPDATE SET payload = excluded.payload", e.ID, string(payload))
	return e, err
}

func (v *Vault) Delete(id string) error {
	if _, err := v.Get(id); err != nil {
		return err
	}
	return v.db.Exec("DELETE FROM entries WHERE id = ?", id)
}

func duplicate(a, b model.Entry) bool {
	if a.Kind != b.Kind {
		return false
	}
	if a.Kind == "secret" {
		return a.Title == b.Title
	}
	if a.Username != b.Username {
		return false
	}
	for _, origin := range a.Origins {
		if b.Matches(origin) {
			return true
		}
	}
	return len(a.Origins) == 0 && len(b.Origins) == 0 && a.Title == b.Title
}

func (v *Vault) Import(entries []model.Entry, policy string) (result ImportResult, err error) {
	if policy != "skip" && policy != "update" && policy != "error" {
		return result, errors.New("duplicate policy must be skip, update, or error")
	}
	if len(entries) > 10000 {
		return result, errors.New("import is limited to 10000 entries")
	}
	for i := range entries {
		if err := entries[i].Validate(); err != nil {
			return result, err
		}
	}
	existing, err := v.List()
	if err != nil {
		return result, err
	}
	if err = v.db.Exec("BEGIN IMMEDIATE"); err != nil {
		return result, err
	}
	defer func() {
		if err != nil {
			_ = v.db.Exec("ROLLBACK")
			result = ImportResult{}
		}
	}()
	for _, e := range entries {
		e.ID = ""
		found := -1
		for i, old := range existing {
			if duplicate(e, old) {
				found = i
				break
			}
		}
		if found >= 0 {
			switch policy {
			case "skip":
				result.Skipped++
				continue
			case "error":
				return result, errors.New("duplicate entry; import rolled back")
			case "update":
				e.ID = existing[found].ID
			}
		}
		var saved model.Entry
		saved, err = v.Put(e)
		if err != nil {
			return result, err
		}
		if found >= 0 {
			result.Updated++
			existing[found] = saved
		} else {
			result.Added++
			existing = append(existing, saved)
		}
	}
	err = v.db.Exec("COMMIT")
	return result, err
}

// Backup copies a fully committed database while its sole owner serializes all
// operations. DELETE journal mode and synchronous=FULL are enforced on open.
// The caller must not use this Vault concurrently with Backup or any operation.
func (v *Vault) Backup(destination string) (err error) {
	source, err := os.Open(v.path)
	if err != nil {
		return err
	}
	defer source.Close()
	dest, err := secure.NewFile(destination)
	if err != nil {
		return err
	}
	defer func() {
		dest.Close()
		if err != nil {
			os.Remove(destination)
		}
	}()
	if _, err = io.Copy(dest, source); err != nil {
		return err
	}
	if err = dest.Sync(); err != nil {
		return err
	}
	if err = dest.Close(); err != nil {
		return err
	}
	return secure.SyncDir(destination)
}

func Search(entries []model.Entry, query string) []model.Entry {
	result := []model.Entry{}
	query = strings.ToLower(query)
	for _, e := range entries {
		haystack := strings.ToLower(strings.Join([]string{e.Title, e.Username, strings.Join(e.Origins, " "), strings.Join(e.Tags, " ")}, " "))
		if strings.Contains(haystack, query) {
			result = append(result, e.Summary())
		}
	}
	return result
}
