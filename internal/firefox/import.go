package firefox

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"pq/internal/model"
	"pq/internal/secure"
)

const maxImport = 32 << 20

func boundedRead(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxImport+1))
	if err != nil {
		secure.Wipe(data)
		return nil, err
	}
	if len(data) > maxImport {
		secure.Wipe(data)
		return nil, errors.New("Firefox import exceeds 32 MiB")
	}
	return data, nil
}

func CSV(r io.Reader) ([]model.Entry, error) {
	data, err := boundedRead(r)
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(data)
	reader := csv.NewReader(bytes.NewReader(data))
	header, err := reader.Read()
	if err != nil {
		return nil, errors.New("cannot read Firefox CSV header")
	}
	columns := map[string]int{}
	for i, name := range header {
		name = strings.TrimPrefix(name, "\ufeff")
		if _, exists := columns[name]; exists {
			return nil, errors.New("duplicate CSV column")
		}
		columns[name] = i
	}
	for _, name := range []string{"url", "username", "password"} {
		if _, ok := columns[name]; !ok {
			return nil, errors.New("expected Firefox CSV columns: url, username, password")
		}
	}
	entries := []model.Entry{}
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("invalid Firefox CSV row")
		}
		origin, err := model.Origin(row[columns["url"]])
		if err != nil {
			return nil, errors.New("Firefox CSV contains an unsupported website URL")
		}
		e := model.Entry{Kind: "login", Title: origin, Origins: []string{origin}, Username: row[columns["username"]], Password: row[columns["password"]]}
		if err := e.Validate(); err != nil {
			return nil, err
		}
		entries = append(entries, e)
		if len(entries) > 10000 {
			return nil, errors.New("import is limited to 10000 entries")
		}
	}
	return entries, nil
}

// Profile opens NSS read-only. Close Firefox before importing so logins.json
// and key4.db describe a consistent profile. No profile files are copied.
func Profile(path string, primaryPassword []byte) ([]model.Entry, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(absolute, "key4.db")); err != nil {
		return nil, errors.New("Firefox profile must contain key4.db")
	}
	f, err := os.Open(filepath.Join(absolute, "logins.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := boundedRead(f)
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(data)
	var document struct {
		Logins []struct {
			Hostname string `json:"hostname"`
			Username string `json:"encryptedUsername"`
			Password string `json:"encryptedPassword"`
		} `json:"logins"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, errors.New("invalid Firefox logins.json")
	}
	if len(document.Logins) > 10000 {
		return nil, errors.New("import is limited to 10000 entries")
	}
	decrypt, closeNSS, err := openNSS(absolute, primaryPassword)
	if err != nil {
		return nil, err
	}
	defer closeNSS()
	entries := make([]model.Entry, 0, len(document.Logins))
	for _, login := range document.Logins {
		origin, err := model.Origin(login.Hostname)
		if err != nil {
			return nil, errors.New("Firefox profile contains an unsupported website URL")
		}
		username, err := decrypt(login.Username)
		if err != nil {
			return nil, err
		}
		password, err := decrypt(login.Password)
		if err != nil {
			return nil, err
		}
		e := model.Entry{Kind: "login", Title: origin, Origins: []string{origin}, Username: username, Password: password}
		if err := e.Validate(); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}
