package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"pq/internal/secure"
)

type Paths struct{ DataDir, Socket, Config string }
type Settings struct {
	UnlockTTL string `json:"unlock_ttl"`
}

func Defaults() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, err
	}
	cfg, err := os.UserConfigDir()
	if err != nil {
		return Paths{}, err
	}
	data := os.Getenv("XDG_DATA_HOME")
	if data == "" {
		data = filepath.Join(home, ".local", "share")
	}
	runtime := os.Getenv("XDG_RUNTIME_DIR")
	if runtime == "" {
		runtime = filepath.Join(os.TempDir(), "pq-"+strconv.Itoa(os.Getuid()))
	}
	return Paths{DataDir: filepath.Join(data, "pq"), Socket: filepath.Join(runtime, "pq", "pq.sock"), Config: filepath.Join(cfg, "pq", "config.json")}, nil
}

func Load(path string) (Settings, error) {
	s := Settings{UnlockTTL: "15m"}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	defer f.Close()
	if err = secure.Check(path, false); err != nil {
		return s, err
	}
	data, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return s, err
	}
	trimmed := bytes.TrimSpace(data)
	if len(data) > 4096 || len(trimmed) == 0 || trimmed[0] != '{' {
		return s, errors.New("configuration must be a JSON object of at most 4096 bytes")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(&s); err != nil {
		return s, errors.New("invalid configuration JSON")
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return s, errors.New("configuration must contain one JSON object")
	}
	_, err = Duration(s.UnlockTTL)
	return s, err
}

func Duration(raw string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("unlock TTL must be a positive duration such as 15m or 1h")
	}
	return d, nil
}
