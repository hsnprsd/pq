package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"time"
	"unicode/utf8"

	"pq/internal/model"
	"pq/internal/secure"
)

const Version = 1

var ErrTooLarge = errors.New("message exceeds size limit")

const MaxMessage = 16 << 20
const NativeMaxMessage = 1 << 20

type Request struct {
	Version     int           `json:"version,omitempty"`
	Op          string        `json:"op"`
	Password    []byte        `json:"password,omitempty"`
	TTL         string        `json:"ttl,omitempty"`
	ID          string        `json:"id,omitempty"`
	Query       string        `json:"query,omitempty"`
	Origin      string        `json:"origin,omitempty"`
	Entry       *model.Entry  `json:"entry,omitempty"`
	Entries     []model.Entry `json:"entries,omitempty"`
	Duplicates  string        `json:"duplicates,omitempty"`
	Destination string        `json:"destination,omitempty"`
}

type Status struct {
	Initialized bool       `json:"initialized"`
	Locked      bool       `json:"locked"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	DefaultTTL  string     `json:"default_ttl"`
}

type Response struct {
	Version int                 `json:"version"`
	Error   string              `json:"error,omitempty"`
	Code    string              `json:"code,omitempty"`
	Status  *Status             `json:"status,omitempty"`
	Entry   *model.Entry        `json:"entry,omitempty"`
	Entries []model.Entry       `json:"entries,omitempty"`
	Import  *model.ImportResult `json:"import,omitempty"`
}

func Read(r io.Reader, value any, limit int) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	n := binary.LittleEndian.Uint32(header[:])
	if n == 0 || uint64(n) > uint64(limit) {
		return errors.New("invalid message size")
	}
	buf := make([]byte, n)
	defer secure.Wipe(buf)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	if !utf8.Valid(buf) {
		return errors.New("protocol JSON must be valid UTF-8")
	}
	if err := json.Unmarshal(buf, value); err != nil {
		return errors.New("invalid protocol JSON")
	}
	return nil
}

func Write(w io.Writer, value any, limit int) error {
	buf, err := json.Marshal(value)
	if err != nil {
		return errors.New("cannot encode response")
	}
	defer secure.Wipe(buf)
	if len(buf) > limit {
		return ErrTooLarge
	}
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(buf)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, buf)
}

func writeAll(w io.Writer, buf []byte) error {
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		buf = buf[n:]
	}
	return nil
}
