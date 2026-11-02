package model

import (
	"errors"
	"net"
	"net/url"
	"strings"
	"time"
)

const MaxSecret = 1 << 20

type ImportResult struct {
	Added   int `json:"added"`
	Updated int `json:"updated"`
	Skipped int `json:"skipped"`
}

type Entry struct {
	ID        string    `json:"id,omitempty"`
	Kind      string    `json:"kind"`
	Title     string    `json:"title"`
	Username  string    `json:"username,omitempty"`
	Password  string    `json:"password,omitempty"`
	Text      string    `json:"text,omitempty"`
	Origins   []string  `json:"origins,omitempty"`
	Notes     string    `json:"notes,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

func Origin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("expected an HTTP or HTTPS website URL without user information")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || strings.ContainsAny(host, " \t\r\n%") {
		return "", errors.New("invalid website host")
	}
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return u.Scheme + "://" + host, nil
}

func (e *Entry) Validate() error {
	if strings.TrimSpace(e.Title) == "" || len(e.Title) > 512 {
		return errors.New("title must contain 1–512 bytes")
	}
	if len(e.Username) > 4096 || len(e.Password) > MaxSecret || len(e.Text) > MaxSecret || len(e.Notes) > MaxSecret {
		return errors.New("entry field exceeds size limit")
	}
	if len(e.Tags) > 64 || len(e.Origins) > 64 {
		return errors.New("too many tags or origins")
	}
	for _, tag := range e.Tags {
		if len(tag) > 128 {
			return errors.New("tag exceeds size limit")
		}
	}
	switch e.Kind {
	case "login":
		if e.Text != "" {
			return errors.New("login entries cannot contain generic secret text")
		}
	case "secret":
		if e.Password != "" || e.Username != "" || len(e.Origins) != 0 {
			return errors.New("secret entries cannot contain login fields")
		}
	default:
		return errors.New("entry kind must be login or secret")
	}
	seen := map[string]bool{}
	origins := make([]string, 0, len(e.Origins))
	for _, raw := range e.Origins {
		if len(raw) > 4096 {
			return errors.New("website URL exceeds size limit")
		}
		origin, err := Origin(raw)
		if err != nil {
			return err
		}
		if !seen[origin] {
			origins = append(origins, origin)
			seen[origin] = true
		}
	}
	e.Origins = origins
	return nil
}

func (e Entry) Summary() Entry {
	e.Password, e.Text, e.Notes = "", "", ""
	return e
}

func (e Entry) Matches(origin string) bool {
	if e.Kind != "login" {
		return false
	}
	for _, candidate := range e.Origins {
		if candidate == origin {
			return true
		}
	}
	return false
}
