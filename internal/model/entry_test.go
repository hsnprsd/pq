package model

import "testing"

func TestTextValidation(t *testing.T) {
	e := Entry{Kind: "secret", Title: "binary", Text: string([]byte{0xff})}
	if err := e.Validate(); err == nil {
		t.Fatal("accepted invalid UTF-8 that JSON would silently replace")
	}
}

func TestOrigins(t *testing.T) {
	for raw, want := range map[string]string{"https://Example.COM:443/login": "https://example.com", "http://example.com:80/x": "http://example.com", "https://example.com:8443": "https://example.com:8443", "https://[::1]:443/path": "https://[::1]"} {
		got, err := Origin(raw)
		if err != nil || got != want {
			t.Errorf("%q: %q %v", raw, got, err)
		}
	}
	for _, raw := range []string{"javascript:alert(1)", "https://user:pass@example.com", "example.com", "file:///tmp/a"} {
		if _, err := Origin(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	e := Entry{Kind: "login", Origins: []string{"https://example.com"}}
	for _, origin := range []string{"https://example.com.evil.test", "http://example.com", "https://sub.example.com", "https://example.com:444"} {
		if e.Matches(origin) {
			t.Errorf("matched %q", origin)
		}
	}
}
