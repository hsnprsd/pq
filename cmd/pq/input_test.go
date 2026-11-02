package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBoundedStdin(t *testing.T) {
	original := os.Stdin
	defer func() { os.Stdin = original }()
	for _, tt := range []struct {
		input, want string
		trim, valid bool
	}{
		{"abcd\r\n", "abcd", true, true}, {"abcd\n", "abcd", true, true}, {"abcd", "abcd", true, true},
		{"abcd\r\nEXTRA", "", true, false}, {"abcde\n", "", true, false}, {"a\nb\n", "a\nb\n", false, true},
	} {
		path := filepath.Join(t.TempDir(), "stdin")
		if err := os.WriteFile(path, []byte(tt.input), 0600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		os.Stdin = f
		got, err := readInput(4, tt.trim)
		f.Close()
		if (err == nil) != tt.valid || tt.valid && string(got) != tt.want {
			t.Fatalf("input %q: got %q, %v", tt.input, got, err)
		}
	}
}
