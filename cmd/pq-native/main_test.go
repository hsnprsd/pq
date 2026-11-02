package main

import (
	"bytes"
	"testing"

	"pq/internal/protocol"
)

func TestNativeOperationAllowlist(t *testing.T) {
	for _, op := range []string{"get", "list", "put", "delete", "import", "init", "passwd", "backup", "browser.export", ""} {
		var in, out bytes.Buffer
		if err := protocol.Write(&in, protocol.Request{Op: op}, protocol.NativeMaxMessage); err != nil {
			t.Fatal(err)
		}
		if err := run(&in, &out, "/no/daemon"); err != nil {
			t.Fatal(err)
		}
		var response protocol.Response
		if err := protocol.Read(&out, &response, protocol.NativeMaxMessage); err != nil {
			t.Fatal(err)
		}
		if response.Code != "forbidden" || response.Version != protocol.Version {
			t.Fatalf("allowed %q", op)
		}
	}
	for _, op := range []string{"status", "lock", "unlock", "browser.list", "browser.get", "browser.save"} {
		if !allowed(op) {
			t.Fatalf("missing browser operation %q", op)
		}
	}
}
