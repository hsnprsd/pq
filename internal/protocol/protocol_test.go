package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestFrames(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, Request{Op: "status"}, MaxMessage); err != nil {
		t.Fatal(err)
	}
	var req Request
	if err := Read(&buf, &req, MaxMessage); err != nil || req.Op != "status" {
		t.Fatal(err)
	}
	for _, size := range []uint32{0, MaxMessage + 1, 0xffffffff} {
		var header [4]byte
		binary.LittleEndian.PutUint32(header[:], size)
		if err := Read(bytes.NewReader(header[:]), &req, MaxMessage); err == nil {
			t.Fatalf("accepted size %d", size)
		}
	}
	if err := Read(bytes.NewReader([]byte{20, 0, 0, 0, '{'}), &req, MaxMessage); err == nil {
		t.Fatal("accepted truncated frame")
	}
}

func FuzzRead(f *testing.F) {
	f.Add([]byte{2, 0, 0, 0, '{', '}'})
	f.Fuzz(func(t *testing.T, data []byte) { var req Request; _ = Read(bytes.NewReader(data), &req, 1024) })
}
