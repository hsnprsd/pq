// pq-native bridges Firefox's framed JSON messages to the local daemon.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"pq/internal/client"
	"pq/internal/config"
	"pq/internal/protocol"
	"pq/internal/secure"
)

func main() {
	syscall.Umask(0077)
	if err := secure.Harden(); err != nil {
		fmt.Fprintln(os.Stderr, "pq-native: process safeguards failed")
		os.Exit(1)
	}
	paths, err := config.Defaults()
	if err == nil {
		err = run(os.Stdin, os.Stdout, paths.Socket)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pq-native:", err)
		os.Exit(1)
	}
}

func allowed(op string) bool {
	switch op {
	case "status", "lock", "unlock", "browser.list", "browser.get", "browser.save":
		return true
	}
	return false
}

func run(in io.Reader, out io.Writer, socket string) error {
	for {
		var req protocol.Request
		err := protocol.Read(in, &req, protocol.NativeMaxMessage)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			secure.Wipe(req.Password)
			return errors.New("invalid native message")
		}
		response := protocol.Response{Version: protocol.Version}
		if !allowed(req.Op) {
			response.Error = "operation is not available to the browser"
			response.Code = "forbidden"
		} else {
			response, err = client.Call(socket, protocol.Request{Op: req.Op, Password: req.Password, TTL: req.TTL, Origin: req.Origin, ID: req.ID, Entry: req.Entry})
			if err != nil && response.Error == "" {
				response.Error = err.Error()
				response.Code = "unavailable"
			}
		}
		secure.Wipe(req.Password)
		response.Version = protocol.Version
		if err := protocol.Write(out, response, protocol.NativeMaxMessage); err != nil {
			if !errors.Is(err, protocol.ErrTooLarge) {
				return err
			}
			if err := protocol.Write(out, protocol.Response{Version: protocol.Version, Error: "native response exceeded size limit", Code: "invalid"}, protocol.NativeMaxMessage); err != nil {
				return err
			}
		}
	}
}
