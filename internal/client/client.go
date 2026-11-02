package client

import (
	"fmt"
	"net"
	"time"

	"pq/internal/protocol"
)

type RemoteError struct{ Code, Message string }

func (e *RemoteError) Error() string { return e.Message }

func Call(socket string, req protocol.Request) (protocol.Response, error) {
	var response protocol.Response
	conn, err := net.DialTimeout("unix", socket, 3*time.Second)
	if err != nil {
		return response, fmt.Errorf("cannot connect to pq daemon; start it with 'pq daemon' or systemctl --user start pq.service: %w", err)
	}
	defer conn.Close()
	if err = conn.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
		return response, err
	}
	if err = protocol.Write(conn, req, protocol.MaxMessage); err != nil {
		return response, err
	}
	if err = protocol.Read(conn, &response, protocol.MaxMessage); err != nil {
		return response, err
	}
	if response.Error != "" {
		return response, &RemoteError{Code: response.Code, Message: response.Error}
	}
	return response, nil
}
