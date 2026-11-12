//go:build windows

package control

import (
	"context"
	"errors"
	"net"
)

// Windows has no Unix-domain control socket here; the TUI and CLI keep using
// the loopback API, and paths.ControlSocket is empty.
func Listen(string, string) (net.Listener, error) {
	return nil, errors.New("local control socket is not supported on Windows")
}

func DialContext(context.Context, string) (net.Conn, error) {
	return nil, errors.New("local control socket is not supported on Windows")
}
