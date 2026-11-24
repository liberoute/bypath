//go:build linux

package gateway

import "syscall"

// bindDeviceControl pins a dial to one interface. A gateway host's default
// route points at the TUN it serves, so the direct-uplink oracle must name the
// physical interface explicitly or it would observe its own exit.
func bindDeviceControl(iface string) func(network, address string, c syscall.RawConn) error {
	if iface == "" {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return sockErr
	}
}
