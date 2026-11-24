//go:build linux

package app

import "syscall"

// bindDeviceControl pins a dialer's sockets to the physical uplink interface.
// While the gateway TUN owns the default route, an unbound probe is itself
// tunneled, so the measured "direct uplink" would be the tunnel exit and every
// isolated measurement would be discarded as EXIT_EQUALS_UPLINK.
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
