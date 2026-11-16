//go:build !linux

package app

import "syscall"

// bindDeviceControl is a no-op where SO_BINDTODEVICE does not exist; the host
// uplink is measured unbound and the platform decides the route.
func bindDeviceControl(iface string) func(network, address string, c syscall.RawConn) error {
	return nil
}
