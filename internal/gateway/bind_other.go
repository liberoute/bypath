//go:build !linux

package gateway

import "syscall"

// bindDeviceControl is a no-op off Linux: gateway mode only exists there, and
// the lab build must keep compiling and testing the same code path.
func bindDeviceControl(iface string) func(network, address string, c syscall.RawConn) error {
	return nil
}
