//go:build windows

package openvpn

import "os"

// openProfileFile is a plain open on Windows, where FIFOs are not a path type a
// profile can refer to; the regular-file check still runs before reading.
func openProfileFile(path string) (*os.File, error) {
	return os.Open(path)
}
