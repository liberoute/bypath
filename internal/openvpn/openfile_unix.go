//go:build !windows

package openvpn

import (
	"os"
	"syscall"
)

// openProfileFile opens a profile without blocking when the path is a FIFO or a
// device node. O_NONBLOCK makes open(2) return immediately; the caller rejects
// anything that is not a regular file before reading any bytes.
func openProfileFile(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
