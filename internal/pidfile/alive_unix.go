//go:build !windows

package pidfile

import (
	"errors"
	"syscall"
)

// processAlive reports whether pid names a live process. Signal 0 performs the
// existence check without delivering a signal; EPERM still proves the process
// exists but belongs to another user.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	if err == nil || errors.Is(err, syscall.EPERM) {
		return true
	}
	return false
}
