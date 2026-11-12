//go:build !linux

package app

// hostUnderLoad is a Linux-only guard: the daemon's production target is the
// Pi. Development builds have no load signal to trust, so they do not refuse.
func hostUnderLoad() (bool, string) {
	return false, ""
}
