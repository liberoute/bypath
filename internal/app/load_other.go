//go:build !linux

package app

// measureHostLoad is a Linux-only guard: the daemon's production target is the
// Pi. Development builds have no load signal to trust, so they do not refuse.
func measureHostLoad() (bool, string) {
	return false, ""
}
