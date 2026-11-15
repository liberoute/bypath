//go:build windows

package pidfile

import (
	"golang.org/x/sys/windows"
)

const stillActive = 259 // STILL_ACTIVE

// processAlive reports whether pid names a live process.
//
// os.Process.Signal(0) is unusable on Windows: Go returns EWINDOWS instead of
// probing liveness, which made 'bypath stop' treat a running daemon as dead.
// OpenProcess + GetExitCodeProcess is the native check.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		// ERROR_ACCESS_DENIED still proves the process exists.
		return err == windows.ERROR_ACCESS_DENIED
	}
	defer windows.CloseHandle(h)

	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}
