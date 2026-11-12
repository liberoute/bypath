package pidfile

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// StopRequestFile is the cross-platform graceful-stop channel. Unix signals do
// not exist on Windows, and there is no pkill; the stop command writes the
// target daemon PID here and the daemon watches the file.
const StopRequestFile = "stop-request"

// StopRequestPath returns the stop-request path inside the runtime directory.
func StopRequestPath(tmpDir string) string {
	return filepath.Join(tmpDir, StopRequestFile)
}

// RequestStop asks the daemon with targetPID to shut down gracefully. The PID is
// recorded so a stale request can never stop a different daemon that later
// reuses the same runtime directory.
func RequestStop(tmpDir string, targetPID int) error {
	if targetPID <= 0 {
		return fmt.Errorf("refusing stop request for invalid pid %d", targetPID)
	}
	path := StopRequestPath(tmpDir)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("preparing stop request: %w", err)
	}
	if err := os.WriteFile(path, []byte(strconv.Itoa(targetPID)), 0600); err != nil {
		return fmt.Errorf("writing stop request: %w", err)
	}
	return nil
}

// ReadStopRequest returns the PID a pending stop request targets.
func ReadStopRequest(tmpDir string) (int, bool) {
	data, err := os.ReadFile(StopRequestPath(tmpDir))
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}

// ClearStopRequest removes a stop request. Only the daemon that consumed it (or
// the stop command after a confirmed shutdown) should call this.
func ClearStopRequest(tmpDir string) {
	os.Remove(StopRequestPath(tmpDir))
}
