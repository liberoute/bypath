// Package pidfile manages PID file creation and process lifecycle.
package pidfile

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const DefaultPath = "./bypath.pid"

// Write writes the current process PID to the pid file.
func Write(path string) error {
	if path == "" {
		path = DefaultPath
	}
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0644)
}

// Read reads the PID from the pid file. Returns 0 if file doesn't exist.
func Read(path string) (int, error) {
	if path == "" {
		path = DefaultPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("invalid pid file content: %w", err)
	}
	return pid, nil
}

// Remove removes the pid file.
func Remove(path string) {
	if path == "" {
		path = DefaultPath
	}
	os.Remove(path)
}

// IsRunning checks if the process with the given PID is still running.
func IsRunning(pid int) bool {
	if pid <= 0 {
		return false
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds. We need to send signal 0 to check.
	// On Windows, FindProcess fails if process doesn't exist.
	err = proc.Signal(os.Signal(nil))
	// If err is nil or "operation not permitted", process exists
	if err == nil {
		return true
	}
	// Check if it's a permission error (process exists but we can't signal it)
	if strings.Contains(err.Error(), "operation not permitted") ||
		strings.Contains(err.Error(), "access is denied") {
		return true
	}
	return false
}

// IsRunningFromFile reads the PID file and checks if that process is running.
func IsRunningFromFile(path string) (int, bool) {
	pid, err := Read(path)
	if err != nil || pid == 0 {
		return 0, false
	}
	return pid, IsRunning(pid)
}

// StopFromFile reads the PID file and kills the process.
func StopFromFile(path string) error {
	pid, running := IsRunningFromFile(path)
	if !running {
		Remove(path)
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		Remove(path)
		return nil
	}

	if err := proc.Kill(); err != nil {
		return fmt.Errorf("killing process %d: %w", pid, err)
	}

	Remove(path)
	return nil
}
