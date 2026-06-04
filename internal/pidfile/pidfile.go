// Package pidfile manages PID file creation and process lifecycle.
package pidfile

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
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
	// On Windows, FindProcess already checks existence.
	// On Unix, FindProcess always succeeds; send signal 0 to test liveness.
	// Must use syscall.Signal(0) — os.Signal(nil) is a nil interface and
	// causes "unsupported signal type" error instead of the intended no-op kill.
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	// EPERM means the process exists but we can't signal it (e.g. different user).
	if err == syscall.EPERM ||
		strings.Contains(err.Error(), "operation not permitted") ||
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

// TryAcquire atomically creates the pidfile and writes the current PID.
// Returns (0, nil) on success. Returns (existingPID, err) if already running.
// Uses O_EXCL for atomic create — only one process can succeed simultaneously.
func TryAcquire(path string) (int, error) {
	if path == "" {
		path = DefaultPath
	}

	for attempts := 0; attempts < 2; attempts++ {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err == nil {
			// We created the file atomically — we're the only instance.
			_, werr := fmt.Fprint(f, strconv.Itoa(os.Getpid()))
			f.Close()
			return 0, werr
		}

		if !os.IsExist(err) && !isErrExist(err) {
			return 0, fmt.Errorf("creating pid file: %w", err)
		}

		// File already exists — check if that process is alive.
		existingPID, readErr := Read(path)
		if readErr == nil && existingPID > 0 && IsRunning(existingPID) {
			return existingPID, fmt.Errorf("already running (PID %d)", existingPID)
		}

		// Stale pidfile (process is dead) — remove and retry once.
		os.Remove(path)
	}

	return 0, fmt.Errorf("could not acquire pid file after retries")
}

func isErrExist(err error) bool {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err == syscall.EEXIST
	}
	return false
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
