//go:build linux

package app

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// ClaimWorkerStdio takes ownership of the worker's result channel and points
// the process's standard output at the log stream. Embedded engines log to
// stdout from inside this process, so without the redirect an engine line would
// be interleaved with the one machine-readable answer.
//
// resultFD is the inherited descriptor holding the result pipe: WorkerResultFD
// when a daemon spawned this process, or 1 when the worker was started by hand.
// logFD is where standard output is pointed afterwards.
func ClaimWorkerStdio(resultFD, logFD int) (*os.File, error) {
	if resultFD < 0 || logFD < 0 {
		return nil, fmt.Errorf("invalid worker descriptor pair (%d, %d)", resultFD, logFD)
	}
	if resultFD == logFD {
		return nil, fmt.Errorf("the worker result channel cannot share the log stream")
	}
	saved, err := unix.Dup(resultFD)
	if err != nil {
		return nil, fmt.Errorf("claiming the worker result channel: %w", err)
	}
	// Engine children must not inherit the result channel.
	unix.CloseOnExec(saved)
	if resultFD != 1 {
		_ = unix.Close(resultFD)
	}
	if err := unix.Dup2(logFD, 1); err != nil {
		_ = unix.Close(saved)
		return nil, fmt.Errorf("redirecting the worker standard output: %w", err)
	}
	os.Stdout = os.Stderr
	return os.NewFile(uintptr(saved), "bypath-worker-result"), nil
}

// WorkerResultFDForEnv reports which descriptor carries the result, based on the
// environment the daemon exports. A hand-started worker keeps standard output.
func WorkerResultFDForEnv() int {
	if v := os.Getenv(WorkerResultFDEnv); v != "" {
		if fd, err := strconv.Atoi(v); err == nil && fd > 2 {
			return fd
		}
	}
	return 1
}
