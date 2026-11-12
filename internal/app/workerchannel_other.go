//go:build !linux

package app

import (
	"errors"
	"os"
)

// ClaimWorkerStdio is only meaningful where the daemon can pass a private
// descriptor to the worker. Other platforms report that instead of guessing.
func ClaimWorkerStdio(resultFD, logFD int) (*os.File, error) {
	return nil, errors.New("the host test worker needs Linux descriptor passing")
}

// WorkerResultFDForEnv reports standard output: no daemon passes a channel on
// this platform.
func WorkerResultFDForEnv() int { return 1 }
