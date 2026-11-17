//go:build !linux

package app

import (
	"context"
	"errors"
)

var errWorkerCancelled = errors.New("the host worker was cancelled before it reported")

// isolatedWorkerRequired is false off Linux: there is no network namespace to
// escape, so the in-process isolated instance runs where the daemon runs.
func isolatedWorkerRequired() (bool, string) { return false, "" }

// NetNSOf has no meaning off Linux.
func NetNSOf(int) string { return "" }

// workerUplinkInterface has no namespace split off Linux, so the daemon's own
// interface is the worker's.
func workerUplinkInterface(preferred string) string { return preferred }

func (s *Local) runWorkerProcess(context.Context, WorkerJob) (WorkerResult, error) {
	return WorkerResult{}, errors.New("the host test worker is only available on Linux")
}
