//go:build !linux

package engine

import (
	"context"
	"time"
)

// processOwnsTCPListener has no portable implementation outside Linux. The
// gateway data path is Linux-only; other platforms keep the dial-based
// readiness check rather than failing startup on a missing assertion.
func processOwnsTCPListener(pid, port int) (bool, error) {
	return true, nil
}

// WaitForOwnedListener is a no-op outside Linux.
func WaitForOwnedListener(ctx context.Context, pid, port int, timeout time.Duration) error {
	return nil
}
