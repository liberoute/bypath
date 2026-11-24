package engine

import (
	"os/exec"
	"sync"
	"time"
)

// ExitWaiter reaps a child process exactly once and exposes its exit to
// callers that must not call Wait themselves (Startup polling, gateway Stop,
// watchdog). Calling Wait twice on the same process is invalid, so every
// process started with WaitAsync must be reaped through its waiter.
type ExitWaiter struct {
	done chan struct{}
	mu   sync.Mutex
	err  error
}

// WaitAsync starts the single reaper for cmd and returns its waiter.
func WaitAsync(cmd *exec.Cmd) *ExitWaiter {
	w := &ExitWaiter{done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		w.mu.Lock()
		w.err = err
		w.mu.Unlock()
		close(w.done)
	}()
	return w
}

// Done is closed when the process has exited.
func (w *ExitWaiter) Done() <-chan struct{} { return w.done }

// Err returns the Wait error once the process exited, or nil while running.
func (w *ExitWaiter) Err() error {
	select {
	case <-w.done:
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.err
	default:
		return nil
	}
}

// Wait blocks until the process exits or the timeout elapses. It reports
// whether the process was reaped in time.
func (w *ExitWaiter) Wait(timeout time.Duration) bool {
	if w == nil {
		return true
	}
	select {
	case <-w.done:
		return true
	case <-time.After(timeout):
		return false
	}
}
