package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func closedChan() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func TestWaitForEngineReadyRetriesUntilReady(t *testing.T) {
	polls := 0
	ready := func() bool {
		polls++
		return polls >= 3
	}

	err := waitForEngineReady(context.Background(), time.Now().Add(time.Second),
		make(chan struct{}), nil, ready, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("expected readiness, got %v", err)
	}
	if polls != 3 {
		t.Fatalf("expected 3 polls, got %d", polls)
	}
}

func TestWaitForEngineReadyReportsEarlyExit(t *testing.T) {
	exited := make(chan struct{})
	ready := func() bool {
		close(exited)
		return false
	}
	exitErr := func() error { return errors.New("exit status 1") }

	err := waitForEngineReady(context.Background(), time.Now().Add(time.Second),
		exited, exitErr, ready, time.Second)
	if !errors.Is(err, errEngineExitedDuringStartup) {
		t.Fatalf("expected early-exit error, got %v", err)
	}
	if got := err.Error(); !strings.Contains(got, "exit status 1") {
		t.Fatalf("expected exit status in error, got %q", got)
	}
}

func TestWaitForEngineReadyHonorsDeadline(t *testing.T) {
	err := waitForEngineReady(context.Background(), time.Now().Add(30*time.Millisecond),
		make(chan struct{}), nil, func() bool { return false }, 5*time.Millisecond)
	if !errors.Is(err, errStartupDeadline) {
		t.Fatalf("expected deadline error, got %v", err)
	}
}

func TestWaitForEngineReadyHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ready := func() bool {
		cancel()
		return false
	}

	err := waitForEngineReady(ctx, time.Now().Add(time.Second),
		make(chan struct{}), nil, ready, 5*time.Millisecond)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestWaitForEngineReadyExitsWhileWaiting(t *testing.T) {
	exited := make(chan struct{})
	go func() {
		time.Sleep(20 * time.Millisecond)
		close(exited)
	}()

	err := waitForEngineReady(context.Background(), time.Now().Add(time.Second),
		exited, nil, func() bool { return false }, 10*time.Millisecond)
	if !errors.Is(err, errEngineExitedDuringStartup) {
		t.Fatalf("expected early-exit error, got %v", err)
	}
}

func TestWaitForEngineReadyImmediateExit(t *testing.T) {
	err := waitForEngineReady(context.Background(), time.Now().Add(time.Second),
		closedChan(), nil, func() bool { return false }, time.Second)
	if !errors.Is(err, errEngineExitedDuringStartup) {
		t.Fatalf("expected early-exit error, got %v", err)
	}
}
