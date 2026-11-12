package gateway

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/profile"
)

func newFallbackTestGateway(t *testing.T, endpointTimeout, totalTimeout string) (*Gateway, *profile.Manager) {
	t.Helper()
	mgr, err := profile.NewManager(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("profile manager: %v", err)
	}
	for _, remark := range []string{"dead-a", "dead-b", "dead-c"} {
		err := mgr.AddLink("default", &profile.Link{
			Protocol: "vless",
			Remark:   remark,
			Address:  "203.0.113.10",
			Port:     443,
		})
		if err != nil {
			t.Fatalf("adding %s: %v", remark, err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cfg := &config.Config{
		Profiles: config.ProfilesConfig{ActiveGroup: "default"},
		Engines: config.EnginesConfig{Fallback: config.FallbackConfig{
			Enabled:         true,
			EndpointTimeout: endpointTimeout,
			TotalTimeout:    totalTimeout,
			Order:           []string{"sing-box"},
		}},
	}
	gw := &Gateway{
		config:     cfg,
		profileMgr: mgr,
		socksPort:  2801,
		ctx:        ctx,
		cancel:     cancel,
	}
	t.Cleanup(cancel)
	return gw, mgr
}

func stubFallbackProbes(t *testing.T, start func(context.Context, *profile.Link) error, probe func(context.Context) bool) {
	t.Helper()
	oldStart, oldProbe := startEngineAttempt, probeTunnelConnection
	t.Cleanup(func() {
		startEngineAttempt, probeTunnelConnection = oldStart, oldProbe
	})
	startEngineAttempt = func(_ *Gateway, ctx context.Context, link *profile.Link) error {
		return start(ctx, link)
	}
	probeTunnelConnection = func(_ *Gateway, ctx context.Context) bool {
		if probe == nil {
			return false
		}
		return probe(ctx)
	}
}

// TestLinkFallbackBoundsConsecutiveDeadEndpoints proves a group of unreachable
// links cannot hold startup open: every link gets its own bounded attempt and
// the whole chain stops at the configured total budget.
func TestLinkFallbackBoundsConsecutiveDeadEndpoints(t *testing.T) {
	gw, _ := newFallbackTestGateway(t, "60ms", "1s")

	var calls int32
	stubFallbackProbes(t, func(ctx context.Context, _ *profile.Link) error {
		atomic.AddInt32(&calls, 1)
		<-ctx.Done()
		return ctx.Err()
	}, func(context.Context) bool {
		t.Error("connectivity probe ran for a link whose engine never started")
		return false
	})

	start := time.Now()
	err := gw.startEngineWithLinkFallback(gw.getActiveLink())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("fallback reported success with only dead endpoints")
	}
	if IsPermanent(err) {
		t.Fatalf("a timeout must stay retryable, got permanent error: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("attempts = %d, want 3 (active link plus two fallbacks)", got)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("dead-endpoint chain took %s, want near the 1s total budget", elapsed)
	}
}

// TestLinkFallbackTotalBudgetStopsChain proves the total budget wins over the
// per-link budget: one slow link cannot starve the rest of the group.
func TestLinkFallbackTotalBudgetStopsChain(t *testing.T) {
	gw, _ := newFallbackTestGateway(t, "5s", "80ms")

	var calls int32
	stubFallbackProbes(t, func(ctx context.Context, _ *profile.Link) error {
		atomic.AddInt32(&calls, 1)
		<-ctx.Done()
		return ctx.Err()
	}, nil)

	start := time.Now()
	err := gw.startEngineWithLinkFallback(gw.getActiveLink())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("fallback reported success with only dead endpoints")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("attempts = %d, want 1 before the total budget expired", got)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("total budget was not enforced: %s", elapsed)
	}
}

// TestLinkFallbackStopCancelsInFlightEngineStart proves Stop interrupts a slow
// engine attempt immediately instead of waiting for the attempt budget.
func TestLinkFallbackStopCancelsInFlightEngineStart(t *testing.T) {
	gw, _ := newFallbackTestGateway(t, "30s", "2m")

	// Buffered: the attempt signals before the test reaches its select, and a
	// dropped signal would wait out the timeout.
	entered := make(chan struct{}, 1)
	stubFallbackProbes(t, func(ctx context.Context, _ *profile.Link) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ctx.Err()
	}, nil)

	done := make(chan error, 1)
	go func() {
		// Startup holds mu for the whole engine phase (startWith), so attempt
		// bookkeeping and the rollback in Stop are serialized.
		gw.mu.Lock()
		defer gw.mu.Unlock()
		done <- gw.startEngineWithLinkFallback(gw.getActiveLink())
	}()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("engine attempt did not start")
	}

	stopped := make(chan struct{})
	go func() {
		gw.Stop()
		close(stopped)
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("fallback error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not cancel the in-flight engine attempt")
	}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return promptly")
	}
}

// TestLinkFallbackStopCancelsInFlightProbe proves a connectivity check in
// progress does not delay shutdown.
func TestLinkFallbackStopCancelsInFlightProbe(t *testing.T) {
	gw, _ := newFallbackTestGateway(t, "30s", "2m")

	probeEntered := make(chan struct{}, 1)
	stubFallbackProbes(t, func(context.Context, *profile.Link) error {
		return nil
	}, func(ctx context.Context) bool {
		select {
		case probeEntered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return false
	})

	done := make(chan error, 1)
	go func() {
		// Startup holds mu for the whole engine phase (startWith).
		gw.mu.Lock()
		defer gw.mu.Unlock()
		done <- gw.startEngineWithLinkFallback(gw.getActiveLink())
	}()

	select {
	case <-probeEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("connectivity probe did not start")
	}

	gw.Stop()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("fallback error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not cancel the connectivity probe")
	}
}

// TestLinkFallbackSucceedsOnNextLink proves a failed active link still falls
// back to a working link in the same group.
func TestLinkFallbackSucceedsOnNextLink(t *testing.T) {
	gw, mgr := newFallbackTestGateway(t, "200ms", "2s")

	var calls int32
	stubFallbackProbes(t, func(_ context.Context, link *profile.Link) error {
		atomic.AddInt32(&calls, 1)
		if link.Remark == "dead-a" {
			return errors.New("engine start failed")
		}
		return nil
	}, func(context.Context) bool { return true })

	selected := gw.getActiveLink()
	if selected == nil || selected.Remark != "dead-a" {
		t.Fatalf("unexpected active link: %+v", selected)
	}

	if err := gw.startEngineWithLinkFallback(selected); err != nil {
		t.Fatalf("fallback failed even though dead-b was healthy: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("attempts = %d, want 2", got)
	}
	active := gw.currentActiveLink()
	if active == nil || active.Remark != "dead-b" {
		t.Fatalf("active link = %+v, want dead-b", active)
	}
	if got := mgr.GetActiveLink(); got == nil || got.Remark != "dead-b" {
		t.Fatalf("manager active link = %+v, want dead-b", got)
	}
}
