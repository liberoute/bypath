package app

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/gateway"
)

// fakeGateway lets the tests hold connect and disconnect calls open so the
// cancellation contract can be observed without a live host.
type fakeGateway struct {
	mu          sync.Mutex
	stops       int
	starts      int
	aborts      int
	stopTunnels int

	startEntered      chan struct{}
	releaseStart      chan struct{}
	abortStart        chan struct{}
	stopTunnelEntered chan struct{}
	releaseStopTunnel chan struct{}
	startContexts     []context.Context

	startOnce   sync.Once
	abortOnce   sync.Once
	stopTunOnce sync.Once
}

func newFakeGateway() *fakeGateway {
	return &fakeGateway{
		startEntered:      make(chan struct{}),
		releaseStart:      make(chan struct{}),
		abortStart:        make(chan struct{}),
		stopTunnelEntered: make(chan struct{}),
		releaseStopTunnel: make(chan struct{}),
	}
}

func (f *fakeGateway) Stop() {
	f.mu.Lock()
	f.stops++
	f.mu.Unlock()
}

func (f *fakeGateway) StartWithContext(ctx context.Context) error {
	f.mu.Lock()
	f.startContexts = append(f.startContexts, ctx)
	f.mu.Unlock()
	return f.Start()
}

func (f *fakeGateway) Start() error {
	f.mu.Lock()
	f.starts++
	f.mu.Unlock()
	f.startOnce.Do(func() { close(f.startEntered) })
	select {
	case <-f.releaseStart:
		return nil
	case <-f.abortStart:
		return errors.New("start aborted")
	}
}

func (f *fakeGateway) AbortStartup() {
	f.mu.Lock()
	f.aborts++
	f.mu.Unlock()
	f.abortOnce.Do(func() { close(f.abortStart) })
}

func (f *fakeGateway) StopTunnel() {
	f.mu.Lock()
	f.stopTunnels++
	f.mu.Unlock()
	f.stopTunOnce.Do(func() { close(f.stopTunnelEntered) })
	<-f.releaseStopTunnel
}

func (f *fakeGateway) GetRuntimeStatus() gateway.RuntimeStatus { return gateway.RuntimeStatus{} }
func (f *fakeGateway) Reload(*config.Config) []string          { return nil }

func (f *fakeGateway) counts() (stops, starts, aborts, stopTunnels int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stops, f.starts, f.aborts, f.stopTunnels
}

func waitForCondition(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (r *GatewayRuntime) registeredOperations() int {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	return len(r.ops)
}

// TestStopTunnelCancelsAnotherClientsConnect is the F-01 regression: a
// Disconnect from one client must abort a Connect already running in another
// client instead of blocking until the startup budget expires.
func TestStopTunnelCancelsAnotherClientsConnect(t *testing.T) {
	fake := newFakeGateway()
	close(fake.releaseStopTunnel)
	shutdowns := 0
	rt := &GatewayRuntime{gw: fake, stop: func() { shutdowns++ }}

	connectDone := make(chan error, 1)
	go func() { connectDone <- rt.ApplyActiveLink(context.Background()) }()
	<-fake.startEntered

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	begin := time.Now()
	if err := rt.StopTunnel(ctx); err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	if elapsed := time.Since(begin); elapsed > 2*time.Second {
		t.Fatalf("disconnect took %s; it waited for the startup instead of cancelling it", elapsed)
	}

	select {
	case err := <-connectDone:
		if err == nil {
			t.Fatal("the cancelled connect reported success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the connect did not return after the disconnect")
	}

	stops, starts, aborts, stopTunnels := fake.counts()
	if starts != 1 || aborts != 1 {
		t.Fatalf("starts=%d aborts=%d, want 1/1", starts, aborts)
	}
	if stopTunnels != 1 {
		t.Fatalf("gateway StopTunnel calls=%d, want 1", stopTunnels)
	}
	if stops != 1 {
		t.Fatalf("gateway Stop calls=%d, want 1", stops)
	}
	if shutdowns != 0 {
		t.Fatalf("disconnect requested a process shutdown %d times", shutdowns)
	}
}

// TestStopTunnelCancelsQueuedConnect covers the second half of F-01: an
// attempt that is still waiting for the operation lock is rejected too, and it
// never reaches the gateway.
func TestStopTunnelCancelsQueuedConnect(t *testing.T) {
	fake := newFakeGateway()
	close(fake.releaseStopTunnel)
	rt := &GatewayRuntime{gw: fake}

	firstDone := make(chan error, 1)
	go func() { firstDone <- rt.ApplyActiveLink(context.Background()) }()
	<-fake.startEntered

	secondDone := make(chan error, 1)
	go func() { secondDone <- rt.ApplyActiveLink(context.Background()) }()
	waitForCondition(t, "both attempts to register", func() bool {
		return rt.registeredOperations() == 2
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rt.StopTunnel(ctx); err != nil {
		t.Fatalf("disconnect: %v", err)
	}

	for name, done := range map[string]chan error{"first": firstDone, "second": secondDone} {
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("%s attempt reported success after the disconnect", name)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s attempt did not return after the disconnect", name)
		}
	}

	_, starts, _, stopTunnels := fake.counts()
	if starts != 1 {
		t.Fatalf("gateway Start calls=%d, want 1 (the queued attempt must not start)", starts)
	}
	if stopTunnels != 1 {
		t.Fatalf("gateway StopTunnel calls=%d, want 1", stopTunnels)
	}
}

// TestConnectDuringDisconnectIsRejected proves the disconnect gate: a connect
// that arrives while the disconnect is still running does not restart the
// tunnel after the operator asked for it to stop.
func TestConnectDuringDisconnectIsRejected(t *testing.T) {
	fake := newFakeGateway()
	rt := &GatewayRuntime{gw: fake}

	disconnectDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		disconnectDone <- rt.StopTunnel(ctx)
	}()
	<-fake.stopTunnelEntered

	err := rt.ApplyActiveLink(context.Background())
	if err == nil {
		t.Fatal("a connect during a disconnect was accepted")
	}
	if !strings.Contains(err.Error(), "disconnect is in progress") {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, starts, _, _ := fake.counts(); starts != 0 {
		t.Fatalf("gateway Start calls=%d, want 0", starts)
	}

	close(fake.releaseStopTunnel)
	if err := <-disconnectDone; err != nil {
		t.Fatalf("disconnect: %v", err)
	}
}

// TestConnectAfterDisconnectWorks makes sure the gate reopens: the disconnect
// guard is for in-flight disconnects only.
func TestConnectAfterDisconnectWorks(t *testing.T) {
	fake := newFakeGateway()
	close(fake.releaseStopTunnel)
	rt := &GatewayRuntime{gw: fake}

	if err := rt.StopTunnel(context.Background()); err != nil {
		t.Fatalf("disconnect: %v", err)
	}
	close(fake.releaseStart)
	if err := rt.ApplyActiveLink(context.Background()); err != nil {
		t.Fatalf("connect after disconnect: %v", err)
	}
	if _, starts, _, _ := fake.counts(); starts != 1 {
		t.Fatalf("gateway Start calls=%d, want 1", starts)
	}
}

// TestOverlappingDisconnectsHoldGateUntilLastFinishes is the R-01 regression:
// the first disconnect to finish must not reopen the gate while another one is
// still stopping the tunnel.
func TestOverlappingDisconnectsHoldGateUntilLastFinishes(t *testing.T) {
	fake := newFakeGateway()
	rt := &GatewayRuntime{gw: fake}

	results := make(chan error, 2)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		results <- rt.StopTunnel(ctx)
	}()
	waitForCondition(t, "the first disconnect to enter StopTunnel", func() bool {
		_, _, _, stopTunnels := fake.counts()
		return stopTunnels == 1
	})

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		results <- rt.StopTunnel(ctx)
	}()
	waitForCondition(t, "both disconnects to enter StopTunnel", func() bool {
		_, _, _, stopTunnels := fake.counts()
		return stopTunnels == 2
	})

	if err := rt.ApplyActiveLink(context.Background()); err == nil {
		t.Fatal("a connect during overlapping disconnects was accepted")
	} else if !strings.Contains(err.Error(), "disconnect is in progress") {
		t.Fatalf("unexpected error: %v", err)
	}

	// Release exactly one disconnect; the gate must stay closed.
	fake.releaseStopTunnel <- struct{}{}
	select {
	case err := <-results:
		if err != nil {
			t.Fatalf("disconnect: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no disconnect finished after its release")
	}

	if err := rt.ApplyActiveLink(context.Background()); err == nil {
		t.Fatal("a connect was accepted while one disconnect was still running")
	}

	fake.releaseStopTunnel <- struct{}{}
	select {
	case err := <-results:
		if err != nil {
			t.Fatalf("disconnect: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the remaining disconnect did not finish")
	}

	close(fake.releaseStart)
	if err := rt.ApplyActiveLink(context.Background()); err != nil {
		t.Fatalf("connect after all disconnects: %v", err)
	}
	if _, starts, _, _ := fake.counts(); starts != 1 {
		t.Fatalf("gateway Start calls=%d, want 1", starts)
	}
}

// TestQueuedConnectRechecksDisconnectAfterLock is the R-02 regression: an
// attempt that was already queued when a disconnect began must re-check the
// gate after it acquires the lifecycle lock and must never call Stop/Start.
func TestQueuedConnectRechecksDisconnectAfterLock(t *testing.T) {
	fake := newFakeGateway()
	close(fake.releaseStart)
	rt := &GatewayRuntime{gw: fake}

	rt.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- rt.ApplyActiveLink(context.Background()) }()
	waitForCondition(t, "the attempt to register", func() bool {
		return rt.registeredOperations() == 1
	})

	// Simulate a disconnect that begins while the attempt is queued.
	rt.opMu.Lock()
	rt.disconnecting++
	rt.opMu.Unlock()
	rt.mu.Unlock()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a queued connect was accepted after a disconnect began")
		}
		if !strings.Contains(err.Error(), "disconnect is in progress") {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the queued connect did not return")
	}

	stops, starts, _, _ := fake.counts()
	if stops != 0 || starts != 0 {
		t.Fatalf("gateway Stop/Start calls=%d/%d, want 0/0", stops, starts)
	}
}

// TestCancellationRacingCompletionStaysCoherent cancels at the instant a start
// completes. Every iteration must end coherently: a reported success is never
// paired with an abort, and a reported failure always means the start was
// actually aborted rather than silently left running.
func TestCancellationRacingCompletionStaysCoherent(t *testing.T) {
	for i := 0; i < 200; i++ {
		fake := newFakeGateway()
		rt := &GatewayRuntime{gw: fake}
		ctx, cancel := context.WithCancel(context.Background())

		go func() {
			time.Sleep(time.Duration(i%3) * time.Millisecond)
			close(fake.releaseStart)
		}()
		done := make(chan error, 1)
		go func() { done <- rt.ApplyActiveLink(ctx) }()
		time.Sleep(time.Duration(i%2) * time.Millisecond)
		cancel()

		var err error
		select {
		case err = <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("iteration %d: connect did not return", i)
		}
		_, starts, aborts, _ := fake.counts()
		if err == nil && aborts != 0 {
			t.Fatalf("iteration %d: success reported after AbortStartup", i)
		}
		// A cancellation that wins before the start is registered is a clean
		// refusal (starts=0). If Start did run, a failure must come from aborting
		// it, never from an unrelated error path.
		if err != nil && starts == 1 && aborts == 0 {
			t.Fatalf("iteration %d: start reported %v without an abort", i, err)
		}
	}
}

func TestApplyActiveLinkHonoursCallerCancellation(t *testing.T) {
	fake := newFakeGateway()
	rt := &GatewayRuntime{gw: fake}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.ApplyActiveLink(ctx) }()
	<-fake.startEntered
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled connect reported success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled connect did not return")
	}
	if _, _, aborts, _ := fake.counts(); aborts != 1 {
		t.Fatalf("AbortStartup calls=%d, want 1", aborts)
	}
}

// TestDisconnectGateStaysClosedAfterCallerTimeout covers F-03: the disconnect
// gate must follow the gateway teardown, not the caller's wait. A cancelled
// caller used to reopen connects while StopTunnel was still running.
func TestDisconnectGateStaysClosedAfterCallerTimeout(t *testing.T) {
	fake := newFakeGateway()
	rt := &GatewayRuntime{gw: fake}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := rt.StopTunnel(ctx); err == nil {
		t.Fatal("disconnect reported success while the gateway stop was still running")
	}
	<-fake.stopTunnelEntered

	// While teardown is still in flight, a queued connect must be refused.
	connectDone := make(chan error, 1)
	go func() { connectDone <- rt.ApplyActiveLink(context.Background()) }()
	select {
	case err := <-connectDone:
		if err == nil || !strings.Contains(err.Error(), "disconnect is in progress") {
			t.Fatalf("queued connect error = %v, want a disconnect refusal", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("queued connect was not refused")
	}
	if _, starts, _, _ := fake.counts(); starts != 0 {
		t.Fatal("queued connect started the gateway during teardown")
	}

	close(fake.releaseStopTunnel)
	waitForCondition(t, "the disconnect to finish", func() bool {
		rt.opMu.Lock()
		defer rt.opMu.Unlock()
		return rt.disconnecting == 0
	})

	close(fake.releaseStart)
	if err := rt.ApplyActiveLink(context.Background()); err != nil {
		t.Fatalf("connect after a completed disconnect: %v", err)
	}
}

// TestApplyActiveLinkGivesStartTheCallerContext covers C2-01: if Start only
// received a context it cannot observe, a cancellation arriving before the
// start registered would be dropped by AbortStartup and the tunnel would come
// up behind the disconnect.
func TestApplyActiveLinkGivesStartTheCallerContext(t *testing.T) {
	fake := newFakeGateway()
	rt := &GatewayRuntime{gw: fake}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.ApplyActiveLink(ctx) }()
	<-fake.startEntered
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled connect reported success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled connect did not return")
	}

	fake.mu.Lock()
	defer fake.mu.Unlock()
	if len(fake.startContexts) != 1 {
		t.Fatalf("Start calls=%d, want 1", len(fake.startContexts))
	}
	if fake.startContexts[0].Err() == nil {
		t.Fatal("Start received a context the caller could not cancel")
	}
}
