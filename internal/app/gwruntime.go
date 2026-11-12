package app

import (
	"context"
	"sync"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/gateway"
)

// gatewayController is the subset of the gateway the runtime mutates. It is an
// interface so the cancellation contract can be tested without a live host.
type gatewayController interface {
	Stop()
	StartWithContext(context.Context) error
	AbortStartup()
	StopTunnel()
	GetRuntimeStatus() gateway.RuntimeStatus
	Reload(*config.Config) []string
}

// GatewayRuntime adapts the live gateway to the Runtime interface. It is the
// only component allowed to stop and start the gateway in place, and it
// serializes those operations so two UI requests can never interleave.
type GatewayRuntime struct {
	gw      gatewayController
	engines *engine.Manager
	stop    func()

	mu      sync.Mutex
	applied time.Time
	// opMu owns the set of connect/restart attempts. A Disconnect cancels every
	// registered attempt and closes the set until it has finished, so a queued
	// attempt cannot restart the tunnel after the operator disconnected.
	opMu sync.Mutex
	ops  map[*runtimeOperation]struct{}
	// disconnecting counts in-flight Disconnect requests. The gate stays closed
	// until the last one finishes, so overlapping disconnects cannot let a
	// connect restart the tunnel after an earlier one reports success.
	disconnecting int
}

type runtimeOperation struct {
	cancel context.CancelFunc
}

// NewGatewayRuntime wires the adapter. requestStop signals the process main
// loop to shut down; it must be safe to call more than once.
func NewGatewayRuntime(gw *gateway.Gateway, engines *engine.Manager, requestStop func()) *GatewayRuntime {
	return &GatewayRuntime{gw: gw, engines: engines, stop: requestStop}
}

// registerOperation creates a cancellable attempt and publishes it so a
// concurrent Disconnect can cancel it while it waits for the operation lock.
func (r *GatewayRuntime) registerOperation(ctx context.Context) (context.Context, *runtimeOperation, error) {
	ctx, cancel := context.WithCancel(ctx)
	op := &runtimeOperation{cancel: cancel}

	r.opMu.Lock()
	if r.disconnecting > 0 {
		r.opMu.Unlock()
		cancel()
		return nil, nil, errorf(CodeUnavailable, "a disconnect is in progress; the connection attempt was not started")
	}
	if r.ops == nil {
		r.ops = make(map[*runtimeOperation]struct{})
	}
	r.ops[op] = struct{}{}
	r.opMu.Unlock()
	return ctx, op, nil
}

func (r *GatewayRuntime) finishOperation(op *runtimeOperation) {
	op.cancel()
	r.opMu.Lock()
	delete(r.ops, op)
	r.opMu.Unlock()
}

// acquireOperationLock waits for the serialization mutex with the attempt's
// context, so a Disconnect can abort an attempt that has not started yet. The
// caller owns the lock when this returns true.
func (r *GatewayRuntime) acquireOperationLock(ctx context.Context) bool {
	locked := make(chan struct{})
	go func() {
		r.mu.Lock()
		close(locked)
	}()

	select {
	case <-locked:
		if ctx.Err() != nil {
			r.mu.Unlock()
			return false
		}
		return true
	case <-ctx.Done():
		// The waiter may still acquire the mutex after the current operation
		// releases it; hand it straight back so it is never held indefinitely.
		go func() {
			<-locked
			r.mu.Unlock()
		}()
		return false
	}
}

// Status mirrors the gateway's live runtime state.
func (r *GatewayRuntime) Status() RuntimeStatus {
	rs := r.gw.GetRuntimeStatus()
	return RuntimeStatus{
		State:                string(rs.State),
		ActiveLink:           rs.ActiveLink,
		ActiveGroup:          rs.ActiveGroup,
		Protocol:             rs.Protocol,
		Engine:               rs.Engine,
		Restarts:             rs.Restarts,
		TunRestarts:          rs.TunRestarts,
		Recovery:             rs.RecoveryAttempt,
		LastError:            rs.LastError,
		LastHealth:           rs.LastHealth,
		HealthCode:           rs.HealthCode,
		HealthDetail:         rs.HealthDetail,
		HealthTunnelAnswered: rs.HealthTunnelAnswered,
		HealthExitIP:         rs.HealthExitIP,
		HealthUplinkSamples:  rs.HealthUplinkSamples,
		FallbackFrom:         rs.FallbackFrom,
		FallbackError:        rs.FallbackError,
	}
}

// ApplyActiveLink restarts the tunnel stack with the persisted active link.
// A fresh start replays host ownership, routing and DNS setup, so this is the
// only honest way to switch a running gateway. The caller's context bounds the
// whole operation (engine startup included); cancelling aborts the start.
func (r *GatewayRuntime) ApplyActiveLink(parent context.Context) error {
	ctx, op, err := r.registerOperation(parent)
	if err != nil {
		return err
	}
	defer r.finishOperation(op)

	if !r.acquireOperationLock(ctx) {
		return errorf(CodeUnavailable, "connection attempt cancelled before it could start: %v", ctx.Err())
	}
	defer r.mu.Unlock()

	// Re-check under the lifecycle lock. A disconnect can begin while this
	// attempt is queued behind another one; the pre-registration check alone
	// cannot see that, and the attempt must not run Stop/Start afterwards.
	r.opMu.Lock()
	disconnecting := r.disconnecting > 0
	r.opMu.Unlock()
	if disconnecting {
		return errorf(CodeUnavailable, "a disconnect is in progress; the connection attempt was not started")
	}

	stopDone := make(chan struct{})
	go func() {
		r.gw.Stop()
		close(stopDone)
	}()
	select {
	case <-stopDone:
	case <-ctx.Done():
		return errorf(CodeUnavailable, "connection attempt cancelled while stopping the gateway: %v", ctx.Err())
	}

	startDone := make(chan error, 1)
	// The caller's context goes into Start itself: AbortStartup is ignored
	// until a start has registered, so a cancellation in that window would
	// otherwise leave a start running after the disconnect.
	go func() { startDone <- r.gw.StartWithContext(ctx) }()
	select {
	case err := <-startDone:
		if err != nil {
			return errorf(CodeUnavailable, "gateway restart failed: %s", Redact(err.Error()))
		}
		r.applied = time.Now()
		return nil
	case <-ctx.Done():
		// Prefer a Start that finished concurrently. Aborting a completed start
		// would disable its watchdog and report failure for a live tunnel.
		select {
		case err := <-startDone:
			if err != nil {
				return errorf(CodeUnavailable, "gateway restart failed: %s", Redact(err.Error()))
			}
			r.applied = time.Now()
			return nil
		default:
			r.gw.AbortStartup()
			return errorf(CodeUnavailable, "connection attempt cancelled while starting the gateway: %v", ctx.Err())
		}
	}
}

// StopTunnel disconnects the VPN while keeping the process and its management
// listeners alive. It cancels every connect or restart attempt first, including
// ones started by another front end, and holds new attempts off until the
// disconnect has finished so a queued connect cannot bring the tunnel back up.
func (r *GatewayRuntime) StopTunnel(ctx context.Context) error {
	r.opMu.Lock()
	r.disconnecting++
	for op := range r.ops {
		op.cancel()
	}
	r.opMu.Unlock()
	// The gate must stay closed for as long as the gateway teardown is actually
	// running. Releasing it on the caller's deadline used to reopen connects
	// while gw.StopTunnel was still killing processes and undoing routing.
	release := func() {
		r.opMu.Lock()
		r.disconnecting--
		r.opMu.Unlock()
	}

	if !r.acquireOperationLock(ctx) {
		release()
		return errorf(CodeUnavailable, "timed out waiting for the in-flight operation: %v", ctx.Err())
	}
	r.mu.Unlock()

	done := make(chan struct{})
	go func() {
		defer release()
		r.gw.StopTunnel()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return errorf(CodeUnavailable, "timed out disconnecting the tunnel: %v", ctx.Err())
	}
}

// RequestStop asks the process main loop to shut down gracefully.
func (r *GatewayRuntime) RequestStop() error {
	if r.stop == nil {
		return errorf(CodeUnavailable, "no shutdown channel is available")
	}
	r.stop()
	return nil
}

// Engines lists the engines known to this gateway process.
func (r *GatewayRuntime) Engines() []Engine {
	if r.engines == nil {
		return nil
	}
	return engineViews(r.engines.List())
}

// Reload forwards a validated configuration to the gateway.
func (r *GatewayRuntime) Reload(cfg *config.Config) []string {
	return r.gw.Reload(cfg)
}
