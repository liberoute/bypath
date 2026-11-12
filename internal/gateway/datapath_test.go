package gateway

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/engine"
)

func TestTunLinkUp(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want bool
	}{
		{"up", "tun0             UNKNOWN        00:00:00:00:00:00 <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1500", true},
		{"admin down", "tun0             DOWN           <POINTOPOINT,NOARP> mtu 1500", false},
		{"no carrier", "tun0             NO-CARRIER     <POINTOPOINT,MULTICAST,NOARP,UP> mtu 1500", false},
		{"missing", "", false},
		{"other link", "eth0             UP             00:11:22:33:44:55", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tunLinkUp(tc.out); got != tc.want {
				t.Fatalf("tunLinkUp(%q) = %v, want %v", tc.out, got, tc.want)
			}
		})
	}
}

func TestRouteTableHelpers(t *testing.T) {
	routes := "default via 10.0.0.1 dev tun0\n" +
		"blackhole default metric 4096\n" +
		"10.10.0.0/24 dev eth1 scope link\n"

	if !hasTunnelDefault(routes, "eth1") {
		t.Error("tunnel default route was not found")
	}
	if hasTunnelDefault("default via 10.0.0.1 dev tun9\n", "eth1") {
		t.Error("a default route through another device was accepted")
	}
	if hasTunnelDefault("10.0.0.0/24 dev tun0 scope link\n", "eth1") {
		t.Error("a non-default route was accepted as the tunnel default")
	}
	if !hasBlackholeDefault(routes) {
		t.Error("fail-closed blackhole route was not found")
	}
	if hasBlackholeDefault("default via 10.0.0.1 dev tun0\n") {
		t.Error("a tunnel default was mistaken for the blackhole")
	}
	if !hasLANRoute(routes, "10.10.0.0/24", "eth1") {
		t.Error("LAN route was not found")
	}
	if hasLANRoute(routes, "10.10.0.0/24", "eth0") {
		t.Error("LAN route on the wrong interface was accepted")
	}
	if hasLANRoute("", "10.10.0.0/24", "eth1") {
		t.Error("empty route table was accepted")
	}
}

func TestRouteDefaultWithAttributesIsAccepted(t *testing.T) {
	// iproute2 may append attributes; the check must not depend on the field count.
	routes := "default via 10.0.0.1 dev tun0 metric 10 proto static\n"
	if !hasTunnelDefault(routes, "eth1") {
		t.Fatal("default route with attributes was rejected")
	}
}

// TestDataPathWatchdogDetectsLossAndRecovers proves the state machine reacts to
// a silently removed data path while the engine stays alive: it must report
// DEGRADED, repair locally and only return to CONNECTED after the probe passes.
func TestDataPathWatchdogDetectsLossAndRecovers(t *testing.T) {
	setDuration(t, &watchdogInterval, 5*time.Millisecond)
	setDuration(t, &recoveryBackoffBase, time.Millisecond)
	setDuration(t, &recoveryBackoffMax, time.Millisecond)

	var healthy atomic.Bool
	healthy.Store(false)
	var repairs atomic.Int32
	var sawUnhealthyState atomic.Bool
	setDataPathProbeHook(t, func(*Gateway) (bool, string) {
		if healthy.Load() {
			return true, ""
		}
		return false, "table 100 has no tunnel default route"
	})
	setRepairDataPathHook(t, func(gw *Gateway) (bool, error) {
		repairs.Add(1)
		// The outage must already be visible to the API before repair starts.
		switch gw.GetRuntimeStatus().State {
		case StateDegraded, StateRecovering:
			sawUnhealthyState.Store(true)
		}
		healthy.Store(true)
		return false, nil
	})
	setEngineRecoveryHook(t, func(*Gateway, string) bool {
		t.Fatal("a repairable data path must not restart the engine")
		return false
	})

	gw := &Gateway{ctx: context.Background(), config: &config.Config{}}
	gw.runtime = RuntimeStatus{State: StateConnected}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		gw.watchLoop(stop)
		close(done)
	}()
	defer func() {
		close(stop)
		<-done
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if repairs.Load() >= 1 && gw.GetRuntimeStatus().State == StateConnected {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}

	if !sawUnhealthyState.Load() {
		t.Fatal("the data-path outage was never reported as DEGRADED/RECOVERING")
	}
	if repairs.Load() != 1 {
		t.Fatalf("repair calls = %d, want 1", repairs.Load())
	}
	if st := gw.GetRuntimeStatus(); st.State != StateConnected {
		t.Fatalf("state = %q, want CONNECTED after the probe passed", st.State)
	}
}

// TestDataPathRecoveryExhaustionFallsBackToEngine checks the bounded-attempt
// contract: local repair is tried maxTunRecoveryAttempts times and only then is
// the engine restarted.
func TestDataPathRecoveryExhaustionFallsBackToEngine(t *testing.T) {
	setDuration(t, &recoveryBackoffBase, time.Millisecond)
	setDuration(t, &recoveryBackoffMax, time.Millisecond)

	setDataPathProbeHook(t, func(*Gateway) (bool, string) { return false, "tun0 is missing" })
	var repairs, engineCalls int
	setRepairDataPathHook(t, func(*Gateway) (bool, error) {
		repairs++
		return false, errors.New("cannot recreate tun0")
	})
	setEngineRecoveryHook(t, func(*Gateway, string) bool {
		engineCalls++
		return true
	})

	gw := &Gateway{ctx: context.Background(), config: &config.Config{}}
	if !gw.recoverDataPath("tun0 is missing") {
		t.Fatal("fallback engine recovery result was not returned")
	}
	if repairs != maxTunRecoveryAttempts {
		t.Fatalf("repair attempts = %d, want %d", repairs, maxTunRecoveryAttempts)
	}
	if engineCalls != 1 {
		t.Fatalf("engine recovery calls = %d, want 1", engineCalls)
	}
}

// TestUpstreamProbeFailureDoesNotRestartEngine covers N-4: a failing external
// probe while the engine and local data path are alive is an upstream outage,
// not a data-plane failure. No recovery or failover may run, but the reported
// state must not claim a Healthy tunnel: an unverified upstream is DEGRADED and
// carries the probe error, otherwise the panel shows "Healthy" with a stale
// timestamp while clients cannot reach the internet.
func TestUpstreamProbeFailureDoesNotRestartEngine(t *testing.T) {
	setDuration(t, &watchdogInterval, 5*time.Millisecond)
	setDuration(t, &healthIntervalFloor, 5*time.Millisecond)

	setDataPathProbeHook(t, func(*Gateway) (bool, string) { return true, "" })
	probes := make(chan struct{}, 32)
	setHealthProbeHook(t, func(*Gateway) (bool, string) {
		select {
		case probes <- struct{}{}:
		default:
		}
		return false, "health check failed: none of 2 endpoints responded through the tunnel"
	})
	setEngineRecoveryHook(t, func(*Gateway, string) bool {
		t.Fatal("an upstream probe failure must not restart a live engine")
		return false
	})

	cfg := &config.Config{}
	cfg.HealthCheck.Enabled = true
	cfg.HealthCheck.Interval = "10ms"
	gw := &Gateway{ctx: context.Background(), config: cfg}
	gw.runtime = RuntimeStatus{State: StateConnected}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		gw.watchLoop(stop)
		close(done)
	}()
	defer func() {
		close(stop)
		<-done
	}()

	// Let the failing probe run more than the old DEGRADED threshold.
	for i := 0; i < healthFailureThreshold+1; i++ {
		select {
		case <-probes:
		case <-time.After(2 * time.Second):
			t.Fatal("health probe never ran")
		}
	}
	st := gw.GetRuntimeStatus()

	if st.State != StateDegraded {
		t.Fatalf("state = %q, want DEGRADED: an unverified upstream is not a Healthy tunnel", st.State)
	}
	if st.LastError == "" {
		t.Fatal("LastError is empty: the panel must be able to show why the tunnel is degraded")
	}
}

// TestWatchdogDetectsEngineExit makes sure a supervised engine that terminates
// without the data path failing is still escalated to engine recovery.
func TestWatchdogDetectsEngineExit(t *testing.T) {
	setDuration(t, &watchdogInterval, 5*time.Millisecond)

	setDataPathProbeHook(t, func(*Gateway) (bool, string) { return true, "" })
	recovered := make(chan struct{}, 1)
	setEngineRecoveryHook(t, func(*Gateway, string) bool {
		select {
		case recovered <- struct{}{}:
		default:
		}
		return true
	})

	cmd := spawnExitingProcess()
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start helper process: %v", err)
	}
	waiter := engine.WaitAsync(cmd)
	if !waiter.Wait(5 * time.Second) {
		t.Fatal("helper process did not exit")
	}

	gw := &Gateway{ctx: context.Background(), config: &config.Config{}}
	gw.runtime = RuntimeStatus{State: StateConnected}
	gw.setEngineWaiter(waiter)

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		gw.watchLoop(stop)
		close(done)
	}()
	defer func() {
		close(stop)
		<-done
	}()

	select {
	case <-recovered:
	case <-time.After(2 * time.Second):
		t.Fatal("a dead engine was not escalated to engine recovery")
	}
}

func TestReconnectClearsOperatorStop(t *testing.T) {
	gw := &Gateway{}
	gw.rtMu.Lock()
	gw.operatorStop = true
	gw.rtMu.Unlock()

	if !gw.OperatorStopped() {
		t.Fatal("operator stop flag was not recorded")
	}
	if gw.initRuntimeLocked() {
		t.Fatal("unexpected pending abort consumed a fresh start")
	}
	if gw.OperatorStopped() {
		t.Fatal("an explicit Connect must clear the previous operator disconnect")
	}
}

func TestStopTunnelIsReflectedInState(t *testing.T) {
	gw := &Gateway{}
	gw.setRuntimeState(StateConnected, "")
	gw.rtMu.Lock()
	gw.operatorStop = true
	gw.rtMu.Unlock()
	gw.setRuntimeState(StateDisconnected, "")
	if st := gw.GetRuntimeStatus(); st.State != StateDisconnected {
		t.Fatalf("state = %q, want DISCONNECTED", st.State)
	}
}

func TestRecoveringStateCarriesAttempt(t *testing.T) {
	gw := &Gateway{}
	gw.setRuntimeAttempt(StateRecovering, 2, "table 100 has no tunnel default route")
	st := gw.GetRuntimeStatus()
	if st.State != StateRecovering {
		t.Fatalf("state = %q, want RECOVERING", st.State)
	}
	if st.RecoveryAttempt != 2 {
		t.Fatalf("recovery_attempt = %d, want 2", st.RecoveryAttempt)
	}
	if st.LastError == "" {
		t.Fatal("RECOVERING must keep the reason visible")
	}
}

// TestConcurrentStopDuringDataPathRecovery ensures shutdown wins over recovery:
// recovery must not publish CONNECTED after a stop request.
func TestConcurrentStopDuringDataPathRecovery(t *testing.T) {
	setDuration(t, &recoveryBackoffBase, 20*time.Millisecond)
	setDuration(t, &recoveryBackoffMax, 20*time.Millisecond)

	setDataPathProbeHook(t, func(*Gateway) (bool, string) { return false, "tun0 is missing" })
	setEngineRecoveryHook(t, func(*Gateway, string) bool {
		t.Fatal("recovery must stop instead of restarting the engine during shutdown")
		return false
	})
	var once sync.Once
	gw := &Gateway{ctx: context.Background(), config: &config.Config{}}
	setRepairDataPathHook(t, func(*Gateway) (bool, error) {
		once.Do(func() {
			gw.setRuntimeState(StateDisconnected, "")
			gw.rtMu.Lock()
			gw.stopping = true
			gw.rtMu.Unlock()
		})
		return false, errors.New("stopped")
	})

	if gw.recoverDataPath("tun0 is missing") {
		t.Fatal("recovery reported success during shutdown")
	}
	if st := gw.GetRuntimeStatus(); st.State == StateConnected {
		t.Fatal("recovery must not publish CONNECTED after a stop request")
	}
}
