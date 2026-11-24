package gateway

import (
	"context"
	"errors"
	"strings"
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

// TestLanForwardArgs guards the single-NIC rule shape: the only same-interface
// ACCEPT bypath may generate is destination-scoped to the LAN subnet.
func TestLanForwardArgs(t *testing.T) {
	args, err := lanForwardArgs("eth1", "10.10.0.0/24")
	if err != nil {
		t.Fatalf("lanForwardArgs: %v", err)
	}
	want := []string{"-i", "eth1", "-d", "10.10.0.0/24", "-j", "ACCEPT"}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("args = %v, want %v", args, want)
	}
	if args, err := lanForwardArgs("eth1", "10.10.0.9/24"); err != nil ||
		strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("host bits were not masked: %v, %v", args, err)
	}
	for _, tc := range []struct{ iface, subnet string }{
		{"eth1", ""},
		{"eth1", "not-a-cidr"},
		{"eth1", "10.10.0.1/32"},
		{"", "10.10.0.0/24"},
	} {
		if _, err := lanForwardArgs(tc.iface, tc.subnet); err == nil {
			t.Errorf("lanForwardArgs(%q, %q) accepted an unsafe rule", tc.iface, tc.subnet)
		}
	}
}

// dataPathHost is a canned host state for the containment probe. Rules are kept
// as they appear in `iptables -S` so the parser is exercised end to end.
type dataPathHost struct {
	forward   []string
	forwardV6 []string
	head      string
	headV6    string
	legacy    bool
}

func (h *dataPathHost) output(name string, args ...string) ([]byte, error) {
	chain, list := chainListed(args)
	switch name {
	case "iptables", "ip6tables":
		if !list {
			return nil, nil
		}
		switch chain {
		case "BYPATH_FWD":
			return []byte(strings.Join(h.forward, "\n") + "\n"), nil
		case "BYPATH_V6":
			return []byte(strings.Join(h.forwardV6, "\n") + "\n"), nil
		case "FORWARD":
			head := h.head
			if name == "ip6tables" {
				head = h.headV6
			}
			return []byte(head + "\n"), nil
		}
		return nil, errors.New("no chain/target/match by that name")
	case "ip":
		switch {
		case len(args) >= 2 && args[0] == "-brief" && args[1] == "link":
			return []byte("tun0             UNKNOWN        00:00:00:00:00:00 <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1500\n"), nil
		case len(args) >= 2 && args[0] == "route":
			return []byte("default via 10.0.0.1 dev tun0\nblackhole default metric 4096\n10.10.0.0/24 dev eth1 scope link\n"), nil
		case len(args) >= 2 && args[0] == "rule":
			return []byte("100: from all fwmark 0x1 lookup 100\n"), nil
		}
	}
	return nil, nil
}

// chainListed reports the chain of an "-S" query, ignoring the options bypath
// prepends.
func chainListed(args []string) (string, bool) {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-S" {
			return args[i+1], true
		}
	}
	return "", false
}

func healthyDataPathHost() *dataPathHost {
	return &dataPathHost{
		forward: []string{
			"-A BYPATH_FWD -i eth1 -o tun0 -j ACCEPT",
			"-A BYPATH_FWD -i eth1 -d 10.10.0.0/24 -j ACCEPT",
			"-A BYPATH_FWD -i eth1 -j DROP",
		},
		forwardV6: []string{"-A BYPATH_V6 -i eth1 -j DROP"},
		head:      "-A FORWARD -j BYPATH_FWD",
		headV6:    "-A FORWARD -j BYPATH_V6",
	}
}

// TestEvaluateDataPathProvesContainment covers the removal of the "tun0 exists
// therefore healthy" shortcut: each way the forwarding contract can be broken
// must make the probe unhealthy, whether or not the tunnel interface is up.
func TestEvaluateDataPathProvesContainment(t *testing.T) {
	enableContainmentHost(t)
	legacySpec := dataPathSpec{enabled: true, iface: "eth1", subnet: "10.10.0.0/24"}
	nativeSpec := legacySpec
	nativeSpec.native = true

	cases := []struct {
		name   string
		spec   dataPathSpec
		mutate func(*dataPathHost)
		want   string
	}{
		{"legacy healthy", legacySpec, func(*dataPathHost) {}, ""},
		{"native healthy", nativeSpec, func(*dataPathHost) {}, ""},
		{"same-interface accept", legacySpec, func(h *dataPathHost) {
			h.forward = append(h.forward[:2], append([]string{"-A BYPATH_FWD -i eth1 -o eth1 -j ACCEPT"}, h.forward[2:]...)...)
		}, "same-interface"},
		{"accept in native mode", nativeSpec, func(h *dataPathHost) {
			h.forward = append(h.forward[:2], append([]string{"-A BYPATH_FWD -i eth1 -o eth1 -j ACCEPT"}, h.forward[2:]...)...)
		}, "same-interface"},
		{"LAN rule missing", legacySpec, func(h *dataPathHost) {
			h.forward = []string{h.forward[0], h.forward[2]}
		}, "LAN-scoped"},
		{"catch-all drop missing", legacySpec, func(h *dataPathHost) {
			h.forward = h.forward[:2]
		}, "drop rule is missing"},
		{"tunnel accept missing", legacySpec, func(h *dataPathHost) {
			h.forward = h.forward[1:]
		}, "tunnel forwarding rule is missing"},
		{"jump demoted", legacySpec, func(h *dataPathHost) {
			h.head = "-A FORWARD -j ACCEPT\n-A FORWARD -j BYPATH_FWD"
		}, "not effective"},
		{"ipv6 drop missing", legacySpec, func(h *dataPathHost) {
			h.forwardV6 = nil
		}, "IPv6 containment"},
		{"ipv6 jump demoted", legacySpec, func(h *dataPathHost) {
			h.headV6 = "-A FORWARD -j ACCEPT\n-A FORWARD -j BYPATH_V6"
		}, "not effective"},
		{"native without containment", nativeSpec, func(h *dataPathHost) {
			h.forward = nil
		}, "drop rule is missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host := healthyDataPathHost()
			tc.mutate(host)
			stubHostCommands(t, nil, nil, host.output)

			healthy, detail := evaluateDataPath(tc.spec)
			if tc.want == "" {
				if !healthy {
					t.Fatalf("healthy data path reported: %s", detail)
				}
				return
			}
			if healthy {
				t.Fatalf("broken data path was reported healthy, want %q", tc.want)
			}
			if !strings.Contains(detail, tc.want) {
				t.Fatalf("detail = %q, want it to mention %q", detail, tc.want)
			}
		})
	}
}

// TestEnsureFailClosedRestoresNativeContainment proves the watchdog re-asserts
// the forwarding contract in native mode too. A flushed chain must be rebuilt
// tunnel allowance first, LAN allowance second, catch-all DROP last, and the
// IPv6 drop restored before anything is declared healthy.
func TestEnsureFailClosedRestoresNativeContainment(t *testing.T) {
	enableContainmentHost(t)
	host := healthyDataPathHost()
	host.forward = nil
	host.forwardV6 = nil
	calls := stubHostCommands(t, nil, nil, host.output)

	ensureFailClosed(dataPathSpec{enabled: true, native: true, iface: "eth1", subnet: "10.10.0.0/24"})

	joined := strings.Join(*calls, "\n")
	if strings.Contains(joined, "blackhole") {
		t.Fatalf("native repair touched the policy table it does not own:\n%s", joined)
	}
	want := []string{
		"-A BYPATH_FWD -i eth1 -o tun0 -j ACCEPT",
		"-A BYPATH_FWD -i eth1 -d 10.10.0.0/24 -j ACCEPT",
		"-A BYPATH_FWD -i eth1 -j DROP",
	}
	last := -1
	for _, rule := range want {
		idx := strings.Index(joined, rule)
		if idx < 0 {
			t.Fatalf("repair did not re-add %q:\n%s", rule, joined)
		}
		if idx < last {
			t.Fatalf("repair emitted %q out of order:\n%s", rule, joined)
		}
		last = idx
	}
	if !strings.Contains(joined, "ip6tables -w "+iptablesWaitSeconds+" -t filter -A BYPATH_V6 -i eth1 -j DROP") {
		t.Fatalf("repair did not re-assert IPv6 containment:\n%s", joined)
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
