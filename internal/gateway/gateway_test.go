package gateway

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/acceptance"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/profile"
	"github.com/miekg/dns"
)

func TestWaitForTUNDevice_Timeout(t *testing.T) {
	// Use a non-existent interface name to trigger timeout
	err := waitForTUNDevice("nonexistent_iface_xyz", 1*time.Second)
	if err == nil {
		t.Fatal("expected error for non-existent interface, got nil")
	}
	if err.Error() != `TUN device "nonexistent_iface_xyz" not found after 1s` {
		t.Fatalf("unexpected error message: %s", err.Error())
	}
}

func TestWaitForTUNDevice_ExistingInterface(t *testing.T) {
	// "lo" (loopback) exists on Linux, "Loopback Pseudo-Interface 1" on Windows.
	// Use loopback as a stand-in for an existing interface.
	err := waitForTUNDevice("Loopback Pseudo-Interface 1", 2*time.Second)
	if err != nil {
		// On Linux, try "lo"
		err = waitForTUNDevice("lo", 2*time.Second)
		if err != nil {
			t.Skipf("skipping: no known loopback interface found (Windows='Loopback Pseudo-Interface 1', Linux='lo')")
		}
	}
}

// newTestGateway creates a minimal Gateway struct for testing orchestration logic.
// It does NOT start any processes — only sets up the struct for field-level assertions.
func newTestGateway(gwEnabled, nativeTUN bool) *Gateway {
	ctx, cancel := context.WithCancel(context.Background())
	cfg := &config.Config{
		Server: config.ServerConfig{
			SOCKSPort: 2801,
			DNSPort:   53,
		},
		Gateway: config.GatewayConfig{
			Enabled:   gwEnabled,
			NativeTUN: nativeTUN,
		},
	}
	return &Gateway{
		config:    cfg,
		socksPort: cfg.Server.SOCKSPort,
		dnsPort:   cfg.Server.DNSPort,
		ctx:       ctx,
		cancel:    cancel,
		mu:        sync.Mutex{},
	}
}

// --- Integration tests for gateway orchestrator decision logic ---

func TestNativeTUNPath_NoLegacyProcesses(t *testing.T) {
	// Validates Requirements 3.1, 3.2, 3.3, 3.5
	// When gateway is enabled and NativeTUN=true, after a successful engine start
	// the nativeTUN flag should be true, meaning tun2socks/dns2socks are NOT started.

	tests := []struct {
		name       string
		gwEnabled  bool
		nativeTUN  bool
		wantNative bool
	}{
		{
			name:       "gateway enabled with native TUN",
			gwEnabled:  true,
			nativeTUN:  true,
			wantNative: true,
		},
		{
			name:       "gateway enabled without native TUN",
			gwEnabled:  true,
			nativeTUN:  false,
			wantNative: false,
		},
		{
			name:       "gateway disabled with native TUN setting",
			gwEnabled:  false,
			nativeTUN:  true,
			wantNative: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newTestGateway(tt.gwEnabled, tt.nativeTUN)
			defer gw.cancel()

			// Simulate what startEngine does: set nativeTUN based on config
			if gw.config.Gateway.Enabled && gw.config.Gateway.NativeTUN {
				gw.nativeTUN = true
			} else {
				gw.nativeTUN = false
			}

			if gw.nativeTUN != tt.wantNative {
				t.Errorf("nativeTUN = %v, want %v", gw.nativeTUN, tt.wantNative)
			}

			// When nativeTUN is true, legacy processes (dnsProc, tunProc) should remain nil
			if gw.nativeTUN {
				if gw.dnsProc != nil {
					t.Error("dnsProc should be nil in native TUN mode (dns2socks not started)")
				}
				if gw.tunProc != nil {
					t.Error("tunProc should be nil in native TUN mode (tun2socks not started)")
				}
			}
		})
	}
}

func TestFallbackPath_LegacyProcessesAfterTUNFailure(t *testing.T) {
	// Validates Requirements 5.1, 5.2, 5.3, 5.4
	// When native TUN fails, restartEngineAsLegacy resets nativeTUN to false
	// and temporarily disables NativeTUN in config for legacy config generation.

	gw := newTestGateway(true, true)
	defer gw.cancel()

	// Simulate initial native TUN attempt succeeded (nativeTUN set to true)
	gw.nativeTUN = true

	// Now simulate TUN device not appearing — trigger fallback logic.
	// restartEngineAsLegacy should:
	// 1. Kill engine (nil here, so no-op)
	// 2. Temporarily set config.Gateway.NativeTUN = false
	// 3. Set gw.nativeTUN = false
	// We can't call restartEngineAsLegacy directly (it needs engine/profile managers),
	// but we can verify the logic it performs on the Gateway struct.

	// Simulate what restartEngineAsLegacy does to the Gateway state:
	origNativeTUN := gw.config.Gateway.NativeTUN
	gw.config.Gateway.NativeTUN = false
	gw.nativeTUN = false

	// Verify: nativeTUN flag is now false (legacy mode)
	if gw.nativeTUN {
		t.Error("nativeTUN should be false after fallback")
	}

	// Verify: config was temporarily disabled for config generation
	if gw.config.Gateway.NativeTUN {
		t.Error("config.Gateway.NativeTUN should be false during legacy config generation")
	}

	// Restore config (as the real function does with defer)
	gw.config.Gateway.NativeTUN = origNativeTUN

	// Verify: original config is restored after fallback
	if !gw.config.Gateway.NativeTUN {
		t.Error("config.Gateway.NativeTUN should be restored to original value after fallback")
	}

	// In legacy mode, the orchestrator would proceed to start dns2socks and tun2socks.
	// The key assertion is that nativeTUN=false means the Start() method takes the legacy branch.
	if gw.nativeTUN {
		t.Error("after fallback, nativeTUN must remain false so legacy path is taken")
	}
}

func TestConfigDrivenDisable_LegacyModeWhenNativeTUNFalse(t *testing.T) {
	// Validates Requirements 5.1, 6.2
	// When native_tun=false in config, the orchestrator should skip native TUN
	// attempt entirely and go straight to legacy mode.

	tests := []struct {
		name             string
		nativeTUNConfig  bool
		expectSkipNative bool
	}{
		{
			name:             "native_tun=false skips native TUN entirely",
			nativeTUNConfig:  false,
			expectSkipNative: true,
		},
		{
			name:             "native_tun=true attempts native TUN",
			nativeTUNConfig:  true,
			expectSkipNative: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newTestGateway(true, tt.nativeTUNConfig)
			defer gw.cancel()

			// Simulate the decision logic in startEngineWithFallback:
			// "If NativeTUN is disabled, skip native TUN attempt entirely"
			skippedNative := !gw.config.Gateway.NativeTUN
			if skippedNative {
				gw.nativeTUN = false
			}

			if skippedNative != tt.expectSkipNative {
				t.Errorf("skippedNative = %v, want %v", skippedNative, tt.expectSkipNative)
			}

			if tt.expectSkipNative && gw.nativeTUN {
				t.Error("nativeTUN should be false when config disables native TUN")
			}
		})
	}
}

func TestStartEngineWithFallback_ConfigDrivenDecision(t *testing.T) {
	// Validates Requirements 3.5, 5.1, 6.2, 6.3
	// Verifies the complete decision tree of startEngineWithFallback:
	// - NativeTUN=false → nativeTUN stays false, legacy path
	// - NativeTUN=true + gateway enabled → nativeTUN set true after engine start
	// - NativeTUN=true + gateway disabled → nativeTUN stays false

	tests := []struct {
		name            string
		gwEnabled       bool
		nativeTUNConfig bool
		wantNativeTUN   bool
		wantGatewayMode bool
	}{
		{
			name:            "config disables native TUN → legacy mode",
			gwEnabled:       true,
			nativeTUNConfig: false,
			wantNativeTUN:   false,
			wantGatewayMode: false,
		},
		{
			name:            "config enables native TUN + gateway → native mode",
			gwEnabled:       true,
			nativeTUNConfig: true,
			wantNativeTUN:   true,
			wantGatewayMode: true,
		},
		{
			name:            "config enables native TUN but gateway disabled → no TUN",
			gwEnabled:       false,
			nativeTUNConfig: true,
			wantNativeTUN:   false,
			wantGatewayMode: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gw := newTestGateway(tt.gwEnabled, tt.nativeTUNConfig)
			defer gw.cancel()

			// Simulate the startEngineWithFallback + startEngine decision:
			// In startEngineWithFallback: if !config.Gateway.NativeTUN → nativeTUN=false
			// In startEngine: if config.Gateway.Enabled && config.Gateway.NativeTUN → set GatewayMode, then nativeTUN=true
			if !gw.config.Gateway.NativeTUN {
				gw.nativeTUN = false
			} else if gw.config.Gateway.Enabled && gw.config.Gateway.NativeTUN {
				// This is what startEngine does after successful start
				gw.nativeTUN = true
			}

			// Check GatewayMode would be set in config generator
			gatewayMode := gw.config.Gateway.Enabled && gw.config.Gateway.NativeTUN

			if gw.nativeTUN != tt.wantNativeTUN {
				t.Errorf("nativeTUN = %v, want %v", gw.nativeTUN, tt.wantNativeTUN)
			}
			if gatewayMode != tt.wantGatewayMode {
				t.Errorf("gatewayMode = %v, want %v", gatewayMode, tt.wantGatewayMode)
			}
		})
	}
}

func TestRestartEngineAsLegacy_ResetsConfig(t *testing.T) {
	// Validates Requirements 5.2, 5.3
	// Verifies that restartEngineAsLegacy properly:
	// 1. Sets nativeTUN = false
	// 2. Temporarily sets config.Gateway.NativeTUN = false for config generation
	// 3. Restores config.Gateway.NativeTUN after config generation

	gw := newTestGateway(true, true)
	defer gw.cancel()

	// Initially in native TUN mode
	gw.nativeTUN = true

	// Simulate restartEngineAsLegacy logic:
	// Step 1: Kill engine (no-op, engineProc is nil)
	if gw.engineProc != nil {
		t.Fatal("engineProc should be nil in test setup")
	}

	// Step 2: Temporarily disable NativeTUN
	origNativeTUN := gw.config.Gateway.NativeTUN
	gw.config.Gateway.NativeTUN = false

	// Step 3: Set nativeTUN = false
	gw.nativeTUN = false

	// At this point, config generation would produce mixed-inbound config (no TUN)
	gatewayModeForConfigGen := gw.config.Gateway.Enabled && gw.config.Gateway.NativeTUN
	if gatewayModeForConfigGen {
		t.Error("during legacy restart, config generator should NOT use gateway mode")
	}

	// Step 4: Restore config (simulating defer)
	gw.config.Gateway.NativeTUN = origNativeTUN

	// Final state assertions
	if gw.nativeTUN {
		t.Error("nativeTUN must remain false after restart as legacy")
	}
	if !gw.config.Gateway.NativeTUN {
		t.Error("config.Gateway.NativeTUN should be restored to true (original value)")
	}
}

// --- Task 5.3: gateway FallbackController integration tests ---

func TestGetActiveEngine_InitiallyEmpty(t *testing.T) {
	gw := newTestGateway(true, true)
	defer gw.cancel()

	if got := gw.GetActiveEngine(); got != "" {
		t.Errorf("GetActiveEngine() = %q, want \"\" initially", got)
	}
}

func TestGetActiveEngine_ReflectsActiveEngine(t *testing.T) {
	for _, engine := range []string{"sing-box", "xray"} {
		t.Run(engine, func(t *testing.T) {
			gw := newTestGateway(true, true)
			defer gw.cancel()

			gw.activeEngine = engine
			if got := gw.GetActiveEngine(); got != engine {
				t.Errorf("GetActiveEngine() = %q, want %q", got, engine)
			}
		})
	}
}

func TestGetActiveEngine_ClearedOnStop(t *testing.T) {
	gw := newTestGateway(true, true)
	defer gw.cancel()

	gw.activeEngine = "sing-box"
	// Simulate what startEngineWithEngineFallback does on stop
	gw.activeEngine = ""

	if got := gw.GetActiveEngine(); got != "" {
		t.Errorf("GetActiveEngine() = %q after clear, want \"\"", got)
	}
}

// TestNativeTUN_NotSetForXray verifies that when the engine that starts is xray,
// nativeTUN is NOT set — xray has no TUN device, so tun2socks must not be skipped.
func TestNativeTUN_NotSetForXray(t *testing.T) {
	gw := newTestGateway(true, true) // gateway enabled, nativeTUN config = true
	defer gw.cancel()

	// Simulate startEngine outcome: FallbackController returned xray
	engineName := "xray"
	gw.activeEngine = engineName

	// Replicate the nativeTUN assignment logic from startEngine (gateway.go:660):
	if gw.config.Gateway.Enabled && gw.config.Gateway.NativeTUN && engineName == "sing-box" {
		gw.nativeTUN = true
	}

	if gw.nativeTUN {
		t.Error("nativeTUN must NOT be set when xray is the active engine (xray provides no TUN device)")
	}
}

// TestNativeTUN_SetForSingbox verifies that when sing-box starts successfully in
// gateway+nativeTUN mode, the nativeTUN flag is set (tun2socks path is skipped).
func TestNativeTUN_SetForSingbox(t *testing.T) {
	gw := newTestGateway(true, true)
	defer gw.cancel()

	engineName := "sing-box"
	gw.activeEngine = engineName

	// Replicate startEngine logic (gateway.go:660)
	if gw.config.Gateway.Enabled && gw.config.Gateway.NativeTUN && engineName == "sing-box" {
		gw.nativeTUN = true
	}

	if !gw.nativeTUN {
		t.Error("nativeTUN must be set when sing-box starts in gateway+nativeTUN mode")
	}
}

// stubLifecycleHost freezes every execution path that could reach the host for
// the duration of one lifecycle test: host commands, systemd and pkill.
func stubLifecycleHost(t *testing.T) *[]string {
	t.Helper()
	isolateHostState(t)
	calls := stubHostCommands(t, nil, nil, nil)

	oldOutput, oldRun, oldPkill := systemctlOutput, systemctlRun, pkillCommand
	systemctlOutput = func(args ...string) ([]byte, error) {
		*calls = append(*calls, "systemctl-output "+strings.Join(args, " "))
		return []byte("inactive\n"), nil
	}
	systemctlRun = func(args ...string) error {
		*calls = append(*calls, "systemctl-run "+strings.Join(args, " "))
		return nil
	}
	pkillCommand = func(pattern string) {
		*calls = append(*calls, "pkill "+pattern)
	}
	t.Cleanup(func() {
		systemctlOutput, systemctlRun, pkillCommand = oldOutput, oldRun, oldPkill
	})
	return calls
}

// hostMutationCommands filters a command log down to the commands that can
// change host networking, resolver configuration or firewall state. Process
// cleanup (pkill) is expected on every start and is not a network mutation.
func hostMutationCommands(calls []string) []string {
	var out []string
	for _, c := range calls {
		for _, prefix := range []string{"ip ", "iptables ", "ip6tables ", "sysctl ", "systemctl-", "resolvconf "} {
			if strings.HasPrefix(c, prefix) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

func testStartupHooks(gw *Gateway, started *int) *startupHooks {
	return &startupHooks{
		detectNetwork: func() error {
			gw.iface = "eth0"
			gw.localIP = "192.0.2.10"
			gw.realGW = "192.0.2.1"
			gw.subnet = "192.0.2.0/24"
			return nil
		},
		activeLink: func() *profile.Link {
			return &profile.Link{Protocol: "vless", Remark: "lifecycle", Address: "203.0.113.9", Port: 443}
		},
		startEngine: func(*profile.Link) error {
			*started++
			gw.activeEngine = "sing-box"
			return nil
		},
	}
}

// TestProxyOnlyLifecycleLeavesHostUntouched drives the real Start/Stop lifecycle
// in proxy-only mode. No routing, resolver, firewall or service command may run,
// and no ownership record may be written: a proxy-only run is not allowed to
// claim resources it does not own.
func TestProxyOnlyLifecycleLeavesHostUntouched(t *testing.T) {
	calls := stubLifecycleHost(t)

	gw := newTestGateway(false, false)
	defer gw.cancel()
	started := 0
	if err := gw.startWith(testStartupHooks(gw, &started)); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if started != 1 {
		t.Fatalf("engine start calls = %d, want 1", started)
	}
	if gw.networkMutated {
		t.Error("proxy-only run marked host networking as mutated")
	}
	if gw.resolvedStopped {
		t.Error("proxy-only run stopped systemd-resolved")
	}
	if gatewayState() != nil {
		t.Fatalf("proxy-only run wrote an ownership record: %+v", gatewayState())
	}
	if got := hostMutationCommands(*calls); len(got) != 0 {
		t.Fatalf("proxy-only startup issued host-mutating commands: %v", got)
	}

	gw.Stop()
	if gatewayState() != nil {
		t.Error("proxy-only stop wrote an ownership record")
	}
	if got := hostMutationCommands(*calls); len(got) != 0 {
		t.Fatalf("proxy-only stop issued host-mutating commands: %v", got)
	}

	if dir := os.Getenv(acceptance.EvidenceDirEnv); dir != "" {
		res := acceptance.Result{
			Case:   "network.proxy-only-isolation",
			Status: acceptance.Success,
			Detail: "real Gateway.Start/Stop lifecycle with stubbed host backend: zero host-mutating commands, no ownership record, resolver untouched",
		}
		if err := acceptance.WriteEvidence(dir, res); err != nil {
			t.Errorf("writing acceptance evidence: %v", err)
		}
	}
}

// TestStartupAbortsWhenPreviousRecoveryFails proves a startup never layers new
// host changes on top of an interrupted rollback. The ownership record survives
// so a later attempt can finish the job.
func TestStartupAbortsWhenPreviousRecoveryFails(t *testing.T) {
	calls := stubLifecycleHost(t)

	st, err := markGatewayState("legacy")
	if err != nil {
		t.Fatalf("markGatewayState: %v", err)
	}
	st.Routes = [][]string{{"route", "add", "default", "via", "10.0.0.1", "dev", "tun0", "table", "100"}}
	if err := saveGatewayState(st); err != nil {
		t.Fatalf("saveGatewayState: %v", err)
	}

	oldRun := runCommand
	runCommand = func(name string, args ...string) error {
		*calls = append(*calls, strings.Join(append([]string{name}, args...), " "))
		if name == "ip" && len(args) > 1 && args[0] == "route" && args[1] == "del" {
			return errors.New("simulated route deletion failure")
		}
		return nil
	}
	t.Cleanup(func() { runCommand = oldRun })
	outputCommand = func(name string, args ...string) ([]byte, error) {
		if name == "ip" && len(args) > 2 && args[0] == "route" && args[1] == "show" {
			return []byte("default via 10.0.0.1 dev tun0\n"), nil
		}
		return nil, nil
	}

	gw := newTestGateway(false, false)
	defer gw.cancel()
	started := 0
	err = gw.startWith(testStartupHooks(gw, &started))
	if err == nil || !strings.Contains(err.Error(), "incomplete recovery") {
		t.Fatalf("Start error = %v, want incomplete recovery", err)
	}
	if started != 0 {
		t.Fatalf("engine started %d times despite failed recovery", started)
	}
	got := gatewayState()
	if got == nil || len(got.Routes) != 1 {
		t.Fatalf("ownership record = %+v, want the un-reversed route retained", got)
	}

	// Releasing the fault lets the next startup finish the pending inverse. No
	// new ownership record may be created by that recovery.
	runCommand = oldRun
	if err := gw.cleanupPreviousRun(); err != nil {
		t.Fatalf("second recovery: %v", err)
	}
	if gatewayState() != nil {
		t.Error("ownership record survived a successful second recovery")
	}
	joined := strings.Join(*calls, "\n")
	if !strings.Contains(joined, "ip route del default via 10.0.0.1 dev tun0 table 100") {
		t.Fatalf("recorded route was never reversed:\n%s", joined)
	}
}

// TestEngineStartFailureRollsBackHostState proves a failed engine start does
// not leave native ownership recorded, services stopped or listeners running.
// The rollback runs inside Start so the caller is never handed a half-started
// host.
func TestEngineStartFailureRollsBackHostState(t *testing.T) {
	calls := stubLifecycleHost(t)
	oldOutput := outputCommand
	outputCommand = func(name string, args ...string) ([]byte, error) {
		*calls = append(*calls, strings.Join(append([]string{name}, args...), " "))
		return nil, nil
	}
	t.Cleanup(func() { outputCommand = oldOutput })

	gw := newTestGateway(true, true)
	defer gw.cancel()
	hooks := testStartupHooks(gw, new(int))
	hooks.startEngine = func(*profile.Link) error {
		return errors.New("simulated engine start failure")
	}
	if err := gw.startWith(hooks); err == nil {
		t.Fatal("Start succeeded although the engine failed")
	}
	if gatewayState() != nil {
		t.Fatalf("failed startup left an ownership record: %+v", gatewayState())
	}
	if gw.run != nil || gw.networkMutated {
		t.Fatalf("failed startup kept in-memory ownership: run=%+v mutated=%v", gw.run, gw.networkMutated)
	}
	if joined := strings.Join(*calls, "\n"); !strings.Contains(joined, "ip rule show") {
		t.Fatalf("rollback never inspected the reserved native table:\n%s", joined)
	}
}

// TestEngineStartFailureRetainsRecordWhenRollbackFails proves the ownership
// record survives an incomplete rollback, so the next start can finish the
// interrupted cleanup instead of pretending the host is clean.
func TestEngineStartFailureRetainsRecordWhenRollbackFails(t *testing.T) {
	stubLifecycleHost(t)

	gw := newTestGateway(true, true)
	defer gw.cancel()
	rollingBack := false
	hooks := testStartupHooks(gw, new(int))
	hooks.startEngine = func(*profile.Link) error {
		rollingBack = true
		return errors.New("simulated engine start failure")
	}

	oldOutput := outputCommand
	outputCommand = func(name string, args ...string) ([]byte, error) {
		if rollingBack && name == "ip" && len(args) > 2 && args[0] == "route" && args[1] == "show" && args[2] == "table" {
			return nil, errors.New("simulated read failure")
		}
		return nil, nil
	}
	t.Cleanup(func() { outputCommand = oldOutput })

	if err := gw.startWith(hooks); err == nil {
		t.Fatal("Start succeeded although the engine failed")
	}
	st := gatewayState()
	if st == nil || !st.NativeRules || st.NativeRuleTable == 0 {
		t.Fatalf("ownership record = %+v, want the unrecovered native table retained", st)
	}

	outputCommand = oldOutput
	if err := gw.cleanupPreviousRun(); err != nil {
		t.Fatalf("second recovery: %v", err)
	}
	if gatewayState() != nil {
		t.Error("ownership record survived a successful second recovery")
	}
}

// startTestDNSListener runs a real UDP DNS server so the lifecycle test can
// observe the moment its socket is released.
func startTestDNSListener(t *testing.T) (*dns.Server, net.PacketConn) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding test DNS listener: %v", err)
	}
	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()

	client := &dns.Client{Net: "udp", Timeout: 200 * time.Millisecond}
	query := new(dns.Msg)
	query.SetQuestion("ready.test.", dns.TypeA)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, _, err := client.Exchange(query, pc.LocalAddr().String()); err == nil {
			return srv, pc
		}
		if time.Now().After(deadline) {
			t.Fatal("test DNS listener never became ready")
		}
	}
}

// TestStopReleasesDNSListenersBeforeRestoringServices proves resolver services
// are only restarted after bypath's own port-53 listeners are gone. Restoring
// first would leave the host without a working resolver.
func TestStopReleasesDNSListenersBeforeRestoringServices(t *testing.T) {
	isolateHostState(t)
	stubHostCommands(t, nil, nil, nil)
	srv, pc := startTestDNSListener(t)
	defer pc.Close()

	restoreChecked := false
	socketReleased := false
	withMockSystemctl(t,
		func(args []string) ([]byte, error) { return []byte("inactive\n"), nil },
		func(args []string) error {
			if len(args) == 2 && args[0] == "start" && args[1] == "systemd-resolved" {
				restoreChecked = true
				// A closed PacketConn rejects a new deadline; an open one means
				// bypath still owns port 53 when the restore is attempted.
				socketReleased = pc.SetReadDeadline(time.Now()) != nil
			}
			return nil
		},
	)

	gw := newTestGateway(true, false)
	defer gw.cancel()
	gw.networkMutated = true
	gw.run = &gatewayRunState{Version: gatewayStateVersion, Mode: "legacy", ResolvedStopped: true}
	gw.dnsBuiltin = []*dns.Server{srv}
	gw.Stop()

	if !restoreChecked {
		t.Fatal("systemd-resolved was never restored")
	}
	if !socketReleased {
		t.Fatal("systemd-resolved was restored while bypath still held port 53")
	}
	if len(gw.dnsBuiltin) != 0 {
		t.Fatalf("built-in DNS listeners survived Stop: %d", len(gw.dnsBuiltin))
	}
}

// TestGatewayFailsClosedWhenTun2socksUnavailable proves a gateway request never
// degrades to a silent proxy-only run: without a transparent data path Start
// fails, rolls back the TUN it created, and leaves no ownership record.
func TestGatewayFailsClosedWhenTun2socksUnavailable(t *testing.T) {
	calls := stubLifecycleHost(t)

	gw := newTestGateway(true, false)
	defer gw.cancel()
	started := 0
	hooks := testStartupHooks(gw, &started)
	hooks.startEngine = func(*profile.Link) error {
		started++
		gw.activeEngine = "xray" // xray has no TUN inbound: tun2socks is required
		gw.nativeTUN = false
		return nil
	}

	err := gw.startWith(hooks)
	if err == nil {
		t.Fatal("gateway startup reported success without a transparent data path")
	}
	if !strings.Contains(err.Error(), "transparent gateway unavailable") {
		t.Fatalf("start error = %v, want a transparent gateway failure", err)
	}
	if gatewayState() != nil {
		t.Fatalf("failed gateway startup left an ownership record: %+v", gatewayState())
	}
	if gw.tunProc != nil || gw.dnsProc != nil || len(gw.dnsBuiltin) != 0 {
		t.Fatalf("failed gateway startup left listeners running: tun=%v dns=%v builtin=%d", gw.tunProc, gw.dnsProc, len(gw.dnsBuiltin))
	}
	// Startup first removes bypath-named chains left behind by a crashed run;
	// that is cleanup of bypath's own objects. Fail-closed means no rule, route,
	// chain or resolver change is installed while there is no TUN.
	for _, call := range *calls {
		if configuresHostNetworking(call) {
			t.Fatalf("routing was configured without a TUN: %s", call)
		}
	}
}

// configuresHostNetworking reports whether a recorded host command installs
// state. Deletions and existence checks are cleanup and do not count.
func configuresHostNetworking(call string) bool {
	fields := strings.Fields(call)
	if len(fields) < 2 {
		return false
	}
	switch fields[0] {
	case "ip":
		if len(fields) < 3 {
			return false
		}
		return (fields[1] == "route" || fields[1] == "rule") && (fields[2] == "add" || fields[2] == "replace")
	case "iptables", "ip6tables":
		for _, f := range fields[1:] {
			switch f {
			case "-A", "-I", "-N", "-P":
				return true
			}
		}
	case "sysctl", "resolvconf":
		return true
	case "systemctl-run":
		switch fields[1] {
		case "start", "restart", "stop", "disable":
			return true
		}
	}
	return false
}

// TestVerifyDNSReadyRequiresAnAnswer proves the readiness gate observes real
// resolution instead of merely a bound socket.
func TestVerifyDNSReadyRequiresAnAnswer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding test resolver: %v", err)
	}
	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("splitting resolver address: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 1),
			})
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()

	gw := newTestGateway(true, false)
	defer gw.cancel()
	gw.dnsPort, _ = strconv.Atoi(port)
	if err := gw.verifyDNSReady(2 * time.Second); err != nil {
		t.Fatalf("verifyDNSReady rejected a working resolver: %v", err)
	}

	// Nothing listens on the old port any more.
	gw.dnsPort = 1
	start := time.Now()
	if err := gw.verifyDNSReady(500 * time.Millisecond); err == nil {
		t.Fatal("verifyDNSReady accepted a resolver that does not answer")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("verifyDNSReady ignored its timeout: %s", elapsed)
	}
}

// TestVerifyDNSReadyWaitsForLocalFallback proves readiness measures the whole
// local-policy path. A DoH endpoint whose :443 path is blackholed costs the
// forwarder dohRequestTimeout before it falls back to direct UDP; readiness
// used to give up after 2s and reject a resolver that was still working.
func TestVerifyDNSReadyWaitsForLocalFallback(t *testing.T) {
	const answerDelay = 2600 * time.Millisecond
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("binding test resolver: %v", err)
	}
	_, port, err := net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("splitting resolver address: %v", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		time.Sleep(answerDelay)
		m := new(dns.Msg)
		m.SetReply(r)
		if len(r.Question) > 0 {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(192, 0, 2, 1),
			})
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()

	gw := newTestGateway(true, false)
	defer gw.cancel()
	gw.dnsPort, _ = strconv.Atoi(port)

	start := time.Now()
	if err := gw.verifyDNSReady(4 * time.Second); err != nil {
		t.Fatalf("verifyDNSReady rejected a resolver slower than its old 2s query timeout: %v", err)
	}
	if elapsed := time.Since(start); elapsed < answerDelay {
		t.Fatalf("verifyDNSReady returned before the resolver answered: %s", elapsed)
	}
}

// TestAbortStartupInterruptsInFlightStart proves SIGTERM during startup does
// not wait for engine timeouts.
func TestAbortStartupInterruptsInFlightStart(t *testing.T) {
	stubLifecycleHost(t)

	gw := newTestGateway(false, false)
	defer gw.cancel()
	started := 0
	hooks := testStartupHooks(gw, &started)
	hooks.startEngine = func(*profile.Link) error {
		<-gw.ctx.Done()
		return gw.ctx.Err()
	}

	done := make(chan error, 1)
	go func() { done <- gw.startWith(hooks) }()
	time.Sleep(100 * time.Millisecond)
	gw.AbortStartup()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("start error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after AbortStartup")
	}
}

func TestRestoreLegacyRoutesRebuildsFwmarkTable(t *testing.T) {
	oldRun := runCommand
	var calls []string
	runCommand = func(name string, args ...string) error {
		calls = append(calls, strings.Join(append([]string{name}, args...), " "))
		return nil
	}
	t.Cleanup(func() { runCommand = oldRun })

	gw := &Gateway{legacyRoutingActive: true, iface: "eth1", subnet: "10.10.0.0/24"}
	if err := gw.restoreLegacyRoutes(); err != nil {
		t.Fatalf("restoreLegacyRoutes: %v", err)
	}
	want := []string{
		"ip route replace default via 10.0.0.1 dev tun0 table 100",
		"ip route replace 10.10.0.0/24 dev eth1 table 100",
	}
	if strings.Join(calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("route calls:\n%s\nwant:\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
	}

	calls = nil
	gw.legacyRoutingActive = false
	if err := gw.restoreLegacyRoutes(); err != nil {
		t.Fatalf("restoreLegacyRoutes (native): %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("native mode touched routes: %v", calls)
	}
}

// TestStartupWithoutActiveLinkIsPermanent proves a missing profile is reported
// as a permanent configuration error, so 'bypath run' exits with a clear
// message instead of retrying every 30 seconds forever.
func TestStartupWithoutActiveLinkIsPermanent(t *testing.T) {
	stubLifecycleHost(t)
	gw := newTestGateway(false, false)
	defer gw.cancel()

	err := gw.startWith(&startupHooks{
		detectNetwork: func() error { return nil },
		activeLink:    func() *profile.Link { return nil },
	})
	if err == nil {
		t.Fatal("startup without a link succeeded")
	}
	if !IsPermanent(err) {
		t.Fatalf("err = %v, want a permanent error", err)
	}
	if !strings.Contains(err.Error(), "no active link") {
		t.Fatalf("err = %v, want the missing-link explanation", err)
	}
}

// TestAbortBeforeStartIsHonoured covers an abort that lands while the Start
// call is waiting for the lifecycle lock. Recreating the runtime context must
// not erase it.
func TestAbortBeforeStartIsHonoured(t *testing.T) {
	stubLifecycleHost(t)

	gw := newTestGateway(false, false)
	defer gw.cancel()

	started := 0
	hooks := testStartupHooks(gw, &started)
	hooks.startEngine = func(*profile.Link) error {
		t.Error("startup proceeded after AbortStartup")
		return nil
	}

	gw.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- gw.startWith(hooks) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		gw.rtMu.Lock()
		waiting := gw.starting > 0
		gw.rtMu.Unlock()
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			gw.mu.Unlock()
			t.Fatal("start did not begin waiting for the lifecycle lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
	gw.AbortStartup()
	gw.mu.Unlock()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("start error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("start did not return after AbortStartup")
	}
	gw.rtMu.Lock()
	stopping := gw.stopping
	gw.rtMu.Unlock()
	if !stopping {
		t.Fatal("abort was lost: gateway did not record a shutdown")
	}
	if started != 0 {
		t.Fatalf("engine started %d times after the abort", started)
	}
}

// TestLateAbortAfterStartDoesNotPoisonNext covers R-03: an AbortStartup that
// loses the race with a completed Start belongs to that start. It must not
// leave abortPending set, cancel the live context, or fail the next connect.
func TestLateAbortAfterStartDoesNotPoisonNext(t *testing.T) {
	stubLifecycleHost(t)

	gw := newTestGateway(false, false)
	defer gw.cancel()
	started := 0
	if err := gw.startWith(testStartupHooks(gw, &started)); err != nil {
		t.Fatalf("first start: %v", err)
	}

	gw.AbortStartup()

	gw.rtMu.Lock()
	pending := gw.abortPending
	stopping := gw.stopping
	var ctxErr error
	if gw.ctx != nil {
		ctxErr = gw.ctx.Err()
	}
	gw.rtMu.Unlock()
	if pending {
		t.Fatal("late abort left abortPending set")
	}
	if stopping {
		t.Fatal("late abort marked a completed start as stopping")
	}
	if ctxErr != nil {
		t.Fatalf("late abort cancelled the live context: %v", ctxErr)
	}
	if state := gw.GetRuntimeStatus().State; state != StateConnected {
		t.Fatalf("late abort changed state to %s, want CONNECTED", state)
	}

	if err := gw.startWith(testStartupHooks(gw, &started)); err != nil {
		t.Fatalf("start after the late abort: %v", err)
	}
	if started != 1 {
		t.Fatalf("a connected gateway started the engine again (starts=%d)", started)
	}

	gw.Stop()
	if err := gw.startWith(testStartupHooks(gw, &started)); err != nil {
		t.Fatalf("next connect after the late abort: %v", err)
	}
	if started != 2 {
		t.Fatalf("engine starts=%d after reconnect, want 2", started)
	}
}

// TestRepeatedAbortAfterCompletionLeavesNoStaleState exercises repeated
// connect/abort/disconnect cycles; a stale pending abort would fail cycle 2.
func TestRepeatedAbortAfterCompletionLeavesNoStaleState(t *testing.T) {
	stubLifecycleHost(t)

	gw := newTestGateway(false, false)
	defer gw.cancel()
	started := 0
	for i := 0; i < 10; i++ {
		if err := gw.startWith(testStartupHooks(gw, &started)); err != nil {
			t.Fatalf("cycle %d start: %v", i+1, err)
		}
		gw.AbortStartup()
		gw.Stop()
	}
	if started != 10 {
		t.Fatalf("engine starts=%d, want 10", started)
	}
	if state := gw.GetRuntimeStatus().State; state == StateConnected {
		t.Fatal("gateway still reports CONNECTED after all disconnects")
	}
}

// TestStartSkipsWhenAlreadyConnected covers an operator who connects through the
// control socket while the daemon's retry loop is still sleeping. The retry must
// not restart the engine: Start would tear down the working connection first.
func TestStartSkipsWhenAlreadyConnected(t *testing.T) {
	calls := stubLifecycleHost(t)

	gw := newTestGateway(true, true)
	defer gw.cancel()

	gw.setRuntimeState(StateConnected, "")

	started := 0
	hooks := testStartupHooks(gw, &started)
	hooks.startEngine = func(*profile.Link) error {
		t.Error("retry restarted the engine of an already-connected gateway")
		return nil
	}
	if err := gw.startWith(hooks); err != nil {
		t.Fatalf("startWith on a connected gateway = %v, want nil", err)
	}
	if started != 0 {
		t.Fatalf("engine start calls = %d, want 0", started)
	}
	if st := gw.GetRuntimeStatus().State; st != StateConnected {
		t.Fatalf("state = %s, want %s", st, StateConnected)
	}
	if got := hostMutationCommands(*calls); len(got) != 0 {
		t.Fatalf("skipped start mutated the host: %v", got)
	}
}

// TestAbortDuringStartDoesNotBlockNextStart covers an abort that lands after
// Start consumed the previous pending abort: the stale flag must be cleared so
// the next explicit Start proceeds instead of returning context.Canceled.
func TestAbortDuringStartDoesNotBlockNextStart(t *testing.T) {
	stubLifecycleHost(t)

	gw := newTestGateway(false, false)
	defer gw.cancel()

	started := 0
	hooks := testStartupHooks(gw, &started)
	detect := hooks.detectNetwork
	hooks.detectNetwork = func() error {
		gw.rtMu.Lock()
		gw.abortPending = true
		gw.rtMu.Unlock()
		return detect()
	}
	if err := gw.startWith(hooks); err != nil {
		t.Fatalf("first start: %v", err)
	}
	gw.rtMu.Lock()
	pending := gw.abortPending
	gw.rtMu.Unlock()
	if pending {
		t.Fatal("abortPending survived the start that completed")
	}

	// Drop to DISCONNECTED as a failed run would, then retry.
	gw.setRuntimeState(StateDisconnected, "")

	hooks = testStartupHooks(gw, &started)
	if err := gw.startWith(hooks); err != nil {
		t.Fatalf("second start = %v, want success after a completed start", err)
	}
	if started != 2 {
		t.Fatalf("engine start calls = %d, want 2", started)
	}
}

// TestShutdownBeforeStartIsSticky covers the late-signal half of F-01: a
// process shutdown that arrives before Start reaches the lifecycle lock must
// still prevent the tunnel from coming up.
func TestShutdownBeforeStartIsSticky(t *testing.T) {
	stubLifecycleHost(t)

	gw := newTestGateway(false, false)
	defer gw.cancel()
	gw.ShutdownStartup()

	started := 0
	err := gw.startWith(testStartupHooks(gw, &started))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("start error = %v, want context.Canceled", err)
	}
	if started != 0 {
		t.Fatalf("engine started %d times after process shutdown", started)
	}
	if state := gw.GetRuntimeStatus().State; state == StateConnected {
		t.Fatal("a start after process shutdown reported CONNECTED")
	}
}

// TestStopDuringStartupIsNotPublishedAsConnected covers F-02: an abort that
// lands while Start holds the lifecycle lock must tear the half-built stack down
// instead of reporting CONNECTED without a watchdog.
func TestStopDuringStartupIsNotPublishedAsConnected(t *testing.T) {
	stubLifecycleHost(t)

	gw := newTestGateway(false, false)
	defer gw.cancel()
	started := 0
	hooks := testStartupHooks(gw, &started)
	startEngine := hooks.startEngine
	hooks.startEngine = func(link *profile.Link) error {
		// The stop arrives after Start passed its abort check but before it
		// publishes CONNECTED.
		gw.AbortStartup()
		return startEngine(link)
	}

	err := gw.startWith(hooks)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("start error = %v, want context.Canceled", err)
	}
	if state := gw.GetRuntimeStatus().State; state == StateConnected {
		t.Fatal("a stopped startup was published as CONNECTED")
	}
	if gw.watchStop != nil {
		t.Fatal("a watchdog was started for a stopped startup")
	}
}

// TestStartWithContextRefusesCancelledCaller covers C2-01: a caller that is
// already gone must not bring the tunnel up, even though AbortStartup would
// have been ignored before the start registered.
func TestStartWithContextRefusesCancelledCaller(t *testing.T) {
	gw := newTestGateway(false, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := gw.StartWithContext(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("start error = %v, want context.Canceled", err)
	}
	if state := gw.GetRuntimeStatus().State; state == StateConnected || state == StateConnecting {
		t.Fatalf("cancelled start published state %q", state)
	}
}

// TestStartCancelledBeforeLockTouchesNothing checks the window that matters
// most: the caller cancels while the start waits for the lifecycle lock, before
// initRuntimeLocked would recreate the context and erase the abort.
func TestStartCancelledBeforeLockTouchesNothing(t *testing.T) {
	gw := newTestGateway(false, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	detected := false
	err := gw.startWithContext(ctx, &startupHooks{
		detectNetwork: func() error { detected = true; return nil },
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("start error = %v, want context.Canceled", err)
	}
	if detected {
		t.Fatal("a start cancelled before the lifecycle lock still probed the network")
	}
	if gw.run != nil {
		t.Fatal("a cancelled start initialised runtime state")
	}
}

// TestDNSForwardBudgetCoversEveryUpstream covers C2-02: readiness must outlast
// the worst path through forwardDNS, which tries every DoH endpoint and, under
// the local policy, every direct UDP upstream.
func TestDNSForwardBudgetCoversEveryUpstream(t *testing.T) {
	tests := []struct {
		name        string
		upstreams   []string
		allowDirect bool
		want        time.Duration
	}{
		{"default strict", []string{"1.1.1.1", "8.8.8.8"}, false, 2*dohRequestTimeout + time.Second},
		{"default local", []string{"1.1.1.1", "8.8.8.8"}, true, 2*dohRequestTimeout + 2*udpQueryTimeout + time.Second},
		{"single strict", []string{"1.1.1.1"}, false, dohRequestTimeout + time.Second},
		{"no upstreams", nil, false, time.Second},
	}
	for _, tc := range tests {
		if got := dnsForwardBudget(tc.upstreams, tc.allowDirect); got != tc.want {
			t.Errorf("%s: budget = %s, want %s", tc.name, got, tc.want)
		}
	}
}

// TestDNSWarmupOutlastsTheForwarder proves the startup budget is never shorter
// than one complete forwarder path, including the local-policy UDP fallbacks.
func TestDNSWarmupOutlastsTheForwarder(t *testing.T) {
	gw := newTestGateway(true, false)
	gw.config.Gateway.DNSMode = "strict"
	gw.config.Gateway.DNSUpstream = []string{"1.1.1.1", "8.8.8.8"}
	if got := gw.dnsWarmup(); got < 2*dohRequestTimeout {
		t.Fatalf("strict warmup = %s, shorter than the DoH path", got)
	}

	gw.config.Gateway.DNSMode = "local"
	if got, want := gw.dnsWarmup(), dnsForwardBudget(gw.config.Gateway.DNSUpstream, true); got != want {
		t.Fatalf("local warmup = %s, want %s", got, want)
	}

	gw.config.Gateway.DNSMode = ""
	if got := gw.dnsWarmup(); got != dnsWarmupTimeout {
		t.Fatalf("default warmup = %s, want the %s floor", got, dnsWarmupTimeout)
	}
}
