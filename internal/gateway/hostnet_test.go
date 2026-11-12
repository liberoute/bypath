package gateway

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/tunnel"
)

// isolateHostState points the paths package at a scratch directory so these
// tests never read or write state belonging to a real bypath installation. The
// forwarding probe is pointed at a scratch file too, so cleanup behavior never
// depends on the machine that runs the test.
func isolateHostState(t *testing.T) {
	t.Helper()
	t.Setenv("BYPATH_RUNTIME_DIR", t.TempDir())
	paths.Reset()
	t.Cleanup(paths.Reset)
	t.Chdir(t.TempDir())
	setHostForwarding(t, "0")
}

// setHostForwarding writes the scratch ip_forward value read by the cleanup
// path. "1" models a host where Docker or libvirt already enabled forwarding.
func setHostForwarding(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ip_forward")
	if err := os.WriteFile(path, []byte(value+"\n"), 0644); err != nil {
		t.Fatalf("writing scratch ip_forward: %v", err)
	}
	old := ipForwardPath
	ipForwardPath = path
	t.Cleanup(func() { ipForwardPath = old })
	return path
}

// stubHostCommands replaces the injectable command runners for one test. Every
// command executed through the package is captured in calls.
func stubHostCommands(t *testing.T, runFn func(string, ...string) error, statusFn func(string, ...string) error, outputFn func(string, ...string) ([]byte, error)) *[]string {
	t.Helper()
	var calls []string
	oldRun, oldStatus, oldOutput := runCommand, statusCommand, outputCommand
	if runFn == nil {
		runFn = func(name string, args ...string) error {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			return nil
		}
	}
	if statusFn == nil {
		statusFn = func(string, ...string) error { return nil }
	}
	if outputFn == nil {
		outputFn = func(string, ...string) ([]byte, error) { return nil, nil }
	}
	runCommand = runFn
	statusCommand = statusFn
	outputCommand = outputFn
	t.Cleanup(func() {
		runCommand, statusCommand, outputCommand = oldRun, oldStatus, oldOutput
	})
	return &calls
}

func TestGatewayStateMarkerRoundTrip(t *testing.T) {
	isolateHostState(t)

	if got := gatewayState(); got != nil {
		t.Fatalf("fresh state = %+v, want nil", got)
	}

	st, err := markGatewayState("legacy")
	if err != nil {
		t.Fatalf("markGatewayState: %v", err)
	}
	st.Routes = [][]string{{"route", "add", "default", "via", "10.0.0.1", "dev", "tun0", "table", "100"}}
	st.RuleAdded = true
	st.V6Isolated = true
	if err := saveGatewayState(st); err != nil {
		t.Fatalf("saveGatewayState: %v", err)
	}

	got := gatewayState()
	if got == nil {
		t.Fatal("gatewayState() = nil after save")
	}
	if got.Mode != "legacy" || !got.RuleAdded || !got.V6Isolated {
		t.Errorf("state flags lost: %+v", got)
	}
	if !reflect.DeepEqual(got.Routes, st.Routes) {
		t.Errorf("routes = %v, want %v", got.Routes, st.Routes)
	}

	clearGatewayState()
	if got := gatewayState(); got != nil {
		t.Errorf("gatewayState() = %+v after clear", got)
	}
}

func TestGatewayStateReadsLegacyPlainMarker(t *testing.T) {
	isolateHostState(t)

	if err := os.MkdirAll(paths.Get().TmpDir, 0700); err != nil {
		t.Fatalf("creating tmp dir: %v", err)
	}
	if err := os.WriteFile(gatewayStateFile(), []byte("legacy\n"), 0600); err != nil {
		t.Fatalf("writing marker: %v", err)
	}
	got := gatewayState()
	if got == nil || got.Mode != "legacy" || !got.LegacyFormat {
		t.Fatalf("legacy marker = %+v, want mode legacy with LegacyFormat", got)
	}
}

func TestGatewayStateRejectsUnknownMode(t *testing.T) {
	isolateHostState(t)

	if err := os.MkdirAll(paths.Get().TmpDir, 0700); err != nil {
		t.Fatalf("creating tmp dir: %v", err)
	}
	if err := os.WriteFile(gatewayStateFile(), []byte("gateway\n"), 0600); err != nil {
		t.Fatalf("writing marker: %v", err)
	}
	if got := gatewayState(); got != nil {
		t.Fatalf("gatewayState() = %+v for an unknown mode, want nil", got)
	}
}

func TestNeedsNetworkCleanup(t *testing.T) {
	tests := []struct {
		name           string
		marker         string
		networkMutated bool
		want           bool
	}{
		{name: "fresh proxy-only instance", want: false},
		{name: "this instance mutated networking", networkMutated: true, want: true},
		{name: "crashed native run left a marker", marker: "native", want: true},
		{name: "crashed legacy run left a marker", marker: "legacy", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateHostState(t)
			if tt.marker != "" {
				if _, err := markGatewayState(tt.marker); err != nil {
					t.Fatalf("markGatewayState: %v", err)
				}
			}
			gw := &Gateway{networkMutated: tt.networkMutated}
			if got := gw.needsNetworkCleanup(); got != tt.want {
				t.Errorf("needsNetworkCleanup() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIPv6IsolationRules(t *testing.T) {
	rules := ipv6IsolationRules("eth0")
	want := [][]string{
		{"ip6tables", "-t", "filter", "-A", chainV6Drop, "-i", "eth0", "-j", "DROP"},
	}
	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("ipv6IsolationRules() = %v, want %v", rules, want)
	}

	rule := strings.Join(rules[0], " ")
	if strings.Contains(rule, "INPUT") || strings.Contains(rule, "OUTPUT") {
		t.Errorf("IPv6 isolation must only affect forwarded traffic: %s", rule)
	}
	// The jump into the owned chain is added separately; the rule list itself
	// must never insert into a built-in chain.
	if strings.Contains(rule, "FORWARD") {
		t.Errorf("IPv6 rule must target %s, not FORWARD directly: %s", chainV6Drop, rule)
	}
}

func TestGatewayStateFileLivesUnderTmpDir(t *testing.T) {
	isolateHostState(t)

	got := gatewayStateFile()
	want := filepath.Join(paths.Get().TmpDir, "gateway-network-state")
	if got != want {
		t.Fatalf("gatewayStateFile() = %q, want %q", got, want)
	}
}

// verifyJump6First is the only thing standing between "we generated an insert
// command" and "IPv6 is actually contained". An earlier ACCEPT must fail closed.
func TestVerifyJump6FirstRejectsEarlierAccept(t *testing.T) {
	cases := map[string]struct {
		rules string
		want  string // substring of the expected error, empty for success
	}{
		"jump first": {
			rules: "-P FORWARD ACCEPT\n-A FORWARD -j BYPATH_V6\n-A FORWARD -j ACCEPT\n",
		},
		"accept precedes jump": {
			rules: "-P FORWARD ACCEPT\n-A FORWARD -j ACCEPT\n-A FORWARD -j BYPATH_V6\n",
			want:  "precedes",
		},
		"jump missing": {
			rules: "-P FORWARD ACCEPT\n",
			want:  "missing",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			stubHostCommands(t, nil, nil, func(string, ...string) ([]byte, error) {
				return []byte(tc.rules), nil
			})
			err := verifyJump6First("filter", "FORWARD", chainV6Drop)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestEnsureJump6TopInsertsFirst(t *testing.T) {
	var runCalls []string
	inserted := false
	jumpDeleted := false
	// Before the reorder the jump is the only FORWARD rule; after the insert it
	// appears twice until the old copy is removed by number.
	stubHostCommands(t,
		func(name string, args ...string) error {
			runCalls = append(runCalls, strings.Join(append([]string{name}, args...), " "))
			for _, a := range args {
				if a == "-I" {
					inserted = true
				}
				if a == "-D" {
					jumpDeleted = true
				}
			}
			return nil
		},
		nil,
		func(name string, args ...string) ([]byte, error) {
			if name != "ip6tables" {
				return nil, nil
			}
			_, rest := splitFirewallTable(args)
			if len(rest) == 0 || rest[0] != "-S" {
				return nil, nil
			}
			switch {
			case jumpDeleted:
				return []byte("-P FORWARD ACCEPT\n"), nil
			case inserted:
				return []byte("-A FORWARD -j " + chainV6Drop + "\n-A FORWARD -j " + chainV6Drop + "\n"), nil
			default:
				return []byte("-A FORWARD -j " + chainV6Drop + "\n"), nil
			}
		},
	)

	if err := ensureJump6Top("filter", "FORWARD", chainV6Drop); err != nil {
		t.Fatalf("ensureJump6Top: %v", err)
	}
	if len(runCalls) != 2 {
		t.Fatalf("run calls = %v, want one insert and one reorder deletion", runCalls)
	}
	if !strings.Contains(runCalls[0], "-I FORWARD 1 -j "+chainV6Drop) {
		t.Errorf("first call = %q, want containment inserted before any deletion", runCalls[0])
	}
	if !strings.Contains(runCalls[1], "-D FORWARD 2") {
		t.Errorf("second call = %q, want the displaced duplicate deleted by number", runCalls[1])
	}
}

// A firewall inspection failure is not proof of absence. Cleanup must report
// the error so a bypath-owned redirect is never assumed removed.
func TestRemoveJumpReportsInspectionFailure(t *testing.T) {
	isolateHostState(t)
	calls := stubHostCommands(t, nil, nil, func(name string, args ...string) ([]byte, error) {
		if name == "iptables" {
			return []byte("iptables v1.8.9: Permission denied"), errors.New("exit status 4")
		}
		return nil, nil
	})

	if err := removeJump("nat", "PREROUTING", chainDNS); err == nil {
		t.Fatal("removeJump treated an inspection failure as an absent rule")
	}
	if joined := strings.Join(*calls, "\n"); strings.Contains(joined, "-D PREROUTING") {
		t.Fatalf("removeJump deleted a rule it could not inspect:\n%s", joined)
	}
}

func TestSetupIPv6IsolationFailsClosedAndRollsBack(t *testing.T) {
	isolateHostState(t)
	enableContainmentHost(t)
	calls := stubHostCommands(t, nil,
		func(string, ...string) error { return errors.New("absent") },
		func(string, ...string) ([]byte, error) {
			return []byte("-P FORWARD ACCEPT\n-A FORWARD -j ACCEPT\n-A FORWARD -j BYPATH_V6\n"), nil
		},
	)

	gw := &Gateway{iface: "eth0"}
	st := &gatewayRunState{Version: gatewayStateVersion, Mode: "legacy"}
	if err := gw.setupIPv6Isolation(st); err == nil {
		t.Fatal("setupIPv6Isolation succeeded despite an earlier ACCEPT rule")
	}
	if !st.V6Isolated {
		t.Fatal("ownership record must mark V6 isolation attempted before verification")
	}

	// The verification failure happens after the jump was inserted, so at
	// rollback time the rule is present and its inverse must be attempted.
	outputCommand = func(string, ...string) ([]byte, error) { return nil, nil }
	if err := gw.undoNetworkState(st); err != nil {
		t.Fatalf("undoNetworkState: %v", err)
	}
	joined := strings.Join(*calls, "\n")
	if !strings.Contains(joined, "ip6tables -t filter -D FORWARD -j "+chainV6Drop) {
		t.Errorf("rollback did not remove the IPv6 jump:\n%s", joined)
	}
	if strings.Contains(joined, "flush") {
		t.Errorf("rollback flushed a table:\n%s", joined)
	}
}

func TestSetupIPv6IsolationAbortsOnCommandFailure(t *testing.T) {
	isolateHostState(t)
	stubHostCommands(t,
		func(_ string, args ...string) error {
			for _, a := range args {
				if a == "-A" {
					return errors.New("ip6tables failed")
				}
			}
			return nil
		},
		func(string, ...string) error { return errors.New("absent") },
		nil,
	)

	gw := &Gateway{iface: "eth0"}
	st := &gatewayRunState{Version: gatewayStateVersion, Mode: "legacy"}
	if err := gw.setupIPv6Isolation(st); err == nil {
		t.Fatal("setupIPv6Isolation ignored a failed rule command")
	}
	if st.V6Isolated {
		t.Fatal("V6 ownership recorded even though no rule was applied")
	}
}

// Rollback must never delete an interface it cannot prove bypath created.
func TestUndoNetworkStateLeavesUnownedTun(t *testing.T) {
	isolateHostState(t)

	t.Run("not recorded", func(t *testing.T) {
		calls := stubHostCommands(t, nil, nil, nil)
		gw := &Gateway{}
		if err := gw.undoNetworkState(&gatewayRunState{Version: gatewayStateVersion, Mode: "legacy"}); err != nil {
			t.Fatalf("undoNetworkState: %v", err)
		}
		if strings.Contains(strings.Join(*calls, "\n"), "link del tun0") {
			t.Errorf("unowned tun0 was deleted:\n%s", strings.Join(*calls, "\n"))
		}
	})

	t.Run("recorded but wrong address", func(t *testing.T) {
		calls := stubHostCommands(t, nil, nil, func(string, ...string) ([]byte, error) {
			return []byte("tun0 UP 10.9.9.1/24\n"), nil
		})
		st := &gatewayRunState{Version: gatewayStateVersion, Mode: "legacy", TunCreated: true}
		gw := &Gateway{}
		if err := gw.undoNetworkState(st); err == nil {
			t.Fatal("undoNetworkState claimed success without deleting the foreign tun0")
		}
		if strings.Contains(strings.Join(*calls, "\n"), "link del tun0") {
			t.Errorf("tun0 with a foreign address was deleted:\n%s", strings.Join(*calls, "\n"))
		}
		if !st.TunCreated {
			t.Error("ownership flag was cleared even though the inverse did not complete")
		}
	})

	t.Run("recorded and matches", func(t *testing.T) {
		calls := stubHostCommands(t, nil, nil, func(string, ...string) ([]byte, error) {
			return []byte("tun0 UP 10.0.0.1/24\n"), nil
		})
		gw := &Gateway{}
		if err := gw.undoNetworkState(&gatewayRunState{Version: gatewayStateVersion, Mode: "legacy", TunCreated: true}); err != nil {
			t.Fatalf("undoNetworkState: %v", err)
		}
		if !strings.Contains(strings.Join(*calls, "\n"), "ip link del tun0") {
			t.Errorf("owned tun0 was not deleted:\n%s", strings.Join(*calls, "\n"))
		}
	})
}

func TestUndoNetworkStateReversesOnlyRecordedRoutes(t *testing.T) {
	isolateHostState(t)
	calls := stubHostCommands(t, nil, nil, func(name string, args ...string) ([]byte, error) {
		if name == "ip" && len(args) > 0 && args[0] == "rule" {
			return []byte("100: from all fwmark 0x1 lookup 100\n"), nil
		}
		if name == "ip" && len(args) > 0 && args[0] == "route" {
			return []byte("default via 10.0.0.1 dev tun0\n"), nil
		}
		return nil, nil
	})

	gw := &Gateway{}
	st := &gatewayRunState{
		Version:   gatewayStateVersion,
		Mode:      "legacy",
		Routes:    [][]string{{"route", "add", "default", "via", "10.0.0.1", "dev", "tun0", "table", "100"}},
		RuleAdded: true,
	}
	if err := gw.undoNetworkState(st); err != nil {
		t.Fatalf("undoNetworkState: %v", err)
	}

	joined := strings.Join(*calls, "\n")
	if strings.Contains(joined, "flush") {
		t.Fatalf("cleanup flushed a route table:\n%s", joined)
	}
	if !strings.Contains(joined, "ip route del default via 10.0.0.1 dev tun0 table 100") {
		t.Errorf("recorded route was not reversed:\n%s", joined)
	}
	if !strings.Contains(joined, "ip rule del fwmark 0x1 lookup 100 prio 100") {
		t.Errorf("owned fwmark rule was not reversed:\n%s", joined)
	}
}

// A failed route add must not stay in the ownership record, otherwise rollback
// would delete a pre-existing route bypath never created.
func TestApplyRouteFailureDropsOwnership(t *testing.T) {
	isolateHostState(t)
	stubHostCommands(t, func(string, ...string) error { return errors.New("exists") }, nil, nil)

	gw := &Gateway{}
	st := &gatewayRunState{Version: gatewayStateVersion, Mode: "legacy"}
	if err := gw.applyRoute(st, "route", "add", "default", "via", "10.0.0.1", "dev", "tun0", "table", "100"); err == nil {
		t.Fatal("applyRoute succeeded despite the command failing")
	}
	if len(st.Routes) != 0 {
		t.Fatalf("record kept a failed route: %v", st.Routes)
	}
	if saved := gatewayState(); saved != nil && len(saved.Routes) != 0 {
		t.Fatalf("persisted state kept a failed route: %v", saved.Routes)
	}
}

func TestApplyFwmarkRuleDoesNotClaimExistingRule(t *testing.T) {
	isolateHostState(t)
	calls := stubHostCommands(t, nil, nil, func(string, ...string) ([]byte, error) {
		return []byte("100: from all fwmark 0x1 lookup 100\n"), nil
	})

	gw := &Gateway{}
	st := &gatewayRunState{Version: gatewayStateVersion, Mode: "legacy"}
	if err := gw.applyFwmarkRule(st); err != nil {
		t.Fatalf("applyFwmarkRule: %v", err)
	}
	if st.RuleAdded {
		t.Fatal("pre-existing fwmark rule was claimed as owned")
	}
	if len(*calls) != 0 {
		t.Fatalf("unexpected commands: %v", *calls)
	}
}

func TestRemoveEngineNativeRulesOnlyOwnTable(t *testing.T) {
	isolateHostState(t)
	calls := stubHostCommands(t, nil, nil, func(string, ...string) ([]byte, error) {
		return []byte("9000: from all lookup 2022\n9001: from all lookup 100\n9003: from all fwmark 0x1 lookup 2022\n"), nil
	})

	removeEngineNativeRules(0)
	joined := strings.Join(*calls, "\n")
	if strings.Contains(joined, "prio 9001") {
		t.Errorf("deleted a rule that targets table 100:\n%s", joined)
	}
	if !strings.Contains(joined, "ip rule del prio 9000 lookup 2022") || !strings.Contains(joined, "ip rule del prio 9003 lookup 2022") {
		t.Errorf("did not delete bypath's table-2022 rules by priority and table:\n%s", joined)
	}
	if strings.Contains(joined, "flush") {
		t.Errorf("flushed table 2022:\n%s", joined)
	}
}

// setupRouting must not flush table 100 (shared) or delete routes it did not
// record, even in legacy mode.
func TestLegacySetupRoutingDoesNotFlushSharedTable(t *testing.T) {
	isolateHostState(t)

	resolvDir := t.TempDir()
	oldResolv, oldBackup, oldLink := resolvConfPath, resolvBackup, resolvLinkBackup
	resolvConfPath = filepath.Join(resolvDir, "resolv.conf")
	resolvBackup = filepath.Join(resolvDir, "resolv.conf.bypath-backup")
	resolvLinkBackup = filepath.Join(resolvDir, "resolv.conf.bypath-link")
	t.Cleanup(func() { resolvConfPath, resolvBackup, resolvLinkBackup = oldResolv, oldBackup, oldLink })
	if err := os.WriteFile(resolvConfPath, []byte("nameserver 192.0.2.1\n"), 0644); err != nil {
		t.Fatalf("seeding resolv.conf: %v", err)
	}
	// setupRouting makes the file immutable. Clearing the attribute is a no-op
	// unless the test runs as root on a filesystem that honours chattr, where
	// TempDir cleanup would otherwise fail.
	t.Cleanup(func() { exec.Command("chattr", "-i", resolvConfPath).Run() })

	calls := stubHostCommands(t, nil,
		func(string, ...string) error { return errors.New("absent") },
		func(name string, args ...string) ([]byte, error) {
			if name == "ip6tables" {
				return []byte("-P FORWARD ACCEPT\n-A FORWARD -j " + chainV6Drop + "\n"), nil
			}
			if name == "iptables" && len(args) > 2 && args[2] == "-S" {
				return []byte("-A FORWARD -j " + chainForward + "\n"), nil
			}
			if name == "ip" && len(args) > 0 && args[0] == "rule" {
				return []byte("100: from all fwmark 0x1 lookup 100\n"), nil
			}
			if name == "ip" && len(args) > 1 && args[0] == "route" && args[1] == "show" {
				return []byte("default via 10.0.0.1 dev tun0\n10.1.0.0/24 dev eth0\n"), nil
			}
			return nil, nil
		},
	)

	gw := &Gateway{
		config:     &config.Config{Gateway: config.GatewayConfig{Enabled: true}},
		iface:      "eth0",
		subnet:     "10.1.0.0/24",
		dnsPort:    53,
		nativeTUN:  false,
		profileMgr: nil,
	}
	if err := gw.setupRouting(); err != nil {
		t.Fatalf("setupRouting: %v", err)
	}

	joined := strings.Join(*calls, "\n")
	if strings.Contains(joined, "flush") {
		t.Fatalf("legacy setup flushed a table:\n%s", joined)
	}
	if !strings.Contains(joined, "ip route add default via 10.0.0.1 dev tun0 table 100") {
		t.Errorf("default route was not added:\n%s", joined)
	}
	got := gatewayState()
	if got == nil || got.Mode != "legacy" || len(got.Routes) != 3 {
		t.Fatalf("ownership record = %+v, want legacy with two tunnel routes and the fail-closed blackhole", got)
	}
	// The blackhole keeps marked packets from falling back to the main table
	// when tun0 disappears, so it must be owned like any other route.
	blackhole := false
	for _, rec := range got.Routes {
		if strings.Join(rec, " ") == "route add blackhole default metric 4096 table 100" {
			blackhole = true
		}
	}
	if !blackhole {
		t.Fatalf("ownership record lacks the fail-closed blackhole: %+v", got)
	}

	// Rollback must reverse exactly those routes and never flush.
	*calls = nil
	gw.networkMutated = true
	gw.cleanupRouting()
	joined = strings.Join(*calls, "\n")
	if strings.Contains(joined, "flush") {
		t.Fatalf("rollback flushed a table:\n%s", joined)
	}
	if !strings.Contains(joined, "ip route del default via 10.0.0.1 dev tun0 table 100") {
		t.Errorf("default route was not reversed:\n%s", joined)
	}
	if gatewayState() != nil {
		t.Error("ownership record was not cleared after cleanup")
	}
}

// TestForwardChainIsValidAndFailsClosed guards the generated FORWARD rules.
// iptables rejects a rule that matches -o twice ("multiple --out-interface
// options not allowed"), which made the whole fail-closed setup abort at
// startup during lab acceptance.
func TestForwardChainIsValidAndFailsClosed(t *testing.T) {
	for _, native := range []bool{false, true} {
		native := native
		t.Run(fmt.Sprintf("native=%v", native), func(t *testing.T) {
			isolateHostState(t)
			resolvDir := t.TempDir()
			oldResolv, oldBackup, oldLink := resolvConfPath, resolvBackup, resolvLinkBackup
			resolvConfPath = filepath.Join(resolvDir, "resolv.conf")
			resolvBackup = filepath.Join(resolvDir, "resolv.conf.bypath-backup")
			resolvLinkBackup = filepath.Join(resolvDir, "resolv.conf.bypath-link")
			t.Cleanup(func() { resolvConfPath, resolvBackup, resolvLinkBackup = oldResolv, oldBackup, oldLink })
			if err := os.WriteFile(resolvConfPath, []byte("nameserver 192.0.2.1\n"), 0644); err != nil {
				t.Fatalf("seeding resolv.conf: %v", err)
			}
			t.Cleanup(func() { exec.Command("chattr", "-i", resolvConfPath).Run() })

			calls := stubHostCommands(t, nil,
				func(string, ...string) error { return errors.New("absent") },
				func(name string, args ...string) ([]byte, error) {
					if name == "ip6tables" {
						return []byte("-A FORWARD -j " + chainV6Drop + "\n"), nil
					}
					if name == "iptables" && len(args) > 2 && args[2] == "-S" {
						return []byte("-A FORWARD -j " + chainForward + "\n"), nil
					}
					return nil, nil
				},
			)
			gw := &Gateway{
				config:    &config.Config{Gateway: config.GatewayConfig{Enabled: true, NativeTUN: native}},
				iface:     "eth1",
				subnet:    "10.10.0.0/24",
				dnsPort:   53,
				nativeTUN: native,
			}
			if err := gw.setupRouting(); err != nil {
				t.Fatalf("setupRouting: %v", err)
			}

			var fwd []string
			for _, c := range *calls {
				if strings.HasPrefix(c, "iptables -A "+chainForward+" ") {
					fwd = append(fwd, c)
				}
			}
			if len(fwd) == 0 {
				t.Fatal("no FORWARD rules were generated")
			}
			for _, rule := range fwd {
				if n := strings.Count(rule, " -o "); n > 1 {
					t.Errorf("rule matches -o %d times, iptables accepts one: %s", n, rule)
				}
			}
			if want := "iptables -A " + chainForward + " -i eth1 -j DROP"; fwd[len(fwd)-1] != want {
				t.Errorf("last FORWARD rule = %q, want %q", fwd[len(fwd)-1], want)
			}
		})
	}
}

// Proxy-only runs must leave host networking untouched, both when routing setup
// is skipped and when cleanup finds no ownership record. Lifecycle-level
// evidence is produced by TestProxyOnlyLifecycleLeavesHostUntouched; this test
// isolates the routing helpers.
func TestProxyOnlyRoutingIssuesNoHostCommands(t *testing.T) {
	isolateHostState(t)
	calls := stubHostCommands(t, nil, nil, nil)

	gw := &Gateway{config: &config.Config{}}
	if err := gw.setupRouting(); err != nil {
		t.Fatalf("setupRouting: %v", err)
	}
	gw.cleanupRouting()
	if len(*calls) != 0 {
		t.Fatalf("proxy-only run executed host commands: %v", *calls)
	}
	if gw.networkMutated {
		t.Error("proxy-only run marked host networking as mutated")
	}
	if gatewayState() != nil {
		t.Error("proxy-only run wrote an ownership record")
	}
}

// Native mode hands policy routing to sing-box, which owns rules in table 2022.
// Entering native routing must record that ownership so a crash still removes
// exactly those rules.
func TestNativeSetupRecordsEngineRuleOwnership(t *testing.T) {
	isolateHostState(t)
	resolvDir := t.TempDir()
	oldResolv, oldBackup, oldLink := resolvConfPath, resolvBackup, resolvLinkBackup
	resolvConfPath = filepath.Join(resolvDir, "resolv.conf")
	resolvBackup = filepath.Join(resolvDir, "resolv.conf.bypath-backup")
	resolvLinkBackup = filepath.Join(resolvDir, "resolv.conf.bypath-link")
	t.Cleanup(func() { resolvConfPath, resolvBackup, resolvLinkBackup = oldResolv, oldBackup, oldLink })
	if err := os.WriteFile(resolvConfPath, []byte("nameserver 192.0.2.1\n"), 0644); err != nil {
		t.Fatalf("seeding resolv.conf: %v", err)
	}
	// setupRouting makes the file immutable. Clearing the attribute is a no-op
	// unless the test runs as root on a filesystem that honours chattr, where
	// TempDir cleanup would otherwise fail.
	t.Cleanup(func() { exec.Command("chattr", "-i", resolvConfPath).Run() })
	stubHostCommands(t, nil,
		func(string, ...string) error { return errors.New("absent") },
		func(name string, args ...string) ([]byte, error) {
			if name == "ip6tables" {
				return []byte("-A FORWARD -j " + chainV6Drop + "\n"), nil
			}
			if name == "iptables" && len(args) > 2 && args[2] == "-S" {
				return []byte("-A FORWARD -j " + chainForward + "\n"), nil
			}
			return nil, nil
		},
	)

	gw := &Gateway{
		config:    &config.Config{Gateway: config.GatewayConfig{Enabled: true}},
		iface:     "eth0",
		subnet:    "10.1.0.0/24",
		dnsPort:   53,
		nativeTUN: true,
	}
	if err := gw.setupRouting(); err != nil {
		t.Fatalf("setupRouting: %v", err)
	}
	st := gatewayState()
	if st == nil || st.Mode != "native" || !st.NativeRules {
		t.Fatalf("ownership record = %+v, want native mode with engine rules claimed", st)
	}
}

// A v2 record saying "native" does not by itself prove bypath installed engine
// rules. Without the explicit ownership flag, cleanup must leave table 2022 and
// everything else alone: it may belong to a different installation.
func TestNativeModeRecordWithoutOwnershipDoesNotTouchLegacyTable(t *testing.T) {
	isolateHostState(t)
	calls := stubHostCommands(t, nil, func(string, ...string) error { return errors.New("absent") }, func(name string, args ...string) ([]byte, error) {
		if name == "ip" && len(args) > 0 && args[0] == "rule" {
			return []byte("9000: from all lookup 2022\n"), nil
		}
		return nil, nil
	})

	st := &gatewayRunState{Version: gatewayStateVersion, Mode: "native"}
	if err := (&Gateway{}).undoNetworkState(st); err != nil {
		t.Fatalf("undoNetworkState: %v", err)
	}
	joined := strings.Join(*calls, "\n")
	if strings.Contains(joined, "rule del") || strings.Contains(joined, "route del") {
		t.Errorf("native mode without ownership deleted host routing:\n%s", joined)
	}
	if st.NativeRules {
		t.Error("cleanup claimed engine-rule ownership it never had")
	}
}

// A record that claims engine rules without naming the reserved table cannot
// be acted on safely: guessing would clean either table 2022 or the wrong
// table. The record is retained for a human decision instead.
func TestUndoNetworkStateRefusesNativeOwnershipWithoutTable(t *testing.T) {
	isolateHostState(t)
	calls := stubHostCommands(t, nil, func(string, ...string) error { return errors.New("absent") }, nil)

	st := &gatewayRunState{Version: gatewayStateVersion, Mode: "native", NativeRules: true}
	if err := (&Gateway{}).undoNetworkState(st); err == nil {
		t.Fatal("undoNetworkState cleaned native routing without a reserved table")
	}
	if !st.NativeRules {
		t.Error("ownership flag was cleared without cleaning anything")
	}
	if joined := strings.Join(*calls, "\n"); strings.Contains(joined, "rule del") || strings.Contains(joined, "route del") {
		t.Errorf("cleanup mutated host routing from an untrusted record:\n%s", joined)
	}
}

// The pinned-table cleanup must name the table on every deletion (listings omit
// it) and verify the table is empty afterwards.
func TestUndoNetworkStateCleansOnlyPinnedNativeTable(t *testing.T) {
	isolateHostState(t)
	var calls []string
	ruleRemoved, routeRemoved := false, false
	stubHostCommands(t, func(name string, args ...string) error {
		calls = append(calls, strings.Join(append([]string{name}, args...), " "))
		if len(args) >= 2 && args[0] == "rule" && args[1] == "del" {
			ruleRemoved = true
		}
		if len(args) >= 2 && args[0] == "route" && args[1] == "del" {
			routeRemoved = true
		}
		return nil
	}, func(string, ...string) error { return errors.New("absent") }, func(name string, args ...string) ([]byte, error) {
		if name != "ip" {
			return nil, nil
		}
		if len(args) > 0 && args[0] == "rule" {
			if ruleRemoved {
				return nil, nil
			}
			return []byte("9200: from all lookup 20220\n"), nil
		}
		if len(args) > 1 && args[0] == "route" && args[1] == "show" {
			if routeRemoved {
				return nil, nil
			}
			return []byte("default via 10.0.0.1 dev tun0\n"), nil
		}
		return nil, nil
	})

	st := &gatewayRunState{
		Version:         gatewayStateVersion,
		Mode:            "native",
		NativeRules:     true,
		NativeRuleTable: tunnel.NativeRouteTable,
	}
	if err := (&Gateway{}).undoNetworkState(st); err != nil {
		t.Fatalf("undoNetworkState: %v", err)
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "ip rule del prio 9200 lookup 20220") {
		t.Errorf("pinned engine rule was not removed:\n%s", joined)
	}
	if !strings.Contains(joined, "ip route del default via 10.0.0.1 dev tun0 table 20220") {
		t.Errorf("pinned route was deleted without the table selector:\n%s", joined)
	}
	if strings.Contains(joined, "2022\n") || strings.Contains(joined, "lookup 2022 ") {
		t.Errorf("pinned cleanup touched legacy table 2022:\n%s", joined)
	}
	if st.NativeRules || st.NativeRuleTable != 0 {
		t.Fatalf("ownership survived a successful cleanup: %+v", st)
	}
}

// A failed inverse must stay in the record while everything that did succeed is
// pruned, so the next recovery attempt retries only the remaining work.
func TestUndoNetworkStatePrunesOnlySuccessfulInverses(t *testing.T) {
	isolateHostState(t)
	stubHostCommands(t, func(_ string, args ...string) error {
		if strings.Contains(strings.Join(args, " "), "default") {
			return errors.New("route busy")
		}
		return nil
	}, nil, func(name string, args ...string) ([]byte, error) {
		if name == "ip" && len(args) > 1 && args[0] == "route" && args[1] == "show" {
			return []byte("default via 10.0.0.1 dev tun0\n10.1.0.0/24 dev eth0\n"), nil
		}
		return nil, nil
	})

	st := &gatewayRunState{
		Version: gatewayStateVersion,
		Mode:    "legacy",
		Routes: [][]string{
			{"route", "add", "default", "via", "10.0.0.1", "dev", "tun0", "table", "100"},
			{"route", "add", "10.1.0.0/24", "dev", "eth0", "table", "100"},
		},
	}
	if err := (&Gateway{}).undoNetworkState(st); err == nil {
		t.Fatal("undoNetworkState reported success although the default route inverse failed")
	}
	if len(st.Routes) != 1 || !strings.Contains(strings.Join(st.Routes[0], " "), "default") {
		t.Fatalf("remaining routes = %v, want only the failed default route", st.Routes)
	}
	saved := gatewayState()
	if saved == nil || len(saved.Routes) != 1 {
		t.Fatalf("persisted state = %+v, want the failed route retained", saved)
	}
}

// Cleanup must not erase the ownership record when an inverse fails; the
// surviving record is what the next run needs to finish the rollback.
func TestCleanupRoutingKeepsRecordWhenInverseFails(t *testing.T) {
	isolateHostState(t)
	stubHostCommands(t, func(_ string, args ...string) error {
		if len(args) >= 2 && args[0] == "rule" && args[1] == "del" {
			return errors.New("rule busy")
		}
		return nil
	}, nil, func(name string, args ...string) ([]byte, error) {
		if name == "ip" && len(args) > 0 && args[0] == "rule" {
			return []byte("100: from all fwmark 0x1 lookup 100\n"), nil
		}
		return nil, nil
	})

	st, err := markGatewayState("legacy")
	if err != nil {
		t.Fatalf("markGatewayState: %v", err)
	}
	st.RuleAdded = true
	if err := saveGatewayState(st); err != nil {
		t.Fatalf("saveGatewayState: %v", err)
	}

	gw := &Gateway{run: st, networkMutated: true}
	if err := gw.cleanupRouting(); err == nil {
		t.Fatal("cleanupRouting reported success although the rule inverse failed")
	}

	saved := gatewayState()
	if saved == nil || !saved.RuleAdded {
		t.Fatalf("persisted state = %+v, want the failed rule inverse retained", saved)
	}
}

// blockStatePersistence makes the ownership record impossible to replace: the
// record path becomes a directory, so the atomic rename fails on every
// platform. Nothing may be mutated when durable ownership cannot be written.
func blockStatePersistence(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(paths.Get().TmpDir, 0700); err != nil {
		t.Fatalf("creating runtime dir: %v", err)
	}
	if err := os.MkdirAll(gatewayStateFile(), 0700); err != nil {
		t.Fatalf("blocking state file: %v", err)
	}
}

// writeCorruptGatewayState plants a record that exists but cannot be parsed.
func writeCorruptGatewayState(t *testing.T) {
	t.Helper()
	if err := os.MkdirAll(paths.Get().TmpDir, 0700); err != nil {
		t.Fatalf("creating runtime dir: %v", err)
	}
	if err := os.WriteFile(gatewayStateFile(), []byte("{not a record"), 0600); err != nil {
		t.Fatalf("writing corrupt ownership record: %v", err)
	}
}

// A corrupt record may describe live host changes, so it must block startup
// and survive cleanup instead of being mistaken for a clean host.
func TestCleanupPreviousRunRefusesCorruptOwnershipRecord(t *testing.T) {
	isolateHostState(t)
	writeCorruptGatewayState(t)
	oldPkill := pkillCommand
	pkillCommand = func(string) {}
	t.Cleanup(func() { pkillCommand = oldPkill })

	gw := &Gateway{config: &config.Config{}}
	if err := gw.cleanupPreviousRun(); err == nil {
		t.Fatal("startup proceeded from a corrupt ownership record")
	}
	if _, err := os.Stat(gatewayStateFile()); err != nil {
		t.Fatalf("corrupt record was deleted instead of preserved: %v", err)
	}
}

func TestCleanupPersistedStateRefusesCorruptOwnershipRecord(t *testing.T) {
	isolateHostState(t)
	writeCorruptGatewayState(t)

	if err := CleanupPersistedState(); err == nil {
		t.Fatal("crash-recovery accepted a corrupt ownership record")
	}
	if _, err := os.Stat(gatewayStateFile()); err != nil {
		t.Fatalf("corrupt record was deleted instead of preserved: %v", err)
	}
}

func TestCleanupRoutingKeepsCorruptOwnershipRecord(t *testing.T) {
	isolateHostState(t)
	writeCorruptGatewayState(t)

	gw := &Gateway{networkMutated: true}
	if err := gw.cleanupRouting(); err == nil {
		t.Fatal("cleanupRouting reported success without reading the record")
	}
	if _, err := os.Stat(gatewayStateFile()); err != nil {
		t.Fatalf("corrupt record was deleted instead of preserved: %v", err)
	}
}

func TestApplyRouteDoesNotRunWhenOwnershipCannotBePersisted(t *testing.T) {
	isolateHostState(t)
	calls := stubHostCommands(t, nil, nil, nil)
	blockStatePersistence(t)

	gw := &Gateway{}
	st := &gatewayRunState{Version: gatewayStateVersion, Mode: "legacy"}
	if err := gw.applyRoute(st, "route", "add", "default", "via", "10.0.0.1", "dev", "tun0", "table", "100"); err == nil {
		t.Fatal("applyRoute succeeded without a durable ownership record")
	}
	if len(st.Routes) != 0 {
		t.Fatalf("in-memory record kept an unapplied route: %v", st.Routes)
	}
	if len(*calls) != 0 {
		t.Fatalf("host commands ran without durable ownership: %v", *calls)
	}
}

func TestEnsureRunStateReportsPersistenceFailure(t *testing.T) {
	isolateHostState(t)
	blockStatePersistence(t)

	gw := &Gateway{}
	if _, err := gw.ensureRunState("legacy"); err == nil {
		t.Fatal("ensureRunState reported success without a durable record")
	}
	if err := gw.persistRunState(); err == nil {
		t.Fatal("persistRunState reported success without a durable record")
	}
}

func TestSetResolvConfLeavesFileUntouchedWhenPersistenceFails(t *testing.T) {
	isolateHostState(t)
	resolvDir := t.TempDir()
	oldResolv, oldBackup, oldLink := resolvConfPath, resolvBackup, resolvLinkBackup
	resolvConfPath = filepath.Join(resolvDir, "resolv.conf")
	resolvBackup = filepath.Join(resolvDir, "resolv.conf.bypath-backup")
	resolvLinkBackup = filepath.Join(resolvDir, "resolv.conf.bypath-link")
	t.Cleanup(func() { resolvConfPath, resolvBackup, resolvLinkBackup = oldResolv, oldBackup, oldLink })
	const original = "nameserver 192.0.2.1\n"
	if err := os.WriteFile(resolvConfPath, []byte(original), 0644); err != nil {
		t.Fatalf("seeding resolv.conf: %v", err)
	}
	blockStatePersistence(t)

	if err := (&Gateway{}).setResolvConf("127.0.0.1"); err == nil {
		t.Fatal("setResolvConf rewrote the host resolver without an ownership record")
	}
	got, err := os.ReadFile(resolvConfPath)
	if err != nil {
		t.Fatalf("reading resolv.conf: %v", err)
	}
	if string(got) != original {
		t.Fatalf("resolv.conf = %q, want it untouched", got)
	}
}

func TestSetResolvConfRefusesToOverwriteUnreadableResolver(t *testing.T) {
	isolateHostState(t)
	resolvDir := t.TempDir()
	oldResolv, oldBackup, oldLink := resolvConfPath, resolvBackup, resolvLinkBackup
	resolvConfPath = filepath.Join(resolvDir, "resolv.conf")
	resolvBackup = filepath.Join(resolvDir, "resolv.conf.bypath-backup")
	resolvLinkBackup = filepath.Join(resolvDir, "resolv.conf.bypath-link")
	t.Cleanup(func() { resolvConfPath, resolvBackup, resolvLinkBackup = oldResolv, oldBackup, oldLink })
	if err := os.Mkdir(resolvConfPath, 0700); err != nil {
		t.Fatalf("making the resolver path unreadable: %v", err)
	}

	if err := (&Gateway{}).setResolvConf("127.0.0.1"); err == nil {
		t.Fatal("setResolvConf replaced a resolver it could not read (the original would be lost)")
	}
	if fi, err := os.Stat(resolvConfPath); err != nil || !fi.IsDir() {
		t.Fatalf("resolver path was replaced despite the read failure: %v", err)
	}
}

func TestRestoreResolvConfReportsUnreadableBackup(t *testing.T) {
	isolateHostState(t)
	resolvDir := t.TempDir()
	oldResolv, oldBackup, oldLink := resolvConfPath, resolvBackup, resolvLinkBackup
	resolvConfPath = filepath.Join(resolvDir, "resolv.conf")
	resolvBackup = filepath.Join(resolvDir, "resolv.conf.bypath-backup")
	resolvLinkBackup = filepath.Join(resolvDir, "resolv.conf.bypath-link")
	t.Cleanup(func() { resolvConfPath, resolvBackup, resolvLinkBackup = oldResolv, oldBackup, oldLink })
	if err := os.Mkdir(resolvBackup, 0700); err != nil {
		t.Fatalf("making the resolver backup unreadable: %v", err)
	}

	if err := (&Gateway{}).restoreResolvConf(); err == nil {
		t.Fatal("restoreResolvConf reported success while the backup could not be read")
	}
}

func TestDisableSystemdResolvedDoesNotStopServiceWhenPersistenceFails(t *testing.T) {
	isolateHostState(t)
	var ops []string
	withMockSystemctl(t,
		func(args []string) ([]byte, error) {
			if len(args) > 0 && args[0] == "is-active" {
				return []byte("active\n"), nil
			}
			return nil, nil
		},
		func(args []string) error {
			ops = append(ops, strings.Join(args, " "))
			return nil
		},
	)
	blockStatePersistence(t)

	stopped, err := (&Gateway{}).disableSystemdResolved()
	if err == nil {
		t.Fatal("disableSystemdResolved succeeded without durable ownership")
	}
	if stopped {
		t.Error("disableSystemdResolved reported the service as stopped")
	}
	for _, op := range ops {
		if strings.HasPrefix(op, "stop") {
			t.Fatalf("systemd-resolved was stopped without durable ownership: %v", ops)
		}
	}
}

func TestStopDnsmasqLeavesActiveServiceWhenPersistenceFails(t *testing.T) {
	isolateHostState(t)
	var ops []string
	withMockSystemctl(t,
		func(args []string) ([]byte, error) {
			if len(args) > 0 && args[0] == "is-active" {
				return []byte("active\n"), nil
			}
			return nil, nil
		},
		func(args []string) error {
			ops = append(ops, strings.Join(args, " "))
			return nil
		},
	)
	blockStatePersistence(t)

	gw := &Gateway{}
	if err := gw.stopDnsmasq(); err == nil {
		t.Fatal("stopDnsmasq succeeded without durable ownership")
	}
	for _, op := range ops {
		if strings.HasPrefix(op, "stop") {
			t.Fatalf("dnsmasq was stopped without durable ownership: %v", ops)
		}
	}
}

// prepareNativeOwnership must reserve bypath's table and persist that ownership
// before the engine is allowed to create any auto_route objects.
func TestPrepareNativeOwnershipPersistsPinnedTableBeforeEngine(t *testing.T) {
	isolateHostState(t)
	calls := stubHostCommands(t, nil, nil, nil)

	gw := &Gateway{config: &config.Config{}}
	if err := gw.prepareNativeOwnership(); err != nil {
		t.Fatalf("prepareNativeOwnership: %v", err)
	}
	st := gatewayState()
	if st == nil || st.Mode != "native" || !st.NativeRules || st.NativeRuleTable != tunnel.NativeRouteTable {
		t.Fatalf("ownership record = %+v, want native with pinned table %d", st, tunnel.NativeRouteTable)
	}
	if len(*calls) != 0 {
		t.Fatalf("preflight mutated host networking: %v", *calls)
	}
}

func TestPrepareNativeOwnershipRejectsTableAlreadyReferenced(t *testing.T) {
	isolateHostState(t)
	stubHostCommands(t, nil, nil, func(name string, args ...string) ([]byte, error) {
		if name == "ip" && len(args) > 0 && args[0] == "rule" {
			return []byte("9200: from all lookup 20220\n"), nil
		}
		return nil, nil
	})

	if err := (&Gateway{config: &config.Config{}}).prepareNativeOwnership(); err == nil {
		t.Fatal("prepareNativeOwnership accepted an already-referenced reserved table")
	}
	if gatewayState() != nil {
		t.Fatal("prepareNativeOwnership recorded ownership of a foreign table")
	}
}

func TestPrepareNativeOwnershipRejectsNonEmptyTable(t *testing.T) {
	isolateHostState(t)
	stubHostCommands(t, nil, nil, func(name string, args ...string) ([]byte, error) {
		if name == "ip" && len(args) > 1 && args[0] == "route" && args[1] == "show" {
			return []byte("default via 203.0.113.1 dev eth0\n"), nil
		}
		return nil, nil
	})

	if err := (&Gateway{config: &config.Config{}}).prepareNativeOwnership(); err == nil {
		t.Fatal("prepareNativeOwnership accepted a non-empty reserved table")
	}
	if gatewayState() != nil {
		t.Fatal("prepareNativeOwnership recorded ownership of a foreign route table")
	}
}

// An FIB table that has never held a route is the clean state native mode
// requires. iproute2 reports it as an error, which must be read as "empty"
// rather than as an inspection failure that blocks startup.
func TestPrepareNativeOwnershipTreatsMissingFIBTableAsEmpty(t *testing.T) {
	isolateHostState(t)
	stubHostCommands(t, nil, nil, func(name string, args ...string) ([]byte, error) {
		if name == "ip" && len(args) > 1 && args[0] == "route" && args[1] == "show" {
			return []byte("RTNETLINK answers: No such file or directory\n"), errors.New("exit status 2")
		}
		return nil, nil
	})

	if err := (&Gateway{config: &config.Config{}}).prepareNativeOwnership(); err != nil {
		t.Fatalf("prepareNativeOwnership treated a nonexistent FIB table as an error: %v", err)
	}
	st := gatewayState()
	if st == nil || !st.NativeRules || st.NativeRuleTable != tunnel.NativeRouteTable {
		t.Fatalf("ownership record = %+v, want native with pinned table %d", st, tunnel.NativeRouteTable)
	}
}

func TestRemoveEngineNativeRulesDeletesOnlyPinnedTable(t *testing.T) {
	isolateHostState(t)
	var calls []string
	ruleRemoved, routeRemoved := false, false
	stubHostCommands(t, func(name string, args ...string) error {
		calls = append(calls, strings.Join(append([]string{name}, args...), " "))
		if len(args) >= 2 && args[0] == "rule" && args[1] == "del" {
			ruleRemoved = true
		}
		if len(args) >= 2 && args[0] == "route" && args[1] == "del" {
			routeRemoved = true
		}
		return nil
	}, nil, func(name string, args ...string) ([]byte, error) {
		if name != "ip" {
			return nil, nil
		}
		if len(args) > 0 && args[0] == "rule" {
			if ruleRemoved {
				return []byte("100: from all fwmark 0x1 lookup 100\n"), nil
			}
			return []byte("9200: from all lookup 20220\n100: from all fwmark 0x1 lookup 100\n"), nil
		}
		if len(args) > 1 && args[0] == "route" && args[1] == "show" {
			if routeRemoved {
				return nil, nil
			}
			return []byte("default via 10.0.0.1 dev tun0\n"), nil
		}
		return nil, nil
	})

	if err := removeEngineNativeRules(tunnel.NativeRouteTable); err != nil {
		t.Fatalf("removeEngineNativeRules: %v", err)
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "ip rule del prio 9200 lookup 20220") {
		t.Errorf("pinned engine rule was not removed:\n%s", joined)
	}
	if !strings.Contains(joined, "ip route del default via 10.0.0.1 dev tun0 table 20220") {
		t.Errorf("pinned table route was deleted without the table selector:\n%s", joined)
	}
	if strings.Contains(joined, "lookup 100") || strings.Contains(joined, "flush") {
		t.Errorf("removal touched a shared table:\n%s", joined)
	}
}

// A second recovery after an interruption must finish cleanly: resources that
// are already gone are a successful inverse, not an error.
func TestUndoNetworkStateTreatsAlreadyRemovedResourcesAsSuccess(t *testing.T) {
	isolateHostState(t)
	calls := stubHostCommands(t, nil,
		func(name string, args ...string) error {
			if name == "ip" && len(args) > 1 && args[0] == "link" && args[1] == "show" {
				return errors.New("absent")
			}
			return nil
		},
		func(name string, args ...string) ([]byte, error) {
			if name == "iptables" || name == "ip6tables" {
				return []byte(name + ": No chain/target/match by that name."), errors.New("exit status 1")
			}
			if name == "ip" && len(args) > 1 && args[0] == "route" && args[1] == "show" {
				return nil, nil
			}
			if name == "ip" && len(args) > 0 && args[0] == "rule" {
				return []byte("32766: from all lookup main\n"), nil
			}
			if name == "ip" && len(args) > 0 && args[0] == "-brief" {
				return nil, errors.New("tun0 does not exist")
			}
			return nil, nil
		},
	)

	st := &gatewayRunState{
		Version:    gatewayStateVersion,
		Mode:       "legacy",
		Routes:     [][]string{{"route", "add", "default", "via", "10.0.0.1", "dev", "tun0", "table", "100"}},
		RuleAdded:  true,
		TunCreated: true,
	}
	if err := (&Gateway{}).undoNetworkState(st); err != nil {
		t.Fatalf("second recovery reported an error for already-removed resources: %v", err)
	}
	if len(st.Routes) != 0 || st.RuleAdded || st.TunCreated {
		t.Fatalf("record still claims removed resources: %+v", st)
	}
	if len(*calls) != 0 {
		t.Fatalf("second recovery issued commands for absent resources: %v", *calls)
	}
}

func TestUndoNetworkStateRefusesForeignTun(t *testing.T) {
	isolateHostState(t)
	calls := stubHostCommands(t, nil, nil, func(name string, args ...string) ([]byte, error) {
		if name == "ip" && len(args) > 2 && args[0] == "-brief" {
			return []byte("tun0 UNKNOWN 10.9.9.9/24\n"), nil
		}
		return nil, nil
	})

	st := &gatewayRunState{Version: gatewayStateVersion, Mode: "legacy", TunCreated: true}
	if err := (&Gateway{}).undoNetworkState(st); err == nil {
		t.Fatal("undoNetworkState deleted a tun0 it could not prove it created")
	}
	if !st.TunCreated {
		t.Error("ownership flag was cleared for a foreign interface")
	}
	if strings.Contains(strings.Join(*calls, "\n"), "link del tun0") {
		t.Fatalf("foreign interface was deleted: %v", *calls)
	}
}

func TestUndoNetworkStateRefusesNonAddRouteRecord(t *testing.T) {
	isolateHostState(t)
	calls := stubHostCommands(t, nil, nil, nil)

	st := &gatewayRunState{
		Version: gatewayStateVersion,
		Mode:    "legacy",
		Routes:  [][]string{{"route", "flush", "table", "100"}},
	}
	if err := (&Gateway{}).undoNetworkState(st); err == nil {
		t.Fatal("undoNetworkState executed a record that was not a route addition")
	}
	if len(st.Routes) != 1 {
		t.Fatalf("refused record was pruned from state: %v", st.Routes)
	}
	if len(*calls) != 0 {
		t.Fatalf("unexpected commands: %v", *calls)
	}
}

// containmentFirewall models the effective iptables/ip6tables state bypath
// manipulates. Asserting against effective rules (order included) is stronger
// than asserting which command strings were generated: it can prove that a
// forwarded packet never had an uncontained window.
type containmentFirewall struct {
	t                  *testing.T
	rules              map[string][][]string
	calls              []string
	ruleAdded          bool
	routes             [][]string
	flushHook          func(table, chain string)
	requireContainment bool
	failSysctl         bool
}

func newContainmentFirewall(t *testing.T) *containmentFirewall {
	t.Helper()
	f := &containmentFirewall{t: t, rules: map[string][][]string{}}
	for _, bin := range []string{"iptables", "ip6tables"} {
		for table, chains := range map[string][]string{
			"filter": {"INPUT", "FORWARD", "OUTPUT"},
			"nat":    {"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"},
			"mangle": {"PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"},
		} {
			for _, chain := range chains {
				f.rules[fwKey(bin, table, chain)] = nil
			}
		}
	}
	return f
}

func fwKey(bin, table, chain string) string { return bin + "|" + table + "|" + chain }

func (f *containmentFirewall) chainRules(bin, table, chain string) [][]string {
	return f.rules[fwKey(bin, table, chain)]
}

func (f *containmentFirewall) addRule(bin, table, chain string, spec ...string) {
	key := fwKey(bin, table, chain)
	f.rules[key] = append(f.rules[key], append([]string(nil), spec...))
}

func (f *containmentFirewall) hasRule(bin, table, chain string, spec ...string) bool {
	for _, r := range f.chainRules(bin, table, chain) {
		if routeArgsEqual(r, spec) {
			return true
		}
	}
	return false
}

func (f *containmentFirewall) hasJump(bin, table, parent, chain string) bool {
	return f.hasRule(bin, table, parent, "-j", chain)
}

// firstJump returns the target of the first rule of the parent chain.
func (f *containmentFirewall) firstJump(bin, table, parent string) string {
	rules := f.chainRules(bin, table, parent)
	if len(rules) == 0 {
		return ""
	}
	for i := 0; i+1 < len(rules[0]); i++ {
		if rules[0][i] == "-j" {
			return rules[0][i+1]
		}
	}
	return ""
}

// checkContainment fails the test if a mutation removes the last IPv4
// containment jump. It is deliberately conditional on containment existing
// before the command, so installing the guard on a clean host is not flagged.
func (f *containmentFirewall) checkContainment(had bool) {
	if !f.requireContainment || !had || len(f.calls) == 0 {
		return
	}
	if !f.hasJump("iptables", "filter", "FORWARD", chainForward) &&
		!f.hasJump("iptables", "filter", "FORWARD", chainGuard) {
		f.t.Errorf("FORWARD lost fail-closed containment during %q", f.calls[len(f.calls)-1])
	}
}

func splitFirewallTable(args []string) (string, []string) {
	table := "filter"
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-t" {
			rest := append([]string(nil), args[:i]...)
			rest = append(rest, args[i+2:]...)
			return args[i+1], rest
		}
	}
	return table, args
}

func (f *containmentFirewall) run(name string, args ...string) error {
	f.calls = append(f.calls, strings.Join(append([]string{name}, args...), " "))

	if name != "iptables" && name != "ip6tables" {
		return f.runOther(name, args...)
	}
	hadContainment := f.hasJump("iptables", "filter", "FORWARD", chainForward) ||
		f.hasJump("iptables", "filter", "FORWARD", chainGuard)
	defer f.checkContainment(hadContainment)

	table, rest := splitFirewallTable(args)
	if len(rest) == 0 {
		return nil
	}
	key := func(chain string) string { return fwKey(name, table, chain) }
	switch rest[0] {
	case "-N":
		if _, ok := f.rules[key(rest[1])]; ok {
			return fmt.Errorf("%s: Chain already exists", name)
		}
		f.rules[key(rest[1])] = nil
	case "-F":
		if _, ok := f.rules[key(rest[1])]; !ok {
			return fmt.Errorf("%s: No chain/target/match by that name", name)
		}
		if f.flushHook != nil {
			f.flushHook(table, rest[1])
		}
		f.rules[key(rest[1])] = nil
	case "-A":
		f.rules[key(rest[1])] = append(f.rules[key(rest[1])], append([]string(nil), rest[2:]...))
	case "-I":
		if rest[2] != "1" {
			return fmt.Errorf("%s: only insertion at position 1 is modelled", name)
		}
		rules := append([][]string{append([]string(nil), rest[3:]...)}, f.rules[key(rest[1])]...)
		f.rules[key(rest[1])] = rules
	case "-D":
		rules := f.rules[key(rest[1])]
		if n, err := strconv.Atoi(rest[2]); err == nil && len(rest) == 3 {
			if n < 1 || n > len(rules) {
				return fmt.Errorf("%s: Index of deletion too big", name)
			}
			f.rules[key(rest[1])] = append(rules[:n-1], rules[n:]...)
			return nil
		}
		for i, r := range rules {
			if routeArgsEqual(r, rest[2:]) {
				f.rules[key(rest[1])] = append(rules[:i], rules[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("%s: Bad rule (does a matching rule exist in that chain?)", name)
	case "-X":
		if _, ok := f.rules[key(rest[1])]; !ok {
			return fmt.Errorf("%s: No chain/target/match by that name", name)
		}
		if len(f.rules[key(rest[1])]) != 0 {
			return fmt.Errorf("%s: Directory not empty", name)
		}
		delete(f.rules, key(rest[1]))
	}
	return nil
}

func (f *containmentFirewall) runOther(name string, args ...string) error {
	if name == "sysctl" && f.failSysctl {
		return errors.New("read-only file system")
	}
	if name != "ip" || len(args) == 0 {
		return nil
	}
	switch args[0] {
	case "rule":
		if len(args) > 1 {
			switch args[1] {
			case "add":
				f.ruleAdded = true
			case "del":
				f.ruleAdded = false
			}
		}
	case "route":
		if len(args) < 2 {
			return nil
		}
		switch args[1] {
		case "add":
			f.routes = append(f.routes, append([]string(nil), args...))
		case "del":
			for i, r := range f.routes {
				if routeArgsEqual(r[2:], args[2:]) {
					f.routes = append(f.routes[:i], f.routes[i+1:]...)
					return nil
				}
			}
		}
	}
	return nil
}

func (f *containmentFirewall) output(name string, args ...string) ([]byte, error) {
	if name == "iptables" || name == "ip6tables" {
		table, rest := splitFirewallTable(args)
		if len(rest) == 0 {
			return nil, nil
		}
		switch rest[0] {
		case "-S":
			rules, ok := f.rules[fwKey(name, table, rest[1])]
			if !ok {
				return []byte(name + ": No chain/target/match by that name."), errors.New("exit status 1")
			}
			var b strings.Builder
			for _, r := range rules {
				b.WriteString("-A " + rest[1] + " " + strings.Join(r, " ") + "\n")
			}
			return []byte(b.String()), nil
		case "-C":
			if f.hasRule(name, table, rest[1], rest[2:]...) {
				return nil, nil
			}
			return []byte(name + ": Bad rule (does a matching rule exist in that chain?)."), errors.New("exit status 1")
		}
		return nil, nil
	}
	if name != "ip" || len(args) == 0 {
		return nil, nil
	}
	switch args[0] {
	case "rule":
		if len(args) > 1 && args[1] == "show" {
			if f.ruleAdded {
				return []byte("100: from all fwmark 0x1 lookup 100\n"), nil
			}
			return nil, nil
		}
	case "route":
		if len(args) > 1 && args[1] == "show" {
			var b strings.Builder
			for _, r := range f.routes {
				b.WriteString(strings.Join(r[2:], " ") + "\n")
			}
			return []byte(b.String()), nil
		}
	}
	return nil, nil
}

func (f *containmentFirewall) stub(t *testing.T) {
	t.Helper()
	oldRun, oldStatus, oldOutput := runCommand, statusCommand, outputCommand
	runCommand = f.run
	statusCommand = func(string, ...string) error { return errors.New("absent") }
	outputCommand = f.output
	t.Cleanup(func() { runCommand, statusCommand, outputCommand = oldRun, oldStatus, oldOutput })
}

// enableContainmentHost makes the Linux firewall paths and the bare-metal
// resolver paths active regardless of the host running the test.
func enableContainmentHost(t *testing.T) {
	t.Helper()
	oldFirewall, oldNetNS := hostFirewallAvailable, networkNamespaceIsolated
	hostFirewallAvailable = func() bool { return true }
	networkNamespaceIsolated = func() bool { return false }
	t.Cleanup(func() { hostFirewallAvailable, networkNamespaceIsolated = oldFirewall, oldNetNS })
}

// scratchResolver isolates resolv.conf and /etc/hosts for tests that reach the
// resolver rewrite path.
func scratchResolver(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oldResolv, oldBackup, oldLink, oldHosts := resolvConfPath, resolvBackup, resolvLinkBackup, hostsFilePath
	resolvConfPath = filepath.Join(dir, "resolv.conf")
	resolvBackup = filepath.Join(dir, "resolv.conf.bypath-backup")
	resolvLinkBackup = filepath.Join(dir, "resolv.conf.bypath-link")
	hostsFilePath = filepath.Join(dir, "hosts")
	t.Cleanup(func() {
		resolvConfPath, resolvBackup, resolvLinkBackup, hostsFilePath = oldResolv, oldBackup, oldLink, oldHosts
	})
	if err := os.WriteFile(resolvConfPath, []byte("nameserver 192.0.2.1\n"), 0644); err != nil {
		t.Fatalf("seeding resolv.conf: %v", err)
	}
	t.Cleanup(func() { exec.Command("chattr", "-i", resolvConfPath).Run() })
	return resolvConfPath
}

// seedRunningGateway installs the firewall state a live legacy gateway leaves
// behind, including the DNS/NAT/mangle intercept chains a stop must remove.
func seedRunningGateway(f *containmentFirewall, iface string) {
	f.addRule("iptables", "filter", "FORWARD", "-j", chainForward)
	f.addRule("iptables", "filter", chainForward, "-i", iface, "-o", "tun0", "-j", "ACCEPT")
	f.addRule("iptables", "filter", chainForward, "-i", iface, "-o", iface, "-j", "ACCEPT")
	f.addRule("iptables", "filter", chainForward, "-i", iface, "-j", "DROP")
	f.addRule("ip6tables", "filter", "FORWARD", "-j", chainV6Drop)
	f.addRule("ip6tables", "filter", chainV6Drop, "-i", iface, "-j", "DROP")

	f.rules[fwKey("iptables", "nat", chainDNS)] = nil
	f.addRule("iptables", "nat", chainDNS, "-i", iface, "-s", "10.1.0.0/24", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "53")
	f.addRule("iptables", "nat", "PREROUTING", "-j", chainDNS)
	f.rules[fwKey("iptables", "nat", chainNat)] = nil
	f.addRule("iptables", "nat", chainNat, "-o", "tun0", "-j", "MASQUERADE")
	f.addRule("iptables", "nat", "POSTROUTING", "-j", chainNat)
	f.rules[fwKey("iptables", "mangle", chainMangle)] = nil
	f.addRule("iptables", "mangle", chainMangle, "-i", iface, "-s", "10.1.0.0/24", "!", "-d", "10.1.0.0/24", "-j", "MARK", "--set-mark", "0x1")
	f.addRule("iptables", "mangle", "PREROUTING", "-j", chainMangle)
}

// TestSetupRoutingGuardsForwardingWindow proves the guard chain is effective at
// the exact moment BYPATH_FWD is flushed: the rebuild must never expose a
// forwarded packet between the flush and the re-installed jump.
func TestSetupRoutingGuardsForwardingWindow(t *testing.T) {
	isolateHostState(t)
	enableContainmentHost(t)
	scratchResolver(t)
	setHostForwarding(t, "0")

	fw := newContainmentFirewall(t)
	fw.stub(t)
	oldPkill := pkillCommand
	pkillCommand = func(string) {}
	t.Cleanup(func() { pkillCommand = oldPkill })
	fw.requireContainment = true

	flushSawGuard := false
	fw.flushHook = func(table, chain string) {
		if table == "filter" && chain == chainForward {
			if fw.firstJump("iptables", table, "FORWARD") == chainGuard {
				flushSawGuard = true
			}
		}
	}

	gw := &Gateway{
		config:    &config.Config{Gateway: config.GatewayConfig{Enabled: true}},
		iface:     "eth0",
		subnet:    "10.1.0.0/24",
		dnsPort:   53,
		nativeTUN: false,
	}
	if err := gw.setupRouting(); err != nil {
		t.Fatalf("setupRouting: %v", err)
	}
	if !flushSawGuard {
		t.Fatal("BYPATH_FWD was flushed without the fail-closed guard at the head of FORWARD")
	}
	if got := fw.firstJump("iptables", "filter", "FORWARD"); got != chainForward {
		t.Fatalf("first FORWARD jump = %q, want %q after setup", got, chainForward)
	}
	if _, ok := fw.rules[fwKey("iptables", "filter", chainGuard)]; ok {
		t.Fatal("placeholder guard chain survived a successful setup")
	}
	rules := fw.chainRules("iptables", "filter", chainForward)
	if len(rules) == 0 || !routeArgsEqual(rules[len(rules)-1], []string{"-i", "eth0", "-j", "DROP"}) {
		t.Fatalf("BYPATH_FWD does not end with the fail-closed DROP: %v", rules)
	}
}

// TestCrashRestartKeepsContainmentAndForwarding models a SIGKILL: recovery must
// reverse the data path without touching the firewall containment or resetting
// forwarding owned mid-run. The subsequent start adopts the containment.
func TestCrashRestartKeepsContainmentAndForwarding(t *testing.T) {
	isolateHostState(t)
	enableContainmentHost(t)
	scratchResolver(t)
	setHostForwarding(t, "1")

	fw := newContainmentFirewall(t)
	fw.stub(t)
	oldPkill := pkillCommand
	pkillCommand = func(string) {}
	t.Cleanup(func() { pkillCommand = oldPkill })
	fw.requireContainment = true
	seedRunningGateway(fw, "eth0")

	st, err := markGatewayState("legacy")
	if err != nil {
		t.Fatalf("markGatewayState: %v", err)
	}
	st.ForwardingWasOff = true
	st.V6Isolated = true
	st.ContainmentRetained = true
	st.ContainmentIface = "eth0"
	st.Routes = [][]string{{"route", "add", "default", "via", "10.0.0.1", "dev", "tun0", "table", "100"}}
	fw.routes = append(fw.routes, append([]string(nil), st.Routes[0]...))
	if err := saveGatewayState(st); err != nil {
		t.Fatalf("saveGatewayState: %v", err)
	}

	gw := &Gateway{
		config: &config.Config{Gateway: config.GatewayConfig{Enabled: true}},
		iface:  "eth0",
		subnet: "10.1.0.0/24",
	}
	if err := gw.cleanupPreviousRun(); err != nil {
		t.Fatalf("crash recovery: %v", err)
	}

	joined := strings.Join(fw.calls, "\n")
	for _, forbidden := range []string{
		"-F " + chainForward,
		"-D FORWARD -j " + chainForward,
		"-D FORWARD -j " + chainV6Drop,
		"sysctl -w net.ipv4.ip_forward=0",
	} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("crash recovery touched containment or forwarding ownership: %q\n%s", forbidden, joined)
		}
	}
	if !strings.Contains(joined, "ip route del default via 10.0.0.1 dev tun0 table 100") {
		t.Errorf("crash recovery did not reverse the stale data-path route:\n%s", joined)
	}
	kept := gatewayState()
	if kept == nil || !kept.ForwardingWasOff || !kept.V6Isolated || !kept.ContainmentRetained {
		t.Fatalf("ownership record = %+v, want forwarding, IPv6 and containment ownership retained", kept)
	}

	// The restart adopts the retained state; the guard closes the rebuild window
	// the same way a first start does.
	if err := gw.setupRouting(); err != nil {
		t.Fatalf("restart setupRouting: %v", err)
	}
	if got := fw.firstJump("iptables", "filter", "FORWARD"); got != chainForward {
		t.Fatalf("first FORWARD jump = %q, want %q after restart", got, chainForward)
	}
	if got := fw.firstJump("ip6tables", "filter", "FORWARD"); got != chainV6Drop {
		t.Fatalf("first IPv6 FORWARD jump = %q, want %q after restart", got, chainV6Drop)
	}
	adopted := gatewayState()
	if adopted == nil {
		t.Fatal("restart lost the ownership record before setup completed")
	}
	if adopted.ContainmentRetained || adopted.ContainmentIface != "" {
		t.Fatalf("adopted containment was not cleared: %+v", adopted)
	}
}

// TestStopRetainsContainmentWhenForwardingIsForeign proves a clean stop on a
// host where Docker/libvirt keeps ip_forward=1 leaves the fail-closed DROP
// policy in place and never disables that foreign forwarding. Only an explicit
// teardown may remove it.
func TestStopRetainsContainmentWhenForwardingIsForeign(t *testing.T) {
	isolateHostState(t)
	enableContainmentHost(t)
	setHostForwarding(t, "1")

	fw := newContainmentFirewall(t)
	fw.stub(t)
	seedRunningGateway(fw, "eth0")

	st := &gatewayRunState{Version: gatewayStateVersion, Mode: "legacy", V6Isolated: true}
	if err := saveGatewayState(st); err != nil {
		t.Fatalf("saveGatewayState: %v", err)
	}
	gw := &Gateway{
		config: &config.Config{Gateway: config.GatewayConfig{Enabled: true}},
		iface:  "eth0",
		run:    st,
	}
	gw.networkMutated = true
	if err := gw.cleanupRouting(); err != nil {
		t.Fatalf("cleanupRouting: %v", err)
	}

	joined := strings.Join(fw.calls, "\n")
	if strings.Contains(joined, "sysctl -w net.ipv4.ip_forward=0") {
		t.Errorf("stop disabled forwarding owned by another service:\n%s", joined)
	}
	if strings.Contains(joined, "-F "+chainForward) || strings.Contains(joined, "-F "+chainV6Drop) {
		t.Errorf("stop flushed the retained fail-closed chains:\n%s", joined)
	}
	for _, tc := range []struct{ table, chain string }{
		{"nat", chainDNS},
		{"nat", chainNat},
		{"mangle", chainMangle},
		{"filter", chainGuard},
	} {
		if _, ok := fw.rules[fwKey("iptables", tc.table, tc.chain)]; ok {
			t.Errorf("intercept chain %s survived the stop", tc.chain)
		}
	}
	if got := fw.firstJump("iptables", "filter", "FORWARD"); got != chainForward {
		t.Fatalf("retained IPv4 containment is not first: %q", got)
	}
	if got := fw.firstJump("ip6tables", "filter", "FORWARD"); got != chainV6Drop {
		t.Fatalf("retained IPv6 containment is not first: %q", got)
	}
	if !fw.hasRule("iptables", "filter", chainForward, "-i", "eth0", "-j", "DROP") {
		t.Fatal("retained FORWARD chain lost its fail-closed DROP rule")
	}
	retained := gatewayState()
	if retained == nil || !retained.ContainmentRetained || retained.ContainmentIface != "eth0" {
		t.Fatalf("ownership record = %+v, want retained containment on eth0", retained)
	}

	// Only an explicit purge owns the retained chains and removes them.
	fw.requireContainment = false
	if err := PurgePersistedState(); err != nil {
		t.Fatalf("explicit teardown: %v", err)
	}
	if _, ok := fw.rules[fwKey("iptables", "filter", chainForward)]; ok {
		t.Fatal("explicit teardown left BYPATH_FWD behind")
	}
	if _, ok := fw.rules[fwKey("ip6tables", "filter", chainV6Drop)]; ok {
		t.Fatal("explicit teardown left BYPATH_V6 behind")
	}
	if gatewayState() != nil {
		t.Fatal("explicit teardown left an ownership record")
	}
}

// TestStopCleanupKeepsContainmentWhenForwardingIsForeign proves the stop
// contract for a crashed run whose record has no interface: the default
// external cleanup must keep the installed fail-closed chains instead of
// forwarding LAN clients directly. Only PurgePersistedState may remove them.
func TestStopCleanupKeepsContainmentWhenForwardingIsForeign(t *testing.T) {
	isolateHostState(t)
	enableContainmentHost(t)
	setHostForwarding(t, "1")

	fw := newContainmentFirewall(t)
	fw.stub(t)
	seedRunningGateway(fw, "eth0")
	oldPkill := pkillCommand
	pkillCommand = func(string) {}
	t.Cleanup(func() { pkillCommand = oldPkill })
	fw.requireContainment = true

	// A SIGKILLed run leaves a complete record but never records the interface
	// or the retained-containment flag.
	st := &gatewayRunState{Version: gatewayStateVersion, Mode: "legacy", V6Isolated: true}
	if err := saveGatewayState(st); err != nil {
		t.Fatalf("saveGatewayState: %v", err)
	}

	if err := CleanupPersistedState(); err != nil {
		t.Fatalf("default stop cleanup: %v", err)
	}
	if !fw.hasJump("iptables", "filter", "FORWARD", chainForward) {
		t.Fatal("default stop cleanup removed the fail-closed IPv4 jump")
	}
	if !fw.hasRule("iptables", "filter", chainForward, "-i", "eth0", "-j", "DROP") {
		t.Fatal("default stop cleanup lost the fail-closed DROP rule")
	}
	if got := fw.firstJump("iptables", "filter", "FORWARD"); got != chainForward {
		t.Fatalf("retained IPv4 containment is not first: %q", got)
	}
	if got := fw.firstJump("ip6tables", "filter", "FORWARD"); got != chainV6Drop {
		t.Fatalf("retained IPv6 containment is not first: %q", got)
	}
	for _, tc := range []struct{ table, chain string }{
		{"nat", chainDNS},
		{"nat", chainNat},
		{"mangle", chainMangle},
		{"filter", chainGuard},
	} {
		if _, ok := fw.rules[fwKey("iptables", tc.table, tc.chain)]; ok {
			t.Errorf("intercept chain %s survived the stop", tc.chain)
		}
	}
	kept := gatewayState()
	if kept == nil || !kept.ContainmentRetained || kept.ContainmentIface != "eth0" {
		t.Fatalf("ownership record = %+v, want retained containment on eth0", kept)
	}
	if !RetainedContainment() {
		t.Fatal("RetainedContainment did not report the kept containment")
	}

	// The operator's explicit purge is the only path that removes it.
	fw.requireContainment = false
	if err := PurgePersistedState(); err != nil {
		t.Fatalf("explicit purge: %v", err)
	}
	if fw.hasJump("iptables", "filter", "FORWARD", chainForward) {
		t.Fatal("explicit purge left the IPv4 containment jump")
	}
	if fw.hasJump("ip6tables", "filter", "FORWARD", chainV6Drop) {
		t.Fatal("explicit purge left the IPv6 containment jump")
	}
	if gatewayState() != nil {
		t.Fatal("explicit purge left an ownership record")
	}
	if RetainedContainment() {
		t.Fatal("RetainedContainment still reported containment after the purge")
	}
}

// TestUndoKeepsContainmentWhenForwardingRestoreFails proves the teardown order:
// when bypath owned forwarding but cannot turn it off, the fail-closed chains
// stay installed instead of leaving an uncontained forwarding host behind.
func TestUndoKeepsContainmentWhenForwardingRestoreFails(t *testing.T) {
	isolateHostState(t)
	enableContainmentHost(t)
	setHostForwarding(t, "1")

	fw := newContainmentFirewall(t)
	fw.stub(t)
	fw.failSysctl = true
	seedRunningGateway(fw, "eth0")

	st := &gatewayRunState{Version: gatewayStateVersion, Mode: "legacy", ForwardingWasOff: true, V6Isolated: true}
	if err := saveGatewayState(st); err != nil {
		t.Fatalf("saveGatewayState: %v", err)
	}
	loaded := gatewayState()
	if err := (&Gateway{}).undoNetworkState(loaded); err == nil {
		t.Fatal("undo reported success although forwarding could not be restored")
	}
	if !fw.hasJump("iptables", "filter", "FORWARD", chainForward) {
		t.Fatal("containment was removed while forwarding remained enabled")
	}
	kept := gatewayState()
	if kept == nil || !kept.ForwardingWasOff {
		t.Fatalf("ownership record = %+v, want the forwarding ownership kept for the next attempt", kept)
	}
}

// TestStopRemovesContainmentWhenForwardingWasOwned proves the inverse: when
// bypath itself enabled forwarding, stop restores it to 0 before deleting the
// chains, so teardown leaves no permanent firewall, routing or sysctl change.
func TestStopRemovesContainmentWhenForwardingWasOwned(t *testing.T) {
	isolateHostState(t)
	enableContainmentHost(t)
	setHostForwarding(t, "0")

	fw := newContainmentFirewall(t)
	fw.stub(t)
	seedRunningGateway(fw, "eth0")

	st := &gatewayRunState{Version: gatewayStateVersion, Mode: "legacy", V6Isolated: true, ForwardingWasOff: true}
	if err := saveGatewayState(st); err != nil {
		t.Fatalf("saveGatewayState: %v", err)
	}
	gw := &Gateway{
		config: &config.Config{Gateway: config.GatewayConfig{Enabled: true}},
		iface:  "eth0",
		run:    st,
	}
	gw.networkMutated = true
	if err := gw.cleanupRouting(); err != nil {
		t.Fatalf("cleanupRouting: %v", err)
	}

	joined := strings.Join(fw.calls, "\n")
	sysctlAt := strings.Index(joined, "sysctl -w net.ipv4.ip_forward=0")
	chainDelAt := strings.Index(joined, "-D FORWARD -j "+chainForward)
	if sysctlAt < 0 {
		t.Fatalf("stop did not restore forwarding:\n%s", joined)
	}
	if chainDelAt < 0 || sysctlAt > chainDelAt {
		t.Fatalf("containment was removed before forwarding was restored:\n%s", joined)
	}
	if _, ok := fw.rules[fwKey("iptables", "filter", chainForward)]; ok {
		t.Fatal("stop left BYPATH_FWD behind although bypath owned forwarding")
	}
	if _, ok := fw.rules[fwKey("ip6tables", "filter", chainV6Drop)]; ok {
		t.Fatal("stop left BYPATH_V6 behind although bypath owned forwarding")
	}
	if gatewayState() != nil {
		t.Fatal("complete teardown left an ownership record")
	}
}

// TestNamespacedRunLeavesHostResolverUntouched proves a network-namespaced run
// never rewrites the shared mount namespace's resolver or hosts file and never
// stops host resolver services: those belong to the host, while bypath's DNS
// listener only exists in its private network stack.
func TestNamespacedRunLeavesHostResolverUntouched(t *testing.T) {
	isolateHostState(t)
	resolv := scratchResolver(t)
	oldNetNS := networkNamespaceIsolated
	networkNamespaceIsolated = func() bool { return true }
	t.Cleanup(func() { networkNamespaceIsolated = oldNetNS })

	before, err := os.ReadFile(resolv)
	if err != nil {
		t.Fatalf("reading seeded resolver: %v", err)
	}
	hosts := "# host file\n127.0.0.1 localhost\n"
	if err := os.WriteFile(hostsFilePath, []byte(hosts), 0644); err != nil {
		t.Fatalf("seeding hosts file: %v", err)
	}

	var systemctlCalls []string
	oldOut, oldRun := systemctlOutput, systemctlRun
	systemctlOutput = func(args ...string) ([]byte, error) {
		systemctlCalls = append(systemctlCalls, "output "+strings.Join(args, " "))
		return []byte("active\n"), nil
	}
	systemctlRun = func(args ...string) error {
		systemctlCalls = append(systemctlCalls, "run "+strings.Join(args, " "))
		return nil
	}
	t.Cleanup(func() { systemctlOutput, systemctlRun = oldOut, oldRun })

	gw := &Gateway{config: &config.Config{}}
	if err := gw.setResolvConf("127.0.0.1"); err != nil {
		t.Fatalf("setResolvConf: %v", err)
	}
	if stopped, err := gw.disableSystemdResolved(); err != nil || stopped {
		t.Fatalf("disableSystemdResolved = %v, %v; want no host service change", stopped, err)
	}
	if err := gw.stopDnsmasq(); err != nil {
		t.Fatalf("stopDnsmasq: %v", err)
	}
	if _, err := gw.pinHostToEtcHosts("vpn.example.test"); err != nil {
		t.Fatalf("pinHostToEtcHosts: %v", err)
	}

	after, err := os.ReadFile(resolv)
	if err != nil {
		t.Fatalf("re-reading resolver: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("namespaced run rewrote the host resolver: %q", after)
	}
	hostsAfter, err := os.ReadFile(hostsFilePath)
	if err != nil {
		t.Fatalf("re-reading hosts file: %v", err)
	}
	if string(hostsAfter) != hosts {
		t.Fatalf("namespaced run rewrote the host hosts file: %q", hostsAfter)
	}
	if len(systemctlCalls) != 0 {
		t.Fatalf("namespaced run touched host resolver services: %v", systemctlCalls)
	}
	if gatewayState() != nil {
		t.Fatalf("namespaced run claimed ownership of host resolver state: %+v", gatewayState())
	}
}

func TestMountPointListed(t *testing.T) {
	dir := t.TempDir()
	table := strings.Join([]string{
		`36 35 98:0 /mnt1 / rw,noatime - ext3 /dev/root rw`,
		`37 36 0:32 / /etc/resolv.conf rw,nosuid - tmpfs resolv rw`,
		`38 36 0:33 / /var/lib/docker/containers rw - none none rw`,
	}, "\n")
	path := filepath.Join(dir, "mountinfo")
	if err := os.WriteFile(path, []byte(table), 0644); err != nil {
		t.Fatal(err)
	}
	if !mountPointListed(path, "/etc/resolv.conf") {
		t.Fatal("bind-mounted resolver was not detected")
	}
	if !mountPointListed(path, "/") {
		t.Fatal("root mount was not detected")
	}
	if mountPointListed(path, "/etc/hosts") {
		t.Fatal("an unlisted path was reported as a mount point")
	}
	if mountPointListed(filepath.Join(dir, "missing"), "/etc/resolv.conf") {
		t.Fatal("a missing mountinfo must not report mount points")
	}
}

func TestChainExistsTreatsBackendQuirkAsAbsent(t *testing.T) {
	old := outputCommand
	outputCommand = func(string, ...string) ([]byte, error) {
		return []byte("iptables: Incompatible with this kernel."), errors.New("exit status 1")
	}
	t.Cleanup(func() { outputCommand = old })

	exists, err := chainExists("nat", "BYPATH_NAT")
	if err != nil || exists {
		t.Fatalf("chainExists = %t, %v; want false, nil for an absent chain", exists, err)
	}
}
