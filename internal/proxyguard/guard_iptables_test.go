//go:build linux

package proxyguard

// Real-iptables lifecycle tests. They mutate only this network namespace's
// INPUT chain and a private state directory, so they run inside a disposable
// privileged container:
//
//	docker run --rm --privileged -e BYPATH_GUARD_IPTABLES=1 \
//	    -v "$PWD:/src" -w /src golang:1.26 go test ./internal/proxyguard -run IPTables -v
//
// Nothing here contacts a provider, a tunnel, or the network beyond spawning
// the local iptables binary.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/config"
)

func iptablesTests(t *testing.T) {
	t.Helper()
	if os.Getenv("BYPATH_GUARD_IPTABLES") != "1" {
		t.Skip("set BYPATH_GUARD_IPTABLES=1 in a disposable privileged namespace")
	}
	if os.Geteuid() != 0 {
		t.Skip("real iptables tests require root")
	}
	if _, err := exec.LookPath("/usr/sbin/iptables"); err != nil {
		t.Skip("/usr/sbin/iptables not installed")
	}
}

// iptablesConfig binds the wildcard proxy on a private port; the trusted LAN is
// discovered from the container interface the same way a real host discovers it.
func iptablesConfig() *config.Config {
	cfg := &config.Config{Server: config.ServerConfig{
		SOCKSPort: 29123, SOCKSListen: "0.0.0.0", SOCKSAllowLAN: true,
	}}
	cfg.Gateway.Enabled = true
	return cfg
}

// iptablesState points the guard at a root-owned private directory and returns
// a reset helper that leaves no chain, jump or record behind even after a
// deliberately broken test.
func iptablesState(t *testing.T) string {
	t.Helper()
	old := statePath
	dir := filepath.Join("/var/lib", fmt.Sprintf("bypath-guard-test-%d", os.Getpid()))
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	statePath = filepath.Join(dir, "proxy-input.json")
	t.Cleanup(func() {
		forceGuardCleanup()
		statePath = old
		os.RemoveAll(dir)
	})
	forceGuardCleanup()
	return statePath
}

// forceGuardCleanup is test-only surgery. It removes the guard objects even
// when ownership cannot be proven, so one failing test cannot poison the next.
func forceGuardCleanup() {
	releaseHeld()
	out, _ := run("-S")
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "-A" || f[len(f)-1] != chain {
			continue
		}
		run(append([]string{"-D", f[1]}, f[2:]...)...)
	}
	if _, err := run("-S", chain); err == nil {
		run("-F", chain)
		run("-X", chain)
	}
	os.Remove(statePath)
	os.Remove(lockPath())
}

func guardPresent(t *testing.T) (rules int, jumps int) {
	t.Helper()
	out, err := run("-S", chain)
	if err != nil {
		return 0, 0
	}
	rules = len(chainRules(out))
	all, err := run("-S")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(all), "\n") {
		f := strings.Fields(line)
		if len(f) > 2 && f[0] == "-A" && f[len(f)-1] == chain && f[1] == "INPUT" {
			jumps++
		}
	}
	return rules, jumps
}

func requireClean(t *testing.T) {
	t.Helper()
	rules, jumps := guardPresent(t)
	if rules != 0 || jumps != 0 {
		t.Fatalf("guard leftovers: rules=%d jumps=%d", rules, jumps)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("ownership record survived: %v", err)
	}
}

func TestIPTablesLifecycleIsIdempotent(t *testing.T) {
	iptablesTests(t)
	iptablesState(t)
	for i := 0; i < 5; i++ {
		if err := Ensure(iptablesConfig()); err != nil {
			t.Fatalf("cycle %d Ensure: %v", i, err)
		}
		rules, jumps := guardPresent(t)
		if rules != 4 || jumps != 2 {
			t.Fatalf("cycle %d installed rules=%d jumps=%d", i, rules, jumps)
		}
		if err := Cleanup(); err != nil {
			t.Fatalf("cycle %d Cleanup: %v", i, err)
		}
		requireClean(t)
		if err := Cleanup(); err != nil {
			t.Fatalf("cycle %d second Cleanup must be a no-op: %v", i, err)
		}
	}
}

// Deleting the ownership record while the daemon is down must not strand the
// chain: the chain itself carries the marker and the exact guard shape, which is
// enough to adopt and remove it before installing a fresh guard.
func TestIPTablesOrphanWithoutRecordRecovers(t *testing.T) {
	iptablesTests(t)
	state := iptablesState(t)
	if err := Ensure(iptablesConfig()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(iptablesConfig()); err != nil {
		t.Fatalf("restart over an orphaned chain: %v", err)
	}
	if err := Cleanup(); err != nil {
		t.Fatal(err)
	}
	requireClean(t)
}

// A crash between installing individual rules leaves a recorded but incomplete
// chain. Startup must roll that back instead of refusing for the rest of the
// host's life.
func TestIPTablesInterruptedInstallRecovers(t *testing.T) {
	iptablesTests(t)
	iptablesState(t)
	if err := Ensure(iptablesConfig()); err != nil {
		t.Fatal(err)
	}
	out, err := run("-S", chain)
	if err != nil {
		t.Fatal(err)
	}
	lines := chainRules(out)
	if len(lines) != 4 {
		t.Fatalf("chain rules = %d", len(lines))
	}
	last := strings.Fields(lines[3])
	if _, err := run(append([]string{"-D", chain}, last[2:]...)...); err != nil {
		t.Fatal(err)
	}
	if _, err := run("-D", "INPUT", "-p", "udp", "--dport", "29123", "-m", "comment", "--comment", currentToken(t), "-j", chain); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(iptablesConfig()); err != nil {
		t.Fatalf("restart over an interrupted install: %v", err)
	}
	if err := Cleanup(); err != nil {
		t.Fatal(err)
	}
	requireClean(t)
}

func currentToken(t *testing.T) string {
	t.Helper()
	r, err := load()
	if err != nil {
		t.Fatal(err)
	}
	return r.Token
}

// A chain rule without our marker is foreign: it must survive and must block
// startup, whatever else the chain contains.
func TestIPTablesForeignRuleIsRetained(t *testing.T) {
	iptablesTests(t)
	state := iptablesState(t)
	if err := Ensure(iptablesConfig()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	if _, err := run("-A", chain, "-j", "ACCEPT"); err != nil {
		t.Fatal(err)
	}
	err := Ensure(iptablesConfig())
	if err == nil || !strings.Contains(err.Error(), "unverified") {
		t.Fatalf("foreign rule accepted: %v", err)
	}
	rules, _ := guardPresent(t)
	if rules != 5 {
		t.Fatalf("foreign rule was deleted: rules=%d", rules)
	}
	forceGuardCleanup()
}

// An INPUT jump into the guard chain that carries no marker is equally foreign.
func TestIPTablesForeignJumpIsRetained(t *testing.T) {
	iptablesTests(t)
	state := iptablesState(t)
	if err := Ensure(iptablesConfig()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	if _, err := run("-I", "INPUT", "1", "-p", "tcp", "--dport", "9999", "-j", chain); err != nil {
		t.Fatal(err)
	}
	err := Ensure(iptablesConfig())
	if err == nil || !strings.Contains(err.Error(), "unverified") {
		t.Fatalf("foreign jump accepted: %v", err)
	}
	_, jumps := guardPresent(t)
	if jumps != 3 {
		t.Fatalf("foreign jump was deleted: jumps=%d", jumps)
	}
	forceGuardCleanup()
}

// SIGKILL at an arbitrary point of startup or shutdown, repeated; the next
// start must always recover exactly like a service restart after a crash.
func TestIPTablesCrashRestartLoop(t *testing.T) {
	iptablesTests(t)
	iptablesState(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	roles := []string{"run", "stop"}
	var delays []time.Duration
	for d := time.Duration(0); d <= 60*time.Millisecond; d += 3 * time.Millisecond {
		delays = append(delays, d)
	}
	for i, delay := range delays {
		role := roles[i%2]
		cmd := exec.Command(exe, "-test.run=TestGuardCrashChild", "-test.v=false")
		cmd.Env = append(os.Environ(),
			"BYPATH_GUARD_IPTABLES=1",
			"GUARD_CRASH_CHILD=1",
			"GUARD_CHILD_ROLE="+role,
			"GUARD_STATE_PATH="+statePath,
		)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(delay)
		cmd.Process.Kill()
		cmd.Wait()
		if err := Ensure(iptablesConfig()); err != nil {
			t.Fatalf("recovery after killed %s at %v: %v", role, delay, err)
		}
		if err := Cleanup(); err != nil {
			t.Fatalf("cleanup after killed %s at %v: %v", role, delay, err)
		}
		requireClean(t)
	}
}

func TestGuardCrashChild(t *testing.T) {
	if os.Getenv("GUARD_CRASH_CHILD") != "1" {
		t.Skip("helper process")
	}
	statePath = os.Getenv("GUARD_STATE_PATH")
	if err := Ensure(iptablesConfig()); err != nil {
		os.Exit(3)
	}
	if os.Getenv("GUARD_CHILD_ROLE") == "stop" {
		_ = Cleanup()
	}
	os.Exit(0)
}

// A daemon killed after a complete install leaves its record and chain behind;
// the next start must recycle that guard rather than refuse it as foreign.
func TestIPTablesRestartWithoutStop(t *testing.T) {
	iptablesTests(t)
	iptablesState(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		cmd := exec.Command(exe, "-test.run=TestGuardCrashChild", "-test.v=false")
		cmd.Env = append(os.Environ(),
			"BYPATH_GUARD_IPTABLES=1",
			"GUARD_CRASH_CHILD=1",
			"GUARD_CHILD_ROLE=run",
			"GUARD_STATE_PATH="+statePath,
		)
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		if err := Ensure(iptablesConfig()); err != nil {
			t.Fatalf("restart %d over an owned orphan: %v", i, err)
		}
		if err := Cleanup(); err != nil {
			t.Fatal(err)
		}
		requireClean(t)
	}
}
