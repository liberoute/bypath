//go:build linux

package proxyguard

// Regression tests for the two release-blocking defects found by the
// independent security review:
//
//	D1  a stop command deleted the guard of a daemon that had already restarted
//	D2  a loopback-only proxy required iptables access at startup
//
// Every interleaving here is deterministic: the guard lock, not timing, decides
// which run owns the firewall.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/config"
)

func loopbackConfig() *config.Config {
	return &config.Config{Server: config.ServerConfig{SOCKSPort: 2901, SOCKSListen: "127.0.0.1"}}
}

// holdGuardLock represents another bypath process that owns the guard. flock
// locks are per open file description, so a second descriptor in this test
// contends with the daemon exactly like a second process does. The returned
// function releases it early; it is always released at test cleanup.
func holdGuardLock(t *testing.T) func() {
	t.Helper()
	f, err := lockGuard(0)
	if err != nil {
		t.Fatalf("could not take the guard lock for the test: %v", err)
	}
	done := false
	release := func() {
		if done {
			return
		}
		done = true
		unlockGuard(f)
	}
	t.Cleanup(release)
	return release
}

func guardInstalled(f *firewall, jumps int) bool {
	if _, ok := f.chains[chain]; !ok {
		return false
	}
	if len(f.chains["INPUT"]) != jumps {
		return false
	}
	return len(f.chains[chain]) > 0
}

// D1, Docker Compose style: the replacement daemon is already serving when the
// old stop command reaches its cleanup step. The guard must stay installed.
func TestImmediateRestartIsNeverDisarmedByTheStoppedRun(t *testing.T) {
	f := setup(t)
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	tokenA := RecordToken()
	if tokenA == "" {
		t.Fatal("first run did not record a guard")
	}

	releaseHeld() // run A is killed; the supervisor restarts it at once
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	tokenB := RecordToken()
	if tokenB == "" || tokenB == tokenA {
		t.Fatalf("replacement run did not record its own guard: %q", tokenB)
	}
	rules := strings.Join(f.chains[chain], "\n")

	// The replacement is alive and holds the guard for its whole lifetime.
	releaseHeld()
	holdGuardLock(t)

	if err := CleanupOwned(tokenA); !errors.Is(err, ErrGuardBusy) {
		t.Fatalf("stop removed a running replacement's guard: %v", err)
	}
	if !guardInstalled(f, 2) || strings.Join(f.chains[chain], "\n") != rules {
		t.Fatal("replacement guard was modified by the stopped run's cleanup")
	}
	if RecordToken() != tokenB {
		t.Fatal("replacement ownership record was deleted")
	}
}

// D1, delayed stop: the replacement started and then died before the old stop
// command resumed. A token comparison alone must not delete its guard.
func TestLateStopCannotDeleteAnExitedReplacementGuard(t *testing.T) {
	f := setup(t)
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	tokenA := RecordToken()

	releaseHeld() // run A is SIGKILLed
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	tokenB := RecordToken()
	releaseHeld() // replacement B is SIGKILLed too, still holding its guard
	rules := strings.Join(f.chains[chain], "\n")

	if err := CleanupOwned(tokenA); !errors.Is(err, ErrGuardReplaced) {
		t.Fatalf("stop deleted a replacement's guard: %v", err)
	}
	if !guardInstalled(f, 2) || strings.Join(f.chains[chain], "\n") != rules {
		t.Fatal("replacement guard was modified")
	}
	if RecordToken() != tokenB {
		t.Fatal("replacement ownership record was deleted")
	}

	// A stop bound to the run that actually owns the guard still completes it.
	if err := CleanupOwned(tokenB); err != nil {
		t.Fatal(err)
	}
	requireNoGuard(t, f)
}

// A token sampled before any guard existed must never authorize deleting one
// that appeared afterwards.
func TestStopWithoutSampledGuardNeverDeletesAnArmedGuard(t *testing.T) {
	f := setup(t)
	releaseHeld()
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	releaseHeld()
	if err := CleanupOwned(""); !errors.Is(err, ErrGuardReplaced) {
		t.Fatalf("unbound stop removed an armed guard: %v", err)
	}
	if !guardInstalled(f, 2) {
		t.Fatal("armed guard was modified")
	}
}

// D1, systemd style: the restart comes after the stop command finished. The old
// guard is removed by the stopped run's own token, and the next start installs
// a fresh guard instead of refusing to start.
func TestDelayedRestartStartsFromACleanGuard(t *testing.T) {
	f := setup(t)
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	tokenA := RecordToken()

	releaseHeld() // SIGKILL, so the daemon's own cleanup never ran
	if err := CleanupOwned(tokenA); err != nil {
		t.Fatalf("stop could not remove the stopped run's guard: %v", err)
	}
	requireNoGuard(t, f)

	if err := Ensure(lanConfig()); err != nil {
		t.Fatalf("delayed restart refused to start: %v", err)
	}
	if !guardInstalled(f, 2) || RecordToken() == tokenA {
		t.Fatal("restart did not install its own guard")
	}
}

// A second start must refuse while another process owns the guard, and it must
// not touch the firewall before that is resolved.
func TestConcurrentStartRefusesWithoutTouchingTheFirewall(t *testing.T) {
	f := setup(t)
	holdGuardLock(t)
	if err := Ensure(lanConfig()); !errors.Is(err, ErrGuardBusy) {
		t.Fatalf("concurrent start was not refused: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("concurrent start ran firewall commands: %v", f.calls)
	}
}

// D2: a loopback-only listener needs no guard, so root without NET_ADMIN must
// start it without running a single iptables command.
func TestLoopbackStartNeedsNoFirewallAccess(t *testing.T) {
	f := setup(t)
	calls := 0
	Command = func(context.Context, ...string) ([]byte, error) {
		calls++
		return nil, errors.New("iptables: Permission denied (you must be root)")
	}
	if err := Ensure(loopbackConfig()); err != nil {
		t.Fatalf("loopback start required firewall access: %v", err)
	}
	if calls != 0 {
		t.Fatalf("loopback start ran %d firewall commands", calls)
	}
	rootUID = func() int { return 1000 }
	if err := Ensure(loopbackConfig()); err != nil {
		t.Fatalf("unprivileged loopback start failed: %v", err)
	}
	if calls != 0 || len(f.calls) != 0 {
		t.Fatal("loopback start touched the firewall")
	}
}

// D2: a foreign chain is never touched by a loopback start, and it still blocks
// a LAN-exposed start.
func TestLoopbackRestartLeavesAForeignChainAlone(t *testing.T) {
	f := setup(t)
	f.chains[chain] = []string{"-j ACCEPT"}
	if err := Ensure(loopbackConfig()); err != nil {
		t.Fatalf("loopback start failed with an unrelated chain present: %v", err)
	}
	if len(f.chains[chain]) != 1 || f.chains[chain][0] != "-j ACCEPT" {
		t.Fatal("loopback start modified a foreign chain")
	}
	if err := Ensure(lanConfig()); err == nil {
		t.Fatal("LAN start adopted a foreign chain")
	}
	if len(f.chains[chain]) != 1 || f.chains[chain][0] != "-j ACCEPT" {
		t.Fatal("LAN start modified a foreign chain")
	}
}

// D2 transition: restarting in loopback mode must keep the previous LAN guard
// installed (fail closed), and a stop bound to that guard still removes it.
func TestLANToLoopbackRestartKeepsContainment(t *testing.T) {
	f := setup(t)
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	token := RecordToken()
	releaseHeld() // the daemon restarts with a loopback-only configuration
	f.calls = nil

	if err := Ensure(loopbackConfig()); err != nil {
		t.Fatalf("loopback restart failed: %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("loopback restart ran firewall commands: %v", f.calls)
	}
	if !guardInstalled(f, 2) || RecordToken() != token {
		t.Fatal("loopback restart disarmed the previous LAN guard")
	}
	if err := CleanupOwned(token); err != nil {
		t.Fatalf("stop could not remove the retained guard: %v", err)
	}
	requireNoGuard(t, f)
}

// A LAN-exposed daemon keeps its containment through a failed stop attempt and
// an interrupted cleanup; the record is never deleted while the chain is armed.
func TestRunningGuardSurvivesInterruptedStopAndCleanup(t *testing.T) {
	f := setup(t)
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	token := RecordToken()
	releaseHeld() // the daemon keeps its lease in its own process
	release := holdGuardLock(t)

	if err := CleanupOwned(token); !errors.Is(err, ErrGuardBusy) {
		t.Fatalf("stop removed a running guard: %v", err)
	}
	if !guardInstalled(f, 2) {
		t.Fatal("running guard was modified")
	}
	release()

	f.fail = "-X " + chain
	if err := Cleanup(); err == nil {
		t.Fatal("interrupted cleanup claimed success")
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatal("ownership record deleted while the chain survived")
	}
	f.fail = ""
	if err := Cleanup(); err != nil {
		t.Fatalf("cleanup did not recover: %v", err)
	}
	requireNoGuard(t, f)
}
