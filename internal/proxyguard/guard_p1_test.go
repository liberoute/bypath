//go:build linux

package proxyguard

// P1 ownership regressions:
//
//	P1-A  the guard lock was a flock on a pathname, so unlinking and recreating
//	      that path yielded an independent lock for a second process
//	P1-B  a failed install called uninstall() even when chain creation itself
//	      had failed, and uninstall flushed whatever carried the chain name
//
// Every test here asserts the required behaviour. P1-A is now a kernel lease
// whose scope (the network namespace) is the scope of the iptables state it
// protects; P1-B rollbacks require the record's own token on every object.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestP1GuardChild is the second process used by the lock tests. It is a real
// child process, not a second lease in the test process, because the defect is
// about two processes acquiring two different locks.
func TestP1GuardChild(t *testing.T) {
	if os.Getenv("P1_GUARD_CHILD") != "1" {
		t.Skip("helper process")
	}
	statePath = os.Getenv("GUARD_STATE_PATH")
	switch err := Cleanup(); {
	case errors.Is(err, ErrGuardBusy):
		fmt.Println("P1-CHILD-BUSY")
		os.Exit(0)
	case err == nil:
		fmt.Println("P1-CHILD-ACTED")
		os.Exit(3)
	default:
		fmt.Println("P1-CHILD-ERROR", err)
		os.Exit(4)
	}
}

func p1Child(t *testing.T) (string, error) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestP1GuardChild$", "-test.v=false")
	cmd.Env = append(os.Environ(), "P1_GUARD_CHILD=1", "GUARD_STATE_PATH="+statePath)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// P1-A: a second process must never obtain the guard lease of a live run, even
// after the legacy lock file is unlinked and recreated. The record it would
// delete is the live run's ownership proof.
func TestP1SecondProcessCannotActAfterLockfileReplacement(t *testing.T) {
	setup(t)
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	defer releaseHeld()

	if err := os.Remove(lockPath()); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	out, _ := p1Child(t)
	if !strings.Contains(out, "P1-CHILD-BUSY") {
		t.Fatalf("second process was not excluded by the live lease: %s", out)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatal("live run's ownership record was deleted by a second process")
	}
}

// P1-A with the real firewall: the second process must not be able to remove
// the chain that protects a serving daemon.
func TestP1LiveGuardCannotBeDisarmedAfterLockfileReplacement(t *testing.T) {
	iptablesTests(t)
	iptablesState(t)
	if err := Ensure(iptablesConfig()); err != nil {
		t.Fatal(err)
	}
	defer releaseHeld()

	if err := os.Remove(lockPath()); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	out, _ := p1Child(t)
	if !strings.Contains(out, "P1-CHILD-BUSY") {
		t.Fatalf("second process disarmed a live guard: %s", out)
	}
	if _, err := run("-S", chain); err != nil {
		t.Fatal("live guard chain was removed by a second process")
	}
}

// A lease taken in this process is a separate kernel object from a second lease,
// exactly like two processes; the legacy path plays no part in it.
func TestP1LeaseDoesNotDependOnTheLockFile(t *testing.T) {
	setup(t)
	l, err := lockGuard(0)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := os.Remove(lockPath()); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if _, err := lockGuard(0); !errors.Is(err, ErrGuardBusy) {
		t.Fatalf("second lease acquired after the lock file was removed: %v", err)
	}
}

// During an upgrade an older binary may still be running and hold only the
// pre-fix flock. That flock must still exclude a current build.
func TestP1LegacyFlockStillExcludes(t *testing.T) {
	setup(t)
	if err := os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(lockPath(), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if _, err := lockGuard(0); !errors.Is(err, ErrGuardBusy) {
		t.Fatalf("a pre-fix flock no longer excludes the current build: %v", err)
	}
}

// A record-free chain may only be adopted when the state directory pre-existed
// this process: a directory that had to be created belongs to a different mount,
// so what is installed there cannot be attributed to this process's bypath.
func TestP1RecordlessAdoptionRequiresSharedStateDir(t *testing.T) {
	f := setup(t)
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	releaseHeld()
	dir := filepath.Dir(statePath)
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := Cleanup(); !errors.Is(err, ErrGuardUnshared) {
		t.Fatalf("recordless adoption ran without a shared state directory: %v", err)
	}
	if !guardInstalled(f, 2) {
		t.Fatal("guard was modified without a shared state directory")
	}
}

// P1-B: chain creation failed because a foreign chain already carried the guard
// name. That chain must survive, and no ownership record may claim it.
func TestP1ChainCreationFailureKeepsForeignChain(t *testing.T) {
	f := setup(t)
	atomicWrite := writeState
	writeState = func(path string, b []byte) error {
		// The competing owner creates its chain between our inspection and our
		// creation attempt.
		f.chains[chain] = []string{"-j ACCEPT"}
		return atomicWrite(path, b)
	}
	t.Cleanup(func() { writeState = atomicWrite })

	if err := Ensure(lanConfig()); err == nil {
		t.Fatal("startup accepted a chain it did not create")
	}
	if got := strings.Join(f.chains[chain], "\n"); got != "-j ACCEPT" {
		t.Fatalf("foreign chain was modified by the failed install: %q", got)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatal("failed creation left an ownership record behind")
	}
}

// P1-B: the chain was created, a later step failed, and by the time rollback ran
// another writer had replaced the chain contents. Rollback must withhold.
func TestP1RollbackWithholdsWhenChainWasReplaced(t *testing.T) {
	f := setup(t)
	fake := Command
	replaced := false
	Command = func(ctx context.Context, args ...string) ([]byte, error) {
		if !replaced && len(args) > 3 && strings.HasPrefix(strings.Join(args[2:], " "), "-A "+chain+" -p udp") {
			replaced = true
			f.chains[chain] = []string{"-j ACCEPT"}
			return nil, errors.New("injected failure after a foreign replacement")
		}
		return fake(ctx, args...)
	}
	t.Cleanup(func() { Command = fake })

	if err := Ensure(lanConfig()); err == nil {
		t.Fatal("install failure was not reported")
	}
	if !replaced {
		t.Fatal("injection did not run")
	}
	if got := strings.Join(f.chains[chain], "\n"); got != "-j ACCEPT" {
		t.Fatalf("foreign replacement was deleted by rollback: %q", got)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatal("ownership record was deleted while a foreign chain remained")
	}
}

// P1-B: a foreign rule joined a partial install. Rollback must leave the chain
// and the record in place because ownership can no longer be proven.
func TestP1RollbackKeepsPartialInstallWithForeignAddition(t *testing.T) {
	f := setup(t)
	fake := Command
	added := false
	Command = func(ctx context.Context, args ...string) ([]byte, error) {
		if !added && len(args) > 3 && strings.HasPrefix(strings.Join(args[2:], " "), "-I INPUT 1") {
			added = true
			f.chains[chain] = append(f.chains[chain], "-j ACCEPT")
			return nil, errors.New("injected failure after a foreign rule was added")
		}
		return fake(ctx, args...)
	}
	t.Cleanup(func() { Command = fake })

	if err := Ensure(lanConfig()); err == nil {
		t.Fatal("install failure was not reported")
	}
	if !added {
		t.Fatal("injection did not run")
	}
	if got := strings.Join(f.chains[chain], "\n"); !strings.Contains(got, "-j ACCEPT") {
		t.Fatalf("foreign rule was deleted by rollback: %q", got)
	}
}

// P1-B: rollback of an unmodified partial install must still complete, so a
// failed start never requires manual firewall surgery.
func TestP1FailedInstallCleansUpItsOwnPartialChain(t *testing.T) {
	f := setup(t)
	fake := Command
	Command = func(ctx context.Context, args ...string) ([]byte, error) {
		if len(args) > 3 && strings.HasPrefix(strings.Join(args[2:], " "), "-I INPUT 1") {
			return nil, errors.New("injected jump failure")
		}
		return fake(ctx, args...)
	}
	t.Cleanup(func() { Command = fake })

	if err := Ensure(lanConfig()); err == nil {
		t.Fatal("install failure was not reported")
	}
	requireNoGuard(t, f)
}

// A chain is deleted only after a fresh listing shows it empty. A rule that
// appears while cleanup is running must keep the chain and the record.
func TestP1CleanupNeverFlushesAChangedChain(t *testing.T) {
	f := setup(t)
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	releaseHeld()
	fake := Command
	added := false
	Command = func(ctx context.Context, args ...string) ([]byte, error) {
		out, err := fake(ctx, args...)
		if !added && len(args) > 3 && args[2] == "-D" && args[3] == chain && err == nil {
			f.chains[chain] = append(f.chains[chain], "-j ACCEPT")
			added = true
		}
		return out, err
	}
	t.Cleanup(func() { Command = fake })

	if err := Cleanup(); err == nil {
		t.Fatal("cleanup deleted a chain that had gained an unverified rule")
	}
	if _, ok := f.chains[chain]; !ok {
		t.Fatal("chain was deleted without a verified empty listing")
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatal("ownership record was deleted while the chain survived")
	}
}

// P1-B with the real firewall: a chain that appeared between inspection and
// creation must survive the failed start.
func TestP1RealChainCreationFailureKeepsTheExistingChain(t *testing.T) {
	iptablesTests(t)
	iptablesState(t)
	realCommand := Command
	forced := false
	Command = func(ctx context.Context, args ...string) ([]byte, error) {
		if !forced && len(args) > 3 && args[2] == "-N" && args[3] == chain {
			forced = true
			realCommand(ctx, args...)
			realCommand(ctx, "-w", "3", "-A", chain, "-j", "ACCEPT")
			return []byte("iptables: Chain already exists."), errors.New("exit status 1")
		}
		return realCommand(ctx, args...)
	}
	defer func() { Command = realCommand }()

	if err := Ensure(iptablesConfig()); err == nil {
		t.Fatal("startup accepted a chain it did not create")
	}
	if !forced {
		t.Fatal("injection did not run")
	}
	out, err := run("-S", chain)
	if err != nil || !strings.Contains(string(out), "-j ACCEPT") {
		t.Fatalf("existing chain was removed by the failed install: %v %s", err, out)
	}
	forceGuardCleanup()
}

// TestP1NetnsLeaseHolder and TestP1NetnsLeaseProbe are used by the container
// scenario script. They touch nothing but the lease, so they are safe in a host
// network namespace.
func TestP1NetnsLeaseHolder(t *testing.T) {
	if os.Getenv("P1_NETNS_HOLD") != "1" {
		t.Skip("helper process")
	}
	l, err := lockGuard(0)
	if err != nil {
		fmt.Println("LEASE-ERROR", err)
		os.Exit(4)
	}
	defer l.Close()
	fmt.Println("LEASE-HELD")
	for i := 0; i < 300; i++ {
		time.Sleep(100 * time.Millisecond)
	}
}

func TestP1NetnsLeaseProbe(t *testing.T) {
	if os.Getenv("P1_NETNS_PROBE") != "1" {
		t.Skip("helper process")
	}
	l, err := lockGuard(0)
	if err == nil {
		l.Close()
		fmt.Println("LEASE-FREE")
		return
	}
	if errors.Is(err, ErrGuardBusy) {
		fmt.Println("LEASE-BUSY")
		return
	}
	fmt.Println("LEASE-ERROR", err)
	os.Exit(4)
}
