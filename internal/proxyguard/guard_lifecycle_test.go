//go:build linux

package proxyguard

// Fault-injection regressions for the guard lifecycle. Every state below was
// either observed on a production host or is reachable by killing the daemon at
// the named point; each one must recover without manual firewall surgery.

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func mutatedPlane(calls []string, plane string) bool {
	for _, call := range calls {
		f := strings.Fields(call)
		if len(f) < 2 || f[1] != plane {
			continue
		}
		switch f[0] {
		case "-A", "-I", "-D", "-F", "-X", "-N":
			return true
		}
	}
	return false
}

func requireNoGuard(t *testing.T, f *firewall) {
	t.Helper()
	if _, ok := f.chains[chain]; ok {
		t.Fatal("guard chain retained")
	}
	if len(f.chains["INPUT"]) != 0 {
		t.Fatal("guard jumps retained")
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatal("ownership record retained")
	}
}

// A failed rule or chain deletion must keep the record, because the record is
// what lets the next start finish the job.
func TestCleanupRetainsRecordWhenChainRemovalFails(t *testing.T) {
	for _, stage := range []string{"-D " + chain, "-X " + chain} {
		f := setup(t)
		if err := Ensure(lanConfig()); err != nil {
			t.Fatal(err)
		}
		f.fail = stage
		if err := Cleanup(); err == nil {
			t.Fatalf("%s: cleanup claimed success while the chain survived", stage)
		}
		if _, err := os.Stat(statePath); err != nil {
			t.Fatalf("%s: ownership record deleted with the chain still installed", stage)
		}
		f.fail = ""
		if err := Cleanup(); err != nil {
			t.Fatalf("%s: retry did not recover: %v", stage, err)
		}
		requireNoGuard(t, f)
	}
}

// A kill between two install steps leaves a strict subset of the recorded
// rules. That subset is still ours: the record names the token of every rule.
func TestCleanupRecoversInterruptedInstall(t *testing.T) {
	f := setup(t)
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	rules := f.chains[chain]
	f.chains[chain] = rules[:len(rules)-2]
	f.chains["INPUT"] = f.chains["INPUT"][1:]
	if err := Cleanup(); err != nil {
		t.Fatalf("cleanup after an interrupted install: %v", err)
	}
	requireNoGuard(t, f)
	if err := Ensure(lanConfig()); err != nil {
		t.Fatalf("restart after an interrupted install: %v", err)
	}
	if err := Cleanup(); err != nil {
		t.Fatal(err)
	}
	requireNoGuard(t, f)
}

// A pruning tool can remove the record while the daemon is down. The chain's
// name and shape are not proof: an independent state mount of the same host
// firewall shows exactly the same nothing, so a chain without its record is
// retained and the next start refuses.
func TestCleanupKeepsOrphanWithoutRecord(t *testing.T) {
	f := setup(t)
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	if err := Cleanup(); !errors.Is(err, ErrGuardUnshared) {
		t.Fatalf("recordless chain was not retained: %v", err)
	}
	if !guardInstalled(f, 2) {
		t.Fatal("recordless chain was modified")
	}
	if err := Ensure(lanConfig()); err == nil {
		t.Fatal("startup accepted a chain without its ownership record")
	}
}

func TestOrphanRefusesForeignRule(t *testing.T) {
	f := setup(t)
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	f.chains[chain] = append(f.chains[chain], "-j ACCEPT")
	err := Cleanup()
	if !errors.Is(err, ErrGuardUnshared) {
		t.Fatalf("recordless chain with a foreign rule was not retained: %v", err)
	}
	if len(f.chains[chain]) != 5 {
		t.Fatal("foreign rule was deleted")
	}
	if err := Ensure(lanConfig()); err == nil {
		t.Fatal("startup accepted a chain with a foreign rule")
	}
}

func TestAdoptionRefusesForeignJump(t *testing.T) {
	f := setup(t)
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
	f.chains["INPUT"] = append([]string{"-p tcp --dport 9999 -j " + chain}, f.chains["INPUT"]...)
	if err := Cleanup(); !errors.Is(err, ErrGuardUnshared) {
		t.Fatalf("recordless chain with a foreign jump was not retained: %v", err)
	}
	if len(f.chains["INPUT"]) != 3 {
		t.Fatal("foreign jump was deleted")
	}
}

// A kill between creating the chain and adding rules leaves a subset shape that
// only the record can attribute; the record still does.
func TestCleanupRecoversEmptyRecordedChain(t *testing.T) {
	f := setup(t)
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	f.chains[chain] = nil
	f.chains["INPUT"] = nil
	if err := Cleanup(); err != nil {
		t.Fatal(err)
	}
	requireNoGuard(t, f)
}

func TestCleanupRemovesCorruptRecordWhenNothingInstalled(t *testing.T) {
	f := setup(t)
	if err := os.WriteFile(statePath, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Cleanup(); err != nil {
		t.Fatalf("corrupt record blocked startup with nothing installed: %v", err)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatal("corrupt record retained")
	}
	if len(f.calls) == 0 {
		t.Fatal("cleanup did not inspect the firewall")
	}
}

func TestCleanupKeepsChainWithCorruptRecord(t *testing.T) {
	f := setup(t)
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Cleanup(); err == nil {
		t.Fatal("chain was removed while its record was corrupt")
	}
	if !guardInstalled(f, 2) {
		t.Fatal("chain was modified while its record was corrupt")
	}
}

func TestCleanupRefusesForeignChainWithCorruptRecord(t *testing.T) {
	f := setup(t)
	f.chains[chain] = []string{"-j ACCEPT"}
	if err := os.WriteFile(statePath, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Cleanup(); err == nil {
		t.Fatal("foreign chain deleted behind a corrupt record")
	}
	if len(f.chains[chain]) != 1 {
		t.Fatal("foreign chain modified")
	}
}

func TestCleanupKeepsRecordWhenListingFails(t *testing.T) {
	f := setup(t)
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	f.fail = "-S"
	if err := Cleanup(); err == nil {
		t.Fatal("cleanup claimed success without a listing")
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatal("ownership record deleted after an unreadable firewall")
	}
	f.fail = ""
	if err := Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestRepeatedStopStartCyclesAreIdempotent(t *testing.T) {
	f := setup(t)
	last := ""
	for i := 0; i < 10; i++ {
		if err := Ensure(lanConfig()); err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
		r, err := load()
		if err != nil {
			t.Fatal(err)
		}
		if r.Token == last {
			t.Fatal("guard token was reused across a restart")
		}
		last = r.Token
		if err := Cleanup(); err != nil {
			t.Fatalf("cycle %d cleanup: %v", i, err)
		}
		if err := Cleanup(); err != nil {
			t.Fatalf("cycle %d repeated cleanup: %v", i, err)
		}
		requireNoGuard(t, f)
	}
}
