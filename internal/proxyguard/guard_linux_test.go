//go:build linux

package proxyguard

import (
	"context"
	"errors"
	"github.com/liberoute/bypath/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type firewall struct {
	chains map[string][]string
	calls  []string
	fail   string
	warn   string
}

func (f *firewall) command(_ context.Context, args ...string) ([]byte, error) {
	args = args[2:]
	call := strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if f.fail != "" && strings.Contains(call, f.fail) {
		return nil, errors.New("injected firewall failure")
	}
	if args[0] == "-S" {
		if len(args) == 1 {
			out := f.warn
			for name, rules := range f.chains {
				if name != "INPUT" {
					out += "-N " + name + "\n"
				}
				for _, r := range rules {
					out += "-A " + name + " " + r + "\n"
				}
			}
			return []byte(out), nil
		}
		rules, ok := f.chains[args[1]]
		if !ok {
			return nil, errors.New("no chain")
		}
		out := f.warn + "-N " + args[1] + "\n"
		for _, r := range rules {
			out += "-A " + args[1] + " " + r + "\n"
		}
		return []byte(out), nil
	}
	name := args[1]
	rule := strings.Join(args[2:], " ")
	switch args[0] {
	case "-N":
		if _, ok := f.chains[name]; ok {
			return nil, errors.New("exists")
		}
		f.chains[name] = nil
	case "-A":
		f.chains[name] = append(f.chains[name], rule)
	case "-I":
		rule = strings.Join(args[3:], " ")
		f.chains[name] = append([]string{rule}, f.chains[name]...)
	case "-C", "-D":
		found := -1
		for i, r := range f.chains[name] {
			if r == rule {
				found = i
				break
			}
		}
		if found < 0 {
			return nil, errors.New("no rule")
		}
		if args[0] == "-D" {
			f.chains[name] = append(f.chains[name][:found], f.chains[name][found+1:]...)
		}
	case "-F":
		f.chains[name] = nil
	case "-X":
		delete(f.chains, name)
	default:
		return nil, errors.New("unexpected command")
	}
	return nil, nil
}
func setup(t *testing.T) *firewall {
	t.Helper()
	oldCmd, oldPath, oldRoot, oldCheck, oldLAN, oldWrite := Command, statePath, rootUID, checkState, trustedLANs, writeState
	t.Cleanup(func() {
		Command, statePath, rootUID, checkState, trustedLANs, writeState = oldCmd, oldPath, oldRoot, oldCheck, oldLAN, oldWrite
	})
	f := &firewall{chains: map[string][]string{"INPUT": {}}}
	Command = f.command
	statePath = filepath.Join(t.TempDir(), "guard.json")
	rootUID = func() int { return 0 }
	checkState = func(path string, _ bool) error { _, err := os.Stat(path); return err }
	writeState = func(path string, b []byte) error { return os.WriteFile(path, b, 0600) }
	trustedLANs = func(string, []string) ([]config.LANNetwork, error) {
		return []config.LANNetwork{{IP: "192.168.10.2", CIDR: "192.168.10.0/24", Interface: "eth0"}}, nil
	}
	return f
}
func lanConfig() *config.Config {
	return &config.Config{Server: config.ServerConfig{SOCKSPort: 2901, SOCKSListen: "0.0.0.0", SOCKSAllowLAN: true}}
}
func TestProxyOnlyInstallsNarrowOwnedInputAndCleanup(t *testing.T) {
	f := setup(t)
	cfg := lanConfig()
	cfg.Gateway.Enabled = false
	if err := Ensure(cfg); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(f.calls, "\n")
	for _, want := range []string{"-i lo -j RETURN", "-i eth0 -s 192.168.10.0/24 -j RETURN", "-p tcp --dport 2901 -j DROP", "-p udp --dport 2901 -j DROP", "-I INPUT 1"} {
		if !strings.Contains(calls, want) {
			t.Fatal("missing guard rule", want)
		}
	}
	// A host-local probe may bind the LAN source address (curl --interface), so
	// the loopback allowance must not depend on a 127/8 source.
	if strings.Contains(calls, "-s 127.0.0.0/8") {
		t.Fatal("loopback allowance rejects daemon probes sourced from the LAN IP")
	}
	if strings.Contains(calls, "FORWARD") || strings.Contains(calls, "OUTPUT") {
		t.Fatal("guard mutated unrelated plane")
	}
	if err := Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.chains[chain]; ok || len(f.chains["INPUT"]) != 0 {
		t.Fatal("owned guard not cleaned")
	}
}
func TestForeignChainFailsClosed(t *testing.T) {
	f := setup(t)
	f.chains[chain] = []string{"-j ACCEPT"}
	if err := Ensure(lanConfig()); err == nil {
		t.Fatal("foreign chain adopted")
	}
	if len(f.chains[chain]) != 1 {
		t.Fatal("foreign chain modified")
	}
}
func TestFirewallFailurePreventsExposureAndRecoversPartialSetup(t *testing.T) {
	f := setup(t)
	f.fail = "-A " + chain + " -p udp"
	if err := Ensure(lanConfig()); err == nil {
		t.Fatal("listener could start after missing DROP")
	}
	f.fail = ""
	if err := Cleanup(); err != nil {
		t.Fatal("partial ownership did not recover", err)
	}
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	f.chains[chain] = append(f.chains[chain], "-j ACCEPT")
	if err := Cleanup(); err == nil {
		t.Fatal("foreign rule silently deleted")
	}
}
func TestRebootReinstallsPersistedGuardBeforeListening(t *testing.T) {
	f := setup(t)
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	f.chains = map[string][]string{"INPUT": {}}
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal("reboot guard recovery", err)
	}
	if len(f.chains[chain]) != 4 || len(f.chains["INPUT"]) != 2 {
		t.Fatal("reboot did not reinstall containment")
	}
}
func TestAmbiguousLANAndNonRootFailClosed(t *testing.T) {
	setup(t)
	trustedLANs = func(string, []string) ([]config.LANNetwork, error) {
		return nil, errors.New("ambiguous LAN")
	}
	if err := Ensure(lanConfig()); err == nil {
		t.Fatal("ambiguous LAN trusted")
	}
	rootUID = func() int { return 1000 }
	if err := Ensure(lanConfig()); err == nil {
		t.Fatal("non-root LAN accepted")
	}
}

// A host that owns two private networks: the explicit allow-list must produce
// one interface-scoped RETURN per entry and still drop everything else.
func TestMultipleTrustedCIDRsInstallPairedRules(t *testing.T) {	f := setup(t)
	trustedLANs = func(string, []string) ([]config.LANNetwork, error) {
		return []config.LANNetwork{
			{IP: "10.20.30.10", CIDR: "10.20.30.0/24", Interface: "lan0"},
			{IP: "10.20.40.2", CIDR: "10.20.40.1/32", Interface: "lan0.30"},
		}, nil
	}
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(f.calls, "\n")
	for _, want := range []string{
		"-i lan0 -s 10.20.30.0/24 -j RETURN",
		"-i lan0.30 -s 10.20.40.1/32 -j RETURN",
		"-p tcp --dport 2901 -j DROP",
		"-p udp --dport 2901 -j DROP",
	} {
		if !strings.Contains(calls, want) {
			t.Fatal("missing allow-list rule", want)
		}
	}
	if len(f.chains[chain]) != 5 {
		t.Fatalf("chain rules = %d, want 5", len(f.chains[chain]))
	}
	if err := Cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.chains[chain]; ok || len(f.chains["INPUT"]) != 0 {
		t.Fatal("multi-entry guard not cleaned")
	}
}

// Hosts that also carry legacy iptables tables emit a stderr notice on every
// listing. Counting it as a chain rule rejected our own guard at startup.
func TestLegacyTableWarningIsNotARule(t *testing.T) {
	f := setup(t)
	f.warn = "# Warning: iptables-legacy tables present, use iptables-legacy to see them\n"
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal(err)
	}
	if err := Cleanup(); err != nil {
		t.Fatal("warning broke ownership", err)
	}
	if _, ok := f.chains[chain]; ok {
		t.Fatal("guard not cleaned")
	}
}

// A firewall failure after the chain is created must not leave state that makes
// every later start fail its ownership check.
func TestFailedInstallLeavesNoLockoutState(t *testing.T) {
	f := setup(t)
	f.fail = "-A " + chain + " -p udp"
	if err := Ensure(lanConfig()); err == nil {
		t.Fatal("listener could start without the udp drop")
	}
	f.fail = ""
	if _, ok := f.chains[chain]; ok {
		t.Fatal("partial guard chain retained")
	}
	if len(f.chains["INPUT"]) != 0 {
		t.Fatal("partial guard jumps retained")
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatal("guard state retained after failed install")
	}
	if err := Ensure(lanConfig()); err != nil {
		t.Fatal("retry after failed install", err)
	}
}
