package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/config"
)

// stubResolved makes systemd-resolved look active and records every systemctl
// call. Nothing on the host is touched.
func stubResolved(t *testing.T) *[]string {
	t.Helper()
	calls := []string{}
	oldOut, oldRun := systemctlOutput, systemctlRun
	systemctlOutput = func(args ...string) ([]byte, error) {
		calls = append(calls, "out "+strings.Join(args, " "))
		return []byte("active\n"), nil
	}
	systemctlRun = func(args ...string) error {
		calls = append(calls, "run "+strings.Join(args, " "))
		return nil
	}
	t.Cleanup(func() {
		systemctlOutput, systemctlRun = oldOut, oldRun
	})
	return &calls
}

func stubDropInPath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "90-bypath.conf")
	old := resolvedDropInPath
	resolvedDropInPath = path
	legacy := filepath.Join(t.TempDir(), "legacy-90-bypath.conf")
	oldLegacy := legacyResolvedDropInPath
	legacyResolvedDropInPath = legacy
	t.Cleanup(func() {
		resolvedDropInPath = old
		legacyResolvedDropInPath = oldLegacy
	})
	return path
}

func stubListenerServes(t *testing.T, serves bool) *[]int {
	t.Helper()
	probed := []int{}
	old := dnsListenerServes
	dnsListenerServes = func(port int) bool {
		probed = append(probed, port)
		return serves
	}
	t.Cleanup(func() { dnsListenerServes = old })
	return &probed
}

func writeDropIn(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("creating drop-in directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing drop-in: %v", err)
	}
}

// TestRestoreHostDNSClearsManagedDropIn pins the crash-recovery contract: the
// unit hook removes exactly the file bypath wrote and restarts the resolver,
// so a SIGKILLed gateway cannot leave the host on a dead listener.
func TestRestoreHostDNSClearsManagedDropIn(t *testing.T) {
	isolateHostState(t)
	path := stubDropInPath(t)
	calls := stubResolved(t)
	stubListenerServes(t, false)
	writeDropIn(t, path, resolvedDropInContent(5335))

	if err := RestoreHostDNS(); err != nil {
		t.Fatalf("RestoreHostDNS: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("managed drop-in survived: %v", err)
	}
	if !strings.Contains(strings.Join(*calls, "\n"), "run restart systemd-resolved") {
		t.Fatalf("resolver was not restarted: %v", *calls)
	}
}

// TestRestoreHostDNSKeepsHealthyInstanceAlone covers the race the unit hook
// must avoid: while a gateway listener is answering, its resolver override is
// still in use and must not be swept from under it.
func TestRestoreHostDNSKeepsHealthyInstanceAlone(t *testing.T) {
	isolateHostState(t)
	path := stubDropInPath(t)
	calls := stubResolved(t)
	probed := stubListenerServes(t, true)
	writeDropIn(t, path, resolvedDropInContent(5335))

	if err := RestoreHostDNS(); err != nil {
		t.Fatalf("RestoreHostDNS: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("drop-in removed while the listener was serving: %v", err)
	}
	if len(*probed) != 1 || (*probed)[0] != 5335 {
		t.Fatalf("probe used ports %v, want [5335]", *probed)
	}
	if strings.Contains(strings.Join(*calls, "\n"), "run restart systemd-resolved") {
		t.Fatalf("resolver restarted although nothing was removed: %v", *calls)
	}
}

// TestRestoreHostDNSLeavesEditedOrForeignFileAlone is the "never overwrite
// unrelated administrator changes" rule: a file with the marker but different
// content, or with no marker at all, is not bypath's to delete.
func TestRestoreHostDNSLeavesEditedOrForeignFileAlone(t *testing.T) {
	cases := map[string]string{
		"edited":  resolvedDropInMarker + "\n[Resolve]\nDNS=127.0.0.1:5335\nDomains=~.\nFallbackDNS=9.9.9.9\n",
		"foreign": "[Resolve]\nDNS=192.0.2.53\n",
		"admin":   "[Resolve]\nDNS=127.0.0.1:5335\nDomains=~.\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			isolateHostState(t)
			path := stubDropInPath(t)
			calls := stubResolved(t)
			stubListenerServes(t, false)
			writeDropIn(t, path, content)

			if err := RestoreHostDNS(); err != nil {
				t.Fatalf("RestoreHostDNS: %v", err)
			}
			if _, err := os.Stat(path); err != nil {
				t.Fatalf("%s drop-in was removed: %v", name, err)
			}
			if strings.Contains(strings.Join(*calls, "\n"), "run restart systemd-resolved") {
				t.Fatalf("%s drop-in triggered a resolver restart: %v", name, *calls)
			}
		})
	}
}

// TestRestoreHostDNSClearsLegacyEtcDropIn covers an upgrade from a build that
// wrote the override into /etc: the old file is swept as well.
func TestRestoreHostDNSClearsLegacyEtcDropIn(t *testing.T) {
	isolateHostState(t)
	stubDropInPath(t)
	calls := stubResolved(t)
	stubListenerServes(t, false)
	writeDropIn(t, legacyResolvedDropInPath, resolvedDropInContent(5335))

	if err := RestoreHostDNS(); err != nil {
		t.Fatalf("RestoreHostDNS: %v", err)
	}
	if _, err := os.Stat(legacyResolvedDropInPath); !os.IsNotExist(err) {
		t.Fatalf("legacy drop-in survived: %v", err)
	}
	if !strings.Contains(strings.Join(*calls, "\n"), "run restart systemd-resolved") {
		t.Fatalf("resolver was not restarted: %v", *calls)
	}
}

// TestRestoreHostDNSSkipsRestartDuringShutdown: on the way down the file must
// go, but restarting the resolver would race systemd's own shutdown.
func TestRestoreHostDNSSkipsRestartDuringShutdown(t *testing.T) {
	isolateHostState(t)
	path := stubDropInPath(t)
	calls := []string{}
	oldOut, oldRun := systemctlOutput, systemctlRun
	systemctlOutput = func(args ...string) ([]byte, error) {
		calls = append(calls, "out "+strings.Join(args, " "))
		if len(args) == 1 && args[0] == "is-system-running" {
			return []byte("stopping\n"), nil
		}
		return []byte("active\n"), nil
	}
	systemctlRun = func(args ...string) error {
		calls = append(calls, "run "+strings.Join(args, " "))
		return nil
	}
	t.Cleanup(func() { systemctlOutput, systemctlRun = oldOut, oldRun })
	stubListenerServes(t, false)
	writeDropIn(t, path, resolvedDropInContent(5335))

	if err := RestoreHostDNS(); err != nil {
		t.Fatalf("RestoreHostDNS: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("drop-in survived shutdown cleanup: %v", err)
	}
	if strings.Contains(strings.Join(calls, "\n"), "run restart systemd-resolved") {
		t.Fatalf("resolver was restarted during shutdown: %v", calls)
	}
}

func TestManagedDropInPort(t *testing.T) {
	cases := []struct {
		name    string
		content string
		port    int
		ok      bool
	}{
		{"generated", resolvedDropInContent(5335), 5335, true},
		{"other port", resolvedDropInContent(5353), 5353, true},
		{"extra directive", resolvedDropInContent(5335) + "FallbackDNS=9.9.9.9\n", 0, false},
		{"foreign dns", resolvedDropInMarker + "\n[Resolve]\nDNS=192.0.2.53\nDomains=~.\n", 0, false},
		{"no marker", "[Resolve]\nDNS=127.0.0.1:5335\nDomains=~.\n", 0, false},
		{"empty", "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			port, ok := managedDropInPort([]byte(tc.content))
			if ok != tc.ok || (ok && port != tc.port) {
				t.Fatalf("managedDropInPort(%q) = %d, %v; want %d, %v", tc.content, port, ok, tc.port, tc.ok)
			}
		})
	}
}

// TestSetResolvedDropInReplacesLegacyEtcFile keeps a single bypath upstream
// after upgrading from the /etc location.
func TestSetResolvedDropInReplacesLegacyEtcFile(t *testing.T) {
	isolateHostState(t)
	oldStub := resolvedStubInUse
	resolvedStubInUse = func() bool { return true }
	t.Cleanup(func() { resolvedStubInUse = oldStub })
	path := stubDropInPath(t)
	stubResolved(t)
	stubListenerServes(t, false)
	writeDropIn(t, legacyResolvedDropInPath, resolvedDropInContent(5335))

	gw := nonstandardGateway(t)
	if _, err := gw.ensureRunState("native"); err != nil {
		t.Fatalf("creating the ownership record: %v", err)
	}
	if err := gw.setHostResolver(); err != nil {
		t.Fatalf("setHostResolver: %v", err)
	}
	if _, err := os.Stat(legacyResolvedDropInPath); !os.IsNotExist(err) {
		t.Fatalf("legacy drop-in left in place: %v", err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != resolvedDropInContent(5335) {
		t.Fatalf("runtime drop-in = %q, %v; want the generated file", data, err)
	}
}

func nonstandardGateway(t *testing.T) *Gateway {
	t.Helper()
	cfg, err := config.Parse(nil)
	if err != nil {
		t.Fatalf("parsing default config: %v", err)
	}
	cfg.Server.DNSPort = 5335
	gw := &Gateway{config: cfg}
	gw.dnsPort = cfg.Server.DNSPort
	return gw
}

// TestSetHostResolverNonstandardPortUsesDropIn pins the fix for the installer
// rerun failure: with the systemd-resolved stub in place, a 5335 listener must
// not be written to resolv.conf as a bare 127.0.0.1. The host resolver keeps
// the stub and a bypath-owned drop-in carries the port.
func TestSetHostResolverNonstandardPortUsesDropIn(t *testing.T) {
	isolateHostState(t)
	resolv := scratchResolver(t)
	before, err := os.ReadFile(resolv)
	if err != nil {
		t.Fatalf("reading seeded resolver: %v", err)
	}
	oldStub := resolvedStubInUse
	resolvedStubInUse = func() bool { return true }
	t.Cleanup(func() { resolvedStubInUse = oldStub })
	dropIn := stubDropInPath(t)
	calls := stubResolved(t)

	gw := nonstandardGateway(t)
	if _, err := gw.ensureRunState("native"); err != nil {
		t.Fatalf("creating the ownership record: %v", err)
	}
	if err := gw.setHostResolver(); err != nil {
		t.Fatalf("setHostResolver: %v", err)
	}

	after, err := os.ReadFile(resolv)
	if err != nil {
		t.Fatalf("reading resolver: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("resolv.conf changed to %q; the stub must stay untouched", after)
	}
	data, err := os.ReadFile(dropIn)
	if err != nil {
		t.Fatalf("reading drop-in: %v", err)
	}
	for _, want := range []string{resolvedDropInMarker, "DNS=127.0.0.1:5335", "Domains=~."} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("drop-in %q does not contain %q", data, want)
		}
	}
	joined := strings.Join(*calls, "\n")
	if !strings.Contains(joined, "run restart systemd-resolved") {
		t.Fatalf("systemd-resolved was not restarted with the drop-in: %v", *calls)
	}
	if strings.Contains(joined, "run stop systemd-resolved") {
		t.Fatalf("a nonstandard port must not stop systemd-resolved: %v", *calls)
	}
	if st := gatewayState(); st == nil || !st.ResolvedDropIn {
		t.Fatalf("ownership record does not mark the drop-in: %+v", st)
	}

	if err := gw.restoreResolvedDropIn(); err != nil {
		t.Fatalf("restoreResolvedDropIn: %v", err)
	}
	if _, err := os.Stat(dropIn); !os.IsNotExist(err) {
		t.Fatalf("drop-in survived restoration: %v", err)
	}
	if !strings.Contains(strings.Join(*calls, "\n"), "run restart systemd-resolved") {
		t.Fatal("restoration did not restart systemd-resolved")
	}
}

// TestSetHostResolverNonstandardPortLeavesPlainResolverAlone covers hosts
// without the resolved stub: resolv.conf cannot express a port, so bypath must
// leave it untouched rather than blackhole host DNS.
func TestSetHostResolverNonstandardPortLeavesPlainResolverAlone(t *testing.T) {
	isolateHostState(t)
	resolv := scratchResolver(t)
	before, err := os.ReadFile(resolv)
	if err != nil {
		t.Fatalf("reading seeded resolver: %v", err)
	}
	dropIn := stubDropInPath(t)
	calls := stubResolved(t)

	gw := nonstandardGateway(t)
	if err := gw.setHostResolver(); err != nil {
		t.Fatalf("setHostResolver: %v", err)
	}
	after, err := os.ReadFile(resolv)
	if err != nil {
		t.Fatalf("reading resolver after setHostResolver: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("resolv.conf changed to %q, want %q", after, before)
	}
	if _, err := os.Stat(dropIn); !os.IsNotExist(err) {
		t.Fatalf("a drop-in was written without the resolved stub: %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("systemctl was called without a conflict: %v", *calls)
	}
}

// TestDisableSystemdResolvedSkipsNonstandardPort keeps a resolver on port 53
// running when the gateway listener uses another port and does not conflict.
func TestDisableSystemdResolvedSkipsNonstandardPort(t *testing.T) {
	isolateHostState(t)
	calls := stubResolved(t)
	gw := nonstandardGateway(t)

	stopped, err := gw.disableSystemdResolved()
	if err != nil || stopped {
		t.Fatalf("disableSystemdResolved = %v, %v; want no change", stopped, err)
	}
	if len(*calls) != 0 {
		t.Fatalf("systemd-resolved was queried or stopped without a port conflict: %v", *calls)
	}
}
