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
	t.Cleanup(func() { resolvedDropInPath = old })
	return path
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
