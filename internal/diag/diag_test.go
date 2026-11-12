package diag

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeHost struct {
	tun       bool
	listeners map[int][]string
	units     map[string]string
	installed map[string]bool
	chain     int
	chainOK   bool
	root      bool
	dialable  map[string]bool
}

func (f fakeHost) GOOS() string { return "linux" }
func (f fakeHost) TUN() (bool, string) {
	return f.tun, "/dev/net/tun"
}
func (f fakeHost) Listeners(port int) []string { return f.listeners[port] }
func (f fakeHost) SystemdUnit(name string) (bool, string) {
	state, ok := f.units[name]
	if !ok {
		return false, "unknown"
	}
	return f.installed[name] || true, state
}
func (f fakeHost) FirewallChain(string) (int, bool, string) { return f.chain, f.chainOK, "" }
func (f fakeHost) IsRoot() bool                            { return f.root }
func (f fakeHost) Dial(addr string, _ time.Duration) error {
	if f.dialable[addr] {
		return nil
	}
	return os.ErrDeadlineExceeded
}

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

const neutralConfig = `
server:
  api_port: 8080
  dns_port: 53
  socks_port: 2801
  socks_listen: "127.0.0.1"
gateway:
  enabled: false
  native_tun: true
engines:
  directory: '%ENGINES%'
profiles:
  directory: '%PROFILES%'
routing:
  rules:
    - match: default
      outbound: proxy
`

func neutralPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	body := strings.NewReplacer("%ENGINES%", filepath.Join(dir, "engines"), "%PROFILES%", filepath.Join(dir, "profiles")).Replace(neutralConfig)
	return writeConfig(t, body)
}

func findCheck(t *testing.T, rep *Report, id string) Check {
	t.Helper()
	for _, c := range rep.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("check %q missing from report", id)
	return Check{}
}

func TestNeutralProxyInstallPassesSafetyChecks(t *testing.T) {
	host := fakeHost{tun: true, root: true, chainOK: true, dialable: map[string]bool{}}
	rep := Run(context.Background(), Options{ConfigPath: neutralPath(t), Host: host})
	if findCheck(t, rep, "config").Status != Pass {
		t.Fatalf("config should pass: %+v", findCheck(t, rep, "config"))
	}
	if got := findCheck(t, rep, "lan"); got.Status != Pass {
		t.Fatalf("loopback proxy should pass: %+v", got)
	}
	if got := findCheck(t, rep, "tun"); got.Status != Info {
		t.Fatalf("proxy-only tun should be informational: %+v", got)
	}
	if got := findCheck(t, rep, "routing"); got.Status != Pass {
		t.Fatalf("routing should pass without a gateway: %+v", got)
	}
	for _, c := range rep.Checks {
		if c.Status == Fail && c.ID != "engine" {
			t.Fatalf("neutral install must not fail %s: %+v", c.ID, c)
		}
	}
}

func TestGatewayWithoutSelectionFailsClosed(t *testing.T) {
	path := neutralPath(t)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(body), "enabled: false", "enabled: true", 1)
	if err := os.WriteFile(path, []byte(updated), 0600); err != nil {
		t.Fatal(err)
	}
	host := fakeHost{tun: true, root: true, chainOK: true}
	rep := Run(context.Background(), Options{ConfigPath: path, Host: host})
	routing := findCheck(t, rep, "routing")
	if routing.Status != Fail {
		t.Fatalf("gateway mode without a selected connection must fail: %+v", routing)
	}
	if !strings.Contains(routing.Summary+strings.Join(routing.Detail, " "), "no connection") {
		t.Fatalf("failure must name the missing connection: %+v", routing)
	}
}

func TestGatewayDNSConflictIsReportedNotResolved(t *testing.T) {
	path := neutralPath(t)
	body, _ := os.ReadFile(path)
	updated := strings.Replace(string(body), "enabled: false", "enabled: true", 1)
	os.WriteFile(path, []byte(updated), 0600)
	host := fakeHost{
		tun:       true,
		root:      true,
		chainOK:   true,
		listeners: map[int][]string{53: {"udp 127.0.0.53:53"}},
	}
	rep := Run(context.Background(), Options{ConfigPath: path, Host: host})
	dns := findCheck(t, rep, "dns")
	if dns.Status != Fail {
		t.Fatalf("an occupied DNS port must fail: %+v", dns)
	}
	if !strings.Contains(dns.Remediation, "does not stop") {
		t.Fatalf("remediation must state that bypath never stops the resolver: %q", dns.Remediation)
	}
}

func TestLANListenerWithoutTrustedNetworkFails(t *testing.T) {
	path := neutralPath(t)
	body, _ := os.ReadFile(path)
	updated := strings.Replace(string(body), `socks_listen: "127.0.0.1"`, "socks_listen: \"0.0.0.0\"\n  socks_allow_lan: true", 1)
	os.WriteFile(path, []byte(updated), 0600)
	host := fakeHost{root: true, chainOK: true}
	rep := Run(context.Background(), Options{ConfigPath: path, Host: host})
	lan := findCheck(t, rep, "lan")
	if lan.Status != Fail && lan.Status != Warn {
		t.Fatalf("a LAN bind without a trusted CIDR must not pass: %+v", lan)
	}
}

func TestProxyPortClosedWithoutConnectionIsExpected(t *testing.T) {
	path := neutralPath(t)
	host := fakeHost{
		root: true, chainOK: true,
		installed: map[string]bool{"bypath": true},
		units:     map[string]string{"bypath": "active"},
	}
	rep := Run(context.Background(), Options{ConfigPath: path, Host: host})
	proxy := findCheck(t, rep, "proxy")
	if proxy.Status != Info {
		t.Fatalf("an active service with no stored connection should not warn about the proxy port: %+v", proxy)
	}
	if !strings.Contains(proxy.Summary, "no connection is configured") {
		t.Fatalf("summary should name the missing connection: %q", proxy.Summary)
	}
}

func TestEgressIsSkippedUnlessRequested(t *testing.T) {
	rep := Run(context.Background(), Options{ConfigPath: neutralPath(t), Host: fakeHost{}})
	if got := findCheck(t, rep, "egress"); got.Status != Skip {
		t.Fatalf("egress must be opt-in: %+v", got)
	}

	rep = Run(context.Background(), Options{
		ConfigPath: neutralPath(t),
		Host:       fakeHost{},
		Egress: func(context.Context) (Egress, error) {
			return Egress{Tunnel: "192.0.2.10", Direct: "198.51.100.20"}, nil
		},
	})
	if got := findCheck(t, rep, "egress"); got.Status != Pass {
		t.Fatalf("distinct addresses should pass: %+v", got)
	}

	rep = Run(context.Background(), Options{
		ConfigPath: neutralPath(t),
		Host:       fakeHost{},
		Egress: func(context.Context) (Egress, error) {
			return Egress{Tunnel: "192.0.2.10", Direct: "192.0.2.10", Same: true}, nil
		},
	})
	if got := findCheck(t, rep, "egress"); got.Status != Warn {
		t.Fatalf("identical addresses must warn: %+v", got)
	}
}
