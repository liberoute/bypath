package gateway

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/tunnel"
)

func probeHostCovered(host string) bool {
	host = strings.TrimPrefix(strings.ToLower(host), "www.")
	for _, suffix := range tunnel.StartupProbeDomains {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// The generated configs force the startup-probe domains through the tunnel on
// the daemon's probe inbound. This test keeps every target the gateway actually
// probes inside that forced set, so a newly added target cannot silently fall
// back to a DIRECT rule.
func TestProbeTargetsAreForcedThroughTunnel(t *testing.T) {
	if len(httpsProbeTargets) == 0 {
		t.Fatal("no HTTPS probe targets configured")
	}
	for _, target := range httpsProbeTargets {
		u, err := url.Parse(target)
		if err != nil {
			t.Fatalf("bad probe target %q: %v", target, err)
		}
		if !probeHostCovered(u.Hostname()) {
			t.Fatalf("probe target %q is not covered by tunnel.StartupProbeDomains %v", target, tunnel.StartupProbeDomains)
		}
	}
	for _, candidate := range dataPathCandidates {
		u, err := url.Parse(candidate.url)
		if err != nil {
			t.Fatalf("bad data-path target %q: %v", candidate.url, err)
		}
		if !probeHostCovered(u.Hostname()) {
			t.Fatalf("data-path target %q is not covered by tunnel.StartupProbeDomains %v", candidate.url, tunnel.StartupProbeDomains)
		}
	}
}

// Probes must enter through the reserved inbound whenever one exists: it is the
// only path the generated rules force through the tunnel.
func TestProbesUseReservedInbound(t *testing.T) {
	gw := &Gateway{
		config:    &config.Config{},
		socksPort: 2801,
		probePort: 3999,
	}
	if got := gw.probeSocksAddr(); got != "127.0.0.1:3999" {
		t.Fatalf("probe address = %q, want the reserved inbound", got)
	}

	gw.probePort = 0
	gw.config.Server.SOCKSListen = "192.0.2.10"
	if got := gw.probeSocksAddr(); got != "192.0.2.10:2801" {
		t.Fatalf("fallback probe address = %q, want the client listener", got)
	}
}

// The reserved port must be a usable, free loopback port distinct from the
// client listener so the engine can bind it.
func TestReserveProbePort(t *testing.T) {
	port := reserveProbePort(2801)
	if port <= 0 || port == 2801 {
		t.Fatalf("reserveProbePort = %d", port)
	}
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("reserved port %d is not bindable: %v", port, err)
	}
	l.Close()
}
