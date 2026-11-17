package gateway

import (
	"net/url"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/tunnel"
)

// The generated configs force the startup-probe domains through the tunnel.
// This test keeps every target the gateway actually probes inside that forced
// set, so a newly added target cannot silently fall back to a DIRECT rule.
func TestHTTPSProbeTargetsAreForcedThroughTunnel(t *testing.T) {
	if len(httpsProbeTargets) == 0 {
		t.Fatal("no HTTPS probe targets configured")
	}
	for _, target := range httpsProbeTargets {
		u, err := url.Parse(target)
		if err != nil {
			t.Fatalf("bad probe target %q: %v", target, err)
		}
		host := strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
		covered := false
		for _, suffix := range tunnel.StartupProbeDomains {
			if host == suffix || strings.HasSuffix(host, "."+suffix) {
				covered = true
			}
		}
		if !covered {
			t.Fatalf("probe target %q is not covered by tunnel.StartupProbeDomains %v", target, tunnel.StartupProbeDomains)
		}
	}
}
