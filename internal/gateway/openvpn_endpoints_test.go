package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
)

// writeEndpointProfile stores an .ovpn fixture under dir/ovpn and returns the
// reference as a migrated group would record it (relative to the install root).
func writeEndpointProfile(t *testing.T, dir, name string, lines ...string) string {
	t.Helper()
	ovpnDir := filepath.Join(dir, "ovpn")
	if err := os.MkdirAll(ovpnDir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := append([]string{"client", "dev tun"}, lines...)
	if err := os.WriteFile(filepath.Join(ovpnDir, name), []byte(strings.Join(body, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.ToSlash(filepath.Join("data", "profiles", "ovpn", name))
}

func stubEndpointLookups(t *testing.T, lookup func(string) []string, probe func(string) error) {
	t.Helper()
	oldLookup, oldFrom, oldProbe := lookupServerAddresses, lookupServerAddressesFrom, probeOpenVPNEndpoint
	t.Cleanup(func() {
		lookupServerAddresses, lookupServerAddressesFrom, probeOpenVPNEndpoint = oldLookup, oldFrom, oldProbe
	})
	if lookup != nil {
		lookupServerAddresses = func(_ *Gateway, _ context.Context, host string) []string { return lookup(host) }
	}
	// Alternate-upstream samples stay hermetic; tests that need them stub the
	// seam directly.
	lookupServerAddressesFrom = func(_ *Gateway, _ context.Context, _ string, _ string) []string { return nil }
	if probe != nil {
		probeOpenVPNEndpoint = func(_ context.Context, addr string, _ time.Duration) error { return probe(addr) }
	}
}

func endpointTestGateway(dir string) *Gateway {
	return &Gateway{config: &config.Config{Profiles: config.ProfilesConfig{Directory: dir}}}
}

// TestOpenVPNEndpointCandidatesPreferReachableAddress covers the observed
// OpenVPN round-robin failure: consecutive lookups returned a healthy and a
// dead address. The reachable one must be pinned even when the resolver
// returns it second.
func TestOpenVPNEndpointCandidatesPreferReachableAddress(t *testing.T) {
	dir := t.TempDir()
	ref := writeEndpointProfile(t, dir, "sample.ovpn", "proto tcp", "remote vpn.example.net 443")

	stubEndpointLookups(t,
		func(string) []string { return []string{"203.0.113.9", "198.51.100.7"} },
		func(addr string) error {
			if strings.HasPrefix(addr, "203.0.113.9:") {
				return errors.New("i/o timeout")
			}
			return nil
		},
	)

	gw := endpointTestGateway(dir)
	link := &profile.Link{Protocol: "openvpn", Remark: "eu-tcp", Address: "vpn.example.net", Port: 443, OVPNPath: ref}

	cands, err := gw.openVPNEndpointCandidates(context.Background(), link)
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	if len(cands) != 2 {
		t.Fatalf("candidates = %+v, want both resolved addresses", cands)
	}
	if cands[0].IP != "198.51.100.7" || !cands[0].Reachable {
		t.Fatalf("first candidate = %+v, want the reachable 198.51.100.7", cands[0])
	}
	if cands[1].IP != "203.0.113.9" || cands[1].Reachable {
		t.Fatalf("second candidate = %+v, want the unreachable 203.0.113.9", cands[1])
	}

	sets := gw.openVPNPinSets(context.Background(), link)
	if len(sets) != 2 {
		t.Fatalf("pin sets = %v, want a primary and one alternate", sets)
	}
	pins := sets[0]
	if got := pins["vpn.example.net"]; got != "198.51.100.7" {
		t.Fatalf("pinned %q, want the validated 198.51.100.7", got)
	}
}

// TestOpenVPNEndpointCandidatesUDPUnprobed keeps UDP remotes honest: a TCP
// connect cannot validate them, so no probe result is invented.
func TestOpenVPNEndpointCandidatesUDPUnprobed(t *testing.T) {
	dir := t.TempDir()
	ref := writeEndpointProfile(t, dir, "udp.ovpn", "proto udp", "remote vpn.example.net 443")

	probes := 0
	stubEndpointLookups(t,
		func(string) []string { return []string{"198.51.100.7"} },
		func(string) error { probes++; return nil },
	)

	link := &profile.Link{Protocol: "openvpn", Remark: "us-udp53b", Address: "vpn.example.net", Port: 443, OVPNPath: ref}
	cands, err := endpointTestGateway(dir).openVPNEndpointCandidates(context.Background(), link)
	if err != nil {
		t.Fatalf("candidates: %v", err)
	}
	if probes != 0 {
		t.Fatalf("probe ran %d times for a UDP remote", probes)
	}
	if len(cands) != 1 || cands[0].Probed || cands[0].Network != "udp" {
		t.Fatalf("candidates = %+v, want one unprobed udp candidate", cands)
	}
}

// TestOpenVPNPinnedHostsPinsLinkAddressAlongsideRemotes proves the address the
// link recorded is pinned even when the profile's remote cannot be resolved,
// so the engine never has to fall back to the host resolver for it.
func TestOpenVPNPinnedHostsPinsLinkAddressAlongsideRemotes(t *testing.T) {
	dir := t.TempDir()
	ref := writeEndpointProfile(t, dir, "sample.ovpn", "proto tcp", "remote other.example.net 443")

	stubEndpointLookups(t, func(host string) []string {
		if host == "vpn.example.net" {
			return []string{"198.51.100.7"}
		}
		return nil
	}, nil)

	gw := endpointTestGateway(dir)
	pins := gw.openVPNPinSets(context.Background(), &profile.Link{
		Protocol: "openvpn", Remark: "eu-tcp", Address: "vpn.example.net", Port: 443, OVPNPath: ref,
	})[0]
	if got := pins["vpn.example.net"]; got != "198.51.100.7" {
		t.Fatalf("pins = %v, want the link address pinned to 198.51.100.7", pins)
	}
}

// TestOpenVPNEndpointCandidatesReportUnreadableProfile keeps the failure
// attributable: the error names the link and the artifact rather than looking
// like a network fault.
func TestOpenVPNEndpointCandidatesReportUnreadableProfile(t *testing.T) {
	dir := t.TempDir()
	gw := endpointTestGateway(dir)
	link := &profile.Link{Protocol: "openvpn", Remark: "eu-tcp", OVPNPath: "data/profiles/ovpn/missing.ovpn"}

	_, err := gw.openVPNEndpointCandidates(context.Background(), link)
	if err == nil {
		t.Fatal("missing profile produced no error")
	}
	if !strings.Contains(err.Error(), "eu-tcp") || !strings.Contains(err.Error(), "missing.ovpn") {
		t.Fatalf("error %q must name the link and the artifact", err)
	}
}

// TestOpenVPNPinSetsCollectAlternateUpstreams covers the production resolver
// pair: 1.1.1.1 and 8.8.8.8 are handed different OpenVPN entries, so the second
// answer must become a retry candidate rather than being discarded.
func TestOpenVPNPinSetsCollectAlternateUpstreams(t *testing.T) {
	dir := t.TempDir()
	ref := writeEndpointProfile(t, dir, "sample.ovpn", "proto tcp", "remote vpn.example.net 443")

	oldLookup, oldFrom := lookupServerAddresses, lookupServerAddressesFrom
	t.Cleanup(func() { lookupServerAddresses, lookupServerAddressesFrom = oldLookup, oldFrom })
	lookupServerAddresses = func(_ *Gateway, _ context.Context, _ string) []string {
		return []string{"203.0.113.9"}
	}
	lookupServerAddressesFrom = func(_ *Gateway, _ context.Context, _ string, ns string) []string {
		if ns == "8.8.8.8" {
			return []string{"198.51.100.7"}
		}
		return []string{"203.0.113.9"}
	}
	probeOpenVPNEndpoint = func(_ context.Context, _ string, _ time.Duration) error { return nil }

	gw := endpointTestGateway(dir)
	gw.config.Gateway.DNSUpstream = []string{"1.1.1.1", "8.8.8.8"}
	sets := gw.openVPNPinSets(context.Background(), &profile.Link{
		Protocol: "openvpn", Remark: "eu-tcp", Address: "vpn.example.net", Port: 443, OVPNPath: ref,
	})
	if len(sets) != 2 {
		t.Fatalf("pin sets = %v, want two candidates", sets)
	}
	if sets[0]["vpn.example.net"] != "203.0.113.9" {
		t.Fatalf("primary pin = %v, want the configured resolver's answer", sets[0])
	}
	if sets[1]["vpn.example.net"] != "198.51.100.7" {
		t.Fatalf("alternate pin = %v, want the second resolver's answer", sets[1])
	}
}

// TestStartEngineRetriesFailedOpenVPNEndpoint proves a link whose pinned
// endpoint never completes a handshake is retried with the next candidate
// instead of being declared broken.
func TestStartEngineRetriesFailedOpenVPNEndpoint(t *testing.T) {
	dir := t.TempDir()
	ref := writeEndpointProfile(t, dir, "sample.ovpn", "proto tcp", "remote vpn.example.net 443")
	stubEndpointLookups(t,
		func(string) []string { return []string{"203.0.113.9", "198.51.100.7"} },
		func(string) error { return nil },
	)

	oldStart := startEnginePinned
	t.Cleanup(func() { startEnginePinned = oldStart })
	var tried []string
	startEnginePinned = func(_ *Gateway, _ context.Context, _ *profile.Link, pins map[string]string) error {
		tried = append(tried, pins["vpn.example.net"])
		if len(tried) == 1 {
			return errors.New("OpenVPN endpoint did not pass the HTTPS health check within 1m0s")
		}
		return nil
	}

	gw := endpointTestGateway(dir)
	link := &profile.Link{Protocol: "openvpn", Remark: "eu-tcp", Address: "vpn.example.net", Port: 443, OVPNPath: ref}
	if err := gw.startEngine(context.Background(), link); err != nil {
		t.Fatalf("startEngine: %v", err)
	}
	if len(tried) != 2 || tried[0] == tried[1] {
		t.Fatalf("attempts = %v, want two different endpoint candidates", tried)
	}
}

// TestStartEngineDoesNotRetryLocalConfigError keeps a credentials/profile
// defect permanent instead of burning a second handshake window.
func TestStartEngineDoesNotRetryLocalConfigError(t *testing.T) {
	dir := t.TempDir()
	ref := writeEndpointProfile(t, dir, "sample.ovpn", "proto tcp", "remote vpn.example.net 443")
	stubEndpointLookups(t,
		func(string) []string { return []string{"203.0.113.9", "198.51.100.7"} },
		func(string) error { return nil },
	)

	oldStart := startEnginePinned
	t.Cleanup(func() { startEnginePinned = oldStart })
	calls := 0
	startEnginePinned = func(_ *Gateway, _ context.Context, _ *profile.Link, _ map[string]string) error {
		calls++
		return fmt.Errorf("%w: config generation failed: bad profile", engine.ErrLocalConfig)
	}

	gw := endpointTestGateway(dir)
	link := &profile.Link{Protocol: "openvpn", Remark: "eu-tcp", Address: "vpn.example.net", Port: 443, OVPNPath: ref}
	err := gw.startEngine(context.Background(), link)
	if !errors.Is(err, engine.ErrLocalConfig) {
		t.Fatalf("err = %v, want ErrLocalConfig", err)
	}
	if calls != 1 {
		t.Fatalf("started %d engines, want 1 — a local configuration error is permanent", calls)
	}
}

func TestUsableServerIPsOrdersIPv4FirstAndDropsIntercepted(t *testing.T) {
	got := usableServerIPs([]string{"2001:db8::1", "198.51.100.7", "10.1.2.3", "127.0.0.1", "198.51.100.7", "203.0.113.9"})
	want := []string{"198.51.100.7", "203.0.113.9", "2001:db8::1"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("usable = %v, want %v", got, want)
	}
}
