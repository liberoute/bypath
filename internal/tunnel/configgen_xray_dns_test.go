package tunnel

import (
	"testing"

	"github.com/liberoute/bypath/internal/engine"
)

func generateXrayConfig(t *testing.T, cg *ConfigGenerator) map[string]interface{} {
	t.Helper()
	path, err := cg.Generate(&engine.Engine{Name: "xray"}, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return loadJSON(t, path)
}

func xrayDNSServers(t *testing.T, cfg map[string]interface{}) []map[string]interface{} {
	t.Helper()
	dns, ok := cfg["dns"].(map[string]interface{})
	if !ok {
		t.Fatal("missing dns section")
	}
	raw, _ := dns["servers"].([]interface{})
	servers := make([]map[string]interface{}, len(raw))
	for i, item := range raw {
		servers[i], _ = item.(map[string]interface{})
	}
	return servers
}

func dnsServerWithDomain(servers []map[string]interface{}, domain string) map[string]interface{} {
	for _, server := range servers {
		for _, found := range stringList(server["domains"]) {
			if found == domain {
				return server
			}
		}
	}
	return nil
}

// TestXrayDNS_TunnelResolverFirstNoFallback pins the rebuilt DNS section. xray
// dials every https resolver through its router, so the tunnel resolver is the
// only path for proxy names: it is listed first (the no-match default once the
// fallback chain is disabled) and the local plaintext servers are never used as
// a fallback for it.
func TestXrayDNS_TunnelResolverFirstNoFallback(t *testing.T) {
	cfg := generateXrayConfig(t, NewConfigGenerator(t.TempDir()))
	dns := cfg["dns"].(map[string]interface{})
	servers := xrayDNSServers(t, cfg)

	if len(servers) == 0 {
		t.Fatal("dns.servers is empty")
	}
	first := servers[0]
	if first["address"] != "https://8.8.8.8/dns-query" {
		t.Fatalf("first resolver = %v, want the tunnel DoH resolver", first["address"])
	}
	if first["skipFallback"] != true {
		t.Fatalf("tunnel resolver is eligible for plaintext fallback: %v", first)
	}
	if len(stringList(first["domains"])) != 0 {
		t.Fatalf("tunnel resolver must match every name: %v", first)
	}
	if dns["disableFallback"] != true {
		t.Fatalf("dns.disableFallback = %v, want true", dns["disableFallback"])
	}
	if dns["queryStrategy"] != "UseIPv4" {
		t.Fatalf("dns.queryStrategy = %v, want UseIPv4", dns["queryStrategy"])
	}
	for _, server := range servers {
		// xray has no per-server outbound field; a proxyTag here would be a
		// silent no-op that reads as a containment guarantee.
		if _, has := server["proxyTag"]; has {
			t.Fatalf("ineffective proxyTag present: %v", server)
		}
		if server["skipFallback"] != true {
			t.Fatalf("resolver %v can be reached as a fallback", server)
		}
	}
}

// TestXrayDNS_ProxyNamesHaveNoDirectServer is the R2-03 leak contract: nothing
// but the server-name bootstrap may resolve outside the tunnel, so a proxied
// name can never be sent to the local plaintext resolver.
func TestXrayDNS_ProxyNamesHaveNoDirectServer(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.LocalDNSRules = []LocalDNSRule{{Server: "192.168.1.1:53", Domains: []string{"home", "lan"}}}
	servers := xrayDNSServers(t, generateXrayConfig(t, cg))

	local := dnsServerWithDomain(servers, "domain:home")
	if local == nil || dnsServerWithDomain(servers, "domain:lan") == nil {
		t.Fatalf("local DNS rule not scoped in the DNS section: %v", servers)
	}
	if local["address"] != "192.168.1.1:53" {
		t.Fatalf("local DNS address = %v", local["address"])
	}
	if local["skipFallback"] != true {
		t.Fatalf("local resolver is eligible for other names: %v", local)
	}
	// A server reachable for an unscoped query would see every proxied name.
	for i, server := range servers {
		if i == 0 {
			continue
		}
		if len(stringList(server["domains"])) == 0 {
			t.Fatalf("unscoped resolver can see proxied names: %v", server)
		}
	}
	for _, domain := range []string{"domain:blocked.example", "geosite:ir"} {
		if server := dnsServerWithDomain(servers, domain); server != nil {
			t.Fatalf("proxied class %q classified as direct: %v", domain, server)
		}
	}
}

// TestXrayDNS_BootstrapScopedToServerName keeps the one intentional exception:
// the proxy server's own name resolves over direct DoH so the tunnel can be
// established, and that exception is scoped to that exact name.
func TestXrayDNS_BootstrapScopedToServerName(t *testing.T) {
	servers := xrayDNSServers(t, generateXrayConfig(t, NewConfigGenerator(t.TempDir())))

	bootstrap := dnsServerWithDomain(servers, "full:server.example.com")
	if bootstrap == nil {
		t.Fatalf("bootstrap resolver for the server name missing: %v", servers)
	}
	if bootstrap["address"] != "https://1.1.1.1/dns-query" {
		t.Fatalf("bootstrap address = %v, want direct DoH", bootstrap["address"])
	}
	if bootstrap["skipFallback"] != true {
		t.Fatalf("bootstrap resolver is eligible for other names: %v", bootstrap)
	}
}

// TestXrayCountrySplit_GenerationRefused pins the T4 gate: the split is not
// emitted for an engine that cannot route its resolver through the tunnel.
func TestXrayCountrySplit_GenerationRefused(t *testing.T) {
	writeXrayGeoDat(t, "geoip.dat", []string{"IR"})
	writeXrayGeoDat(t, "geosite.dat", []string{"CATEGORY-IR"})

	cg := NewConfigGenerator(t.TempDir())
	cg.CountrySplit = "ir"
	cg.RoutingRules = []RoutingRule{{Match: "default", Outbound: "proxy"}}

	if _, err := cg.Generate(&engine.Engine{Name: "xray"}, testVlessLink()); err == nil {
		t.Fatal("xray generated a config for a country split")
	} else if err.Error() != xraySplitRefusal {
		t.Fatalf("refusal = %q, want %q", err, xraySplitRefusal)
	}
}

// TestXrayCountrySplit_PlanExplainsRefusal keeps the panel honest: the plan
// still lists the split entries, each with the refusal as its skip reason.
func TestXrayCountrySplit_PlanExplainsRefusal(t *testing.T) {
	writeXrayGeoDat(t, "geoip.dat", []string{"IR"})
	writeXrayGeoDat(t, "geosite.dat", []string{"CATEGORY-IR"})

	cg := NewConfigGenerator(t.TempDir())
	cg.CountrySplit = "ir"
	cg.RoutingRules = []RoutingRule{{Match: "default", Outbound: "proxy"}}

	var split []PlanEntry
	for _, entry := range cg.XrayRoutingPlan() {
		if entry.Scope == "country-split" {
			split = append(split, entry)
		}
	}
	if len(split) != 2 {
		t.Fatalf("plan split entries = %d, want 2: %+v", len(split), split)
	}
	for _, entry := range split {
		if entry.Skip != xraySplitRefusal {
			t.Errorf("split entry %s skip = %q, want the xray refusal", entry.Value, entry.Skip)
		}
	}
}

