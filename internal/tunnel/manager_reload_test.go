package tunnel

import (
	"testing"

	"github.com/liberoute/bypath/internal/config"
)

// TestManagerReloadRepublishesPolicy pins the lifecycle contract for tunnels
// started through the API: the manager used to keep the daemon-start snapshot,
// so a reloaded routing policy never reached them.
func TestManagerReloadRepublishesPolicy(t *testing.T) {
	start := &config.Config{}
	m := NewManager(start, nil)

	next := &config.Config{}
	next.Routing.CountrySplit = "ir"
	next.Routing.Rules = []config.RoutingRule{
		{Match: "domain_suffix:internal.example", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
	next.Routing.ExternalOutbounds = map[string]string{"office": "socks5://192.0.2.10:1080"}
	next.Gateway.LocalDNS = []config.LocalDNSEntry{{Server: "192.0.2.53", Domains: []string{"home"}}}
	next.Whitelist.BypassDomains = []string{"probe.example"}

	m.Reload(next)

	cg := m.configGen
	if cg.CountrySplit != "ir" {
		t.Fatalf("generator country split = %q, want ir", cg.CountrySplit)
	}
	if len(cg.RoutingRules) != 2 || cg.RoutingRules[0].Match != "domain_suffix:internal.example" {
		t.Fatalf("generator routing rules = %+v", cg.RoutingRules)
	}
	if cg.ExternalOutbounds["office"] != "socks5://192.0.2.10:1080" {
		t.Fatalf("generator external outbounds = %+v", cg.ExternalOutbounds)
	}
	if len(cg.LocalDNSRules) != 1 || cg.LocalDNSRules[0].Server != "192.0.2.53" {
		t.Fatalf("generator local DNS = %+v", cg.LocalDNSRules)
	}
	if len(cg.BypassDomains) != 1 || cg.BypassDomains[0] != "probe.example" {
		t.Fatalf("generator bypass domains = %+v", cg.BypassDomains)
	}

	// The plan the manager will hand a new tunnel must show the split, not the
	// proxy-only default it started with.
	plan := cg.SingboxRoutingPlan()
	split := 0
	for _, entry := range plan {
		if entry.Scope == "country-split" {
			split++
		}
	}
	if split != 2 {
		t.Fatalf("reloaded plan has %d country-split entries, want 2 (%+v)", split, plan)
	}
}

// TestManagerCopiesDoNotAliasConfig guards against a later config mutation
// changing a running manager's policy without a reload.
func TestManagerCopiesDoNotAliasConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.Routing.Rules = []config.RoutingRule{{Match: "domain:keep.example", Outbound: "direct"}}
	cfg.Routing.ExternalOutbounds = map[string]string{"office": "socks5://192.0.2.10:1080"}

	m := NewManager(cfg, nil)
	cfg.Routing.Rules[0].Match = "domain:changed.example"
	cfg.Routing.ExternalOutbounds["office"] = "socks5://198.51.100.10:1080"

	if m.configGen.RoutingRules[0].Match != "domain:keep.example" {
		t.Fatalf("manager aliased the rule slice: %+v", m.configGen.RoutingRules)
	}
	if m.configGen.ExternalOutbounds["office"] != "socks5://192.0.2.10:1080" {
		t.Fatalf("manager aliased the outbound map: %+v", m.configGen.ExternalOutbounds)
	}
}
