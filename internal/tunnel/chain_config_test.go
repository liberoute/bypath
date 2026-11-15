package tunnel

import (
	"testing"

	"github.com/liberoute/bypath/internal/profile"
)

// chainLinks returns two distinguishable hops so DNS aggregation and tag
// mapping cannot pass by accident.
func chainLinks() []*profile.Link {
	return []*profile.Link{
		{
			Protocol: "vless",
			Address:  "entry.example.com",
			Port:     443,
			UUID:     "11111111-1111-1111-1111-111111111111",
			TLS:      true,
			SNI:      "entry.example.com",
		},
		{
			Protocol: "vless",
			Address:  "exit.example.com",
			Port:     443,
			UUID:     "22222222-2222-2222-2222-222222222222",
			TLS:      true,
			SNI:      "exit.example.com",
		},
	}
}

func chainOutboundTags(rules []map[string]interface{}) []string {
	var tags []string
	for _, r := range rules {
		if tag, ok := r["outbound"].(string); ok {
			tags = append(tags, tag)
		}
	}
	return tags
}

// TestChainConfig_RouteUsesExitHopAsProxy pins F-006: the entry config carries
// the user's policy and the chain's exit hop takes the place of the "proxy"
// outbound, so a rule written for a tunnel means the same thing in a chain.
func TestChainConfig_RouteUsesExitHopAsProxy(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:corp.example", Outbound: "direct"},
		{Match: "domain_suffix:tunnel.example", Outbound: "proxy"},
		{Match: "default", Outbound: "proxy"},
	}

	cfg := parseChainConfig(t, cg, "c1", chainLinks())
	route := cfg["route"].(map[string]interface{})
	exitTag := "chain-c1-hop-1"

	if route["final"] != exitTag {
		t.Fatalf("route.final = %v, want %s", route["final"], exitTag)
	}

	rules := getSingboxRules(t, cfg)
	tunnelRule := ruleByDomain(rules, "tunnel.example")
	if tunnelRule == nil {
		t.Fatalf("proxy rule missing: %v", rules)
	}
	if tunnelRule["outbound"] != exitTag {
		t.Errorf("proxy rule outbound = %v, want %s", tunnelRule["outbound"], exitTag)
	}
	directRule := ruleByDomain(rules, "corp.example")
	if directRule == nil || directRule["outbound"] != "direct" {
		t.Fatalf("direct rule = %v, want outbound direct", directRule)
	}
	for _, tag := range chainOutboundTags(rules) {
		if tag == "proxy" {
			t.Fatalf("chain route references a nonexistent %q outbound: %v", tag, rules)
		}
	}
}

// TestChainConfig_DNSBindsTunnelResolverToExitHop keeps the chain's queries off
// the local resolver: tunneled names use the chain's DoH path, and every hop's
// server domain resolves directly so the chain can bootstrap.
func TestChainConfig_DNSBindsTunnelResolverToExitHop(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{{Match: "default", Outbound: "proxy"}}

	cfg := parseChainConfig(t, cg, "c2", chainLinks())
	dns := cfg["dns"].(map[string]interface{})
	exitTag := "chain-c2-hop-1"

	if dns["final"] != "dns-tunnel" {
		t.Fatalf("dns.final = %v, want dns-tunnel", dns["final"])
	}

	var tunnelServer map[string]interface{}
	for _, raw := range dns["servers"].([]interface{}) {
		server := raw.(map[string]interface{})
		if server["tag"] == "dns-tunnel" {
			tunnelServer = server
		}
	}
	if tunnelServer == nil {
		t.Fatalf("no dns-tunnel server: %v", dns["servers"])
	}
	if tunnelServer["detour"] != exitTag {
		t.Errorf("dns-tunnel detour = %v, want %s", tunnelServer["detour"], exitTag)
	}
	if tunnelServer["type"] != "https" {
		t.Errorf("dns-tunnel type = %v, want https", tunnelServer["type"])
	}

	// Every hop's server must resolve directly, or the chain needs the tunnel
	// to reach the resolver that bootstraps the tunnel.
	bootstrapSeen := map[string]bool{}
	for _, raw := range dns["rules"].([]interface{}) {
		rule := raw.(map[string]interface{})
		if rule["server"] != "dns-direct" {
			continue
		}
		for _, domain := range stringList(rule["domain"]) {
			bootstrapSeen[domain] = true
		}
	}
	for _, want := range []string{"entry.example.com", "exit.example.com"} {
		if !bootstrapSeen[want] {
			t.Errorf("server domain %q has no direct bootstrap rule: %v", want, dns["rules"])
		}
	}
}

// TestChainConfig_DirectClassResolvesDirect proves the AD-01 classification
// applies to a chain too: a DIRECT name is not answered by the queued resolver.
func TestChainConfig_DirectClassResolvesDirect(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:corp.example", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}

	cfg := parseChainConfig(t, cg, "c3", chainLinks())
	if server := dnsRuleServerFor(t, cfg, "domain_suffix", "corp.example"); server != "dns-direct" {
		t.Fatalf("DIRECT domain class resolves via %q, want dns-direct", server)
	}
}

// TestChainConfig_DefaultDenyRejects keeps the deny spelling identical to a
// tunnel: a matcher-less reject after the user rules, with the exit hop still
// named as the final tag.
func TestChainConfig_DefaultDenyRejects(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:corp.example", Outbound: "direct"},
		{Match: "default", Outbound: "deny"},
	}

	cfg := parseChainConfig(t, cg, "c4", chainLinks())
	route := cfg["route"].(map[string]interface{})
	rules := getSingboxRules(t, cfg)
	last := rules[len(rules)-1]
	if last["action"] != "reject" {
		t.Fatalf("last rule = %v, want reject", last)
	}
	if route["final"] != "chain-c4-hop-1" {
		t.Errorf("route.final = %v, want chain-c4-hop-1", route["final"])
	}
}

// TestChainConfig_SplitAppliesToEntry keeps the opt-in split working through a
// chain: domestic geosite/geoip rules go DIRECT with declared rule sets.
func TestChainConfig_SplitAppliesToEntry(t *testing.T) {
	writeValidGeoRuleSet(t, "geosite", "ir")
	writeValidGeoRuleSet(t, "geoip", "ir")

	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{{Match: "default", Outbound: "proxy"}}
	cg.CountrySplit = "ir"

	cfg := parseChainConfig(t, cg, "c5", chainLinks())
	rules := getSingboxRules(t, cfg)

	geositeIdx := singboxRuleSetIndex(t, rules, "geosite-ir")
	geoipIdx := singboxRuleSetIndex(t, rules, "geoip-ir")
	if geositeIdx < 0 || geoipIdx < 0 {
		t.Fatalf("split rules missing: geosite=%d geoip=%d\n%v", geositeIdx, geoipIdx, rules)
	}
	for _, idx := range []int{geositeIdx, geoipIdx} {
		if rules[idx]["outbound"] != "direct" {
			t.Errorf("split rule %d outbound = %v, want direct", idx, rules[idx]["outbound"])
		}
	}
	if !singboxRuleSetDefined(cfg, "geosite-ir") || !singboxRuleSetDefined(cfg, "geoip-ir") {
		t.Error("split rules reference an undeclared rule_set")
	}
}

// TestChainConfig_ExternalOutboundReferencedByRule proves a rule naming an
// external outbound produces a loadable chain config, not a dangling tag.
func TestChainConfig_ExternalOutboundReferencedByRule(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.ExternalOutbounds = map[string]string{"office": "socks5://192.0.2.10:1080"}
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:office.example", Outbound: "office"},
		{Match: "default", Outbound: "proxy"},
	}

	cfg := parseChainConfig(t, cg, "c6", chainLinks())
	tags := map[string]bool{}
	for _, ob := range getOutbounds(t, cfg) {
		if tag, ok := ob["tag"].(string); ok {
			tags[tag] = true
		}
	}
	if !tags["office"] {
		t.Fatalf("external outbound %q is not defined: %v", "office", tags)
	}
	r := ruleByDomain(getSingboxRules(t, cfg), "office.example")
	if r == nil || r["outbound"] != "office" {
		t.Fatalf("rule for office.example = %v, want outbound office", r)
	}
}
