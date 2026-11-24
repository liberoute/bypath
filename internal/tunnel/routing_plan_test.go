package tunnel

import (
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/engine"
)

// TestPlanMatchesGeneratedXrayRules proves the panel's explanation and the
// engine config come from the same plan: every plan entry that is not skipped
// must appear as the corresponding xray rule, in the same order.
func TestPlanMatchesGeneratedXrayRules(t *testing.T) {
	writeXrayGeoDat(t, "geoip.dat", []string{"DE"})
	writeXrayGeoDat(t, "geosite.dat", []string{"CATEGORY-DE"})

	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "geoip:de", Outbound: "direct"},
		{Match: "geosite:de", Outbound: "direct"},
		{Match: "domain:de", Outbound: "direct"},
		{Match: "domain_suffix:carrier.example", Outbound: "deny"},
		{Match: "ip_cidr:203.0.113.0/24", Outbound: "proxy"},
		{Match: "default", Outbound: "proxy"},
	}
	cg.LocalDNSRules = []LocalDNSRule{{Server: "192.0.2.53", Domains: []string{"home"}}}

	file, err := cg.Generate(&engine.Engine{Name: "xray"}, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	rules := getXrayRules(t, loadJSON(t, file))

	want := []map[string]interface{}{
		// The tunnel resolver pin: xray dispatches every https resolver through
		// the router, so the DoH endpoint must stay on the proxy even when a
		// whitelist or geoip rule covers its address.
		{"ip": []string{"8.8.8.8/32"}, "outboundTag": "proxy"},
		{"ip": []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128"}, "outboundTag": "direct"},
		{"domain": []string{"domain:home"}, "outboundTag": "direct"},
		{"ip": []string{"geoip:de"}, "outboundTag": "direct"},
		{"domain": []string{"geosite:CATEGORY-DE"}, "outboundTag": "direct"},
		{"domain": []string{"full:de"}, "outboundTag": "direct"},
		{"domain": []string{"domain:carrier.example"}, "outboundTag": "block"},
		{"ip": []string{"203.0.113.0/24"}, "outboundTag": "proxy"},
	}
	// The plan still carries a default entry for the panel, but a proxy final
	// needs no generated rule: xray's dispatcher falls back to outbounds[0], and
	// an all-addresses rule would be redundant.
	if len(rules) != len(want) {
		t.Fatalf("generated %d rules, want %d: %v", len(rules), len(want), rules)
	}
	for i := range want {
		for key, value := range want[i] {
			got := rules[i][key]
			if !equalRuleValue(got, value) {
				t.Errorf("rule %d %s = %v, want %v", i, key, got, value)
			}
		}
	}

	plan := cg.XrayRoutingPlan()
	if len(plan) != len(want)+1 {
		t.Fatalf("plan has %d entries, want %d", len(plan), len(want)+1)
	}
	if plan[0].Scope != "dns-pin" || plan[0].Kind != "ip_cidr" {
		t.Errorf("plan resolver pin = %+v", plan[0])
	}
	if plan[4].Kind != "geosite" || plan[4].Resolved != "CATEGORY-DE" {
		t.Errorf("plan geosite entry = %+v, want resolved CATEGORY-DE", plan[4])
	}
	if plan[len(plan)-1].Kind != "default" || plan[len(plan)-1].Outbound != "proxy" {
		t.Errorf("plan default = %+v", plan[len(plan)-1])
	}
}

func equalRuleValue(got, want interface{}) bool {
	switch w := want.(type) {
	case string:
		s, ok := got.(string)
		return ok && s == w
	case []string:
		list, ok := got.([]interface{})
		if !ok || len(list) != len(w) {
			return false
		}
		for i := range w {
			if list[i] != w[i] {
				return false
			}
		}
		return true
	}
	return false
}

func TestPlanLegacyOrderAndDefault(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.WhitelistCountries = []string{"zz"} // no geoip.dat category: skipped
	cg.ForceProxyDomains = []string{"must-tunnel.example"}
	cg.BypassDomains = []string{"bypass.example"}
	cg.LocalDNSRules = []LocalDNSRule{{Server: "10.0.0.1", Domains: []string{"lan"}}}

	plan := cg.XrayRoutingPlan()
	kinds := make([]string, len(plan))
	for i, entry := range plan {
		kinds[i] = entry.Scope
	}
	want := []string{"dns-pin", "builtin", "force-proxy", "local-dns", "bypass", "country", "country", "default"}
	if len(kinds) != len(want) {
		t.Fatalf("plan scopes = %v, want %v", kinds, want)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("plan scopes = %v, want %v", kinds, want)
		}
	}
	// The legacy route emits a geosite rule before the geoip rule for the same
	// country list; both are skipped here because no .dat category exists.
	if plan[5].Skip == "" || plan[5].Kind != "geosite" {
		t.Errorf("missing geosite category was not marked skipped: %+v", plan[5])
	}
	if plan[6].Skip == "" || plan[6].Kind != "geoip" {
		t.Error("missing geoip category was not marked skipped")
	}
	if plan[7].Outbound != "proxy" {
		t.Errorf("legacy default = %q, want proxy", plan[7].Outbound)
	}
}

func TestPlanDenyDefaultBecomesBlock(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{{Match: "default", Outbound: "deny"}}

	plan := cg.XrayRoutingPlan()
	last := plan[len(plan)-1]
	if last.Kind != "default" || last.Outbound != "deny" {
		t.Fatalf("plan default = %+v", last)
	}
	if got := EffectiveOutbound(last.Outbound); got != xrayBlockOutboundTag {
		t.Fatalf("EffectiveOutbound(deny) = %q, want block", got)
	}
}

// TestDirectDefaultWithSkippedProxyRuleIsRefused is the R2-15 regression: when a
// geo asset the operator needs for a proxy or deny rule is unusable, that rule
// is skipped and its traffic falls to the DIRECT default. Generation must fail
// instead of emitting a policy broader than the operator's.
func TestDirectDefaultWithSkippedProxyRuleIsRefused(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "geosite:xq", Outbound: "proxy"},
		{Match: "default", Outbound: "direct"},
	}
	for _, engineName := range []string{"sing-box", "xray"} {
		path, err := cg.Generate(&engine.Engine{Name: engineName}, testVlessLink())
		if err == nil {
			t.Fatalf("%s generated a config despite an unusable proxy rule: %s", engineName, path)
		}
		if !strings.Contains(err.Error(), "DIRECT default") {
			t.Errorf("%s refusal does not explain the DIRECT default: %v", engineName, err)
		}
	}

	// A usable asset makes the same policy generatable.
	writeValidGeoRuleSet(t, "geosite", "xq")
	if _, err := cg.Generate(&engine.Engine{Name: "sing-box"}, testVlessLink()); err != nil {
		t.Fatalf("usable asset still refused: %v", err)
	}
}

// TestDirectDefaultWithSkippedDirectRuleIsAllowed is the control: a skipped
// DIRECT rule narrows the direct set and cannot leak proxy traffic, so it must
// not abort generation.
func TestDirectDefaultWithSkippedDirectRuleIsAllowed(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "geosite:de", Outbound: "direct"},
		{Match: "default", Outbound: "direct"},
	}
	if _, err := cg.Generate(&engine.Engine{Name: "sing-box"}, testVlessLink()); err != nil {
		t.Fatalf("a skipped DIRECT rule aborted generation: %v", err)
	}
}
