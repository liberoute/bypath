package tunnel

import (
	"testing"

	"github.com/liberoute/bypath/internal/config"
)

func singboxRuleIndexWith(t *testing.T, rules []map[string]interface{}, key, value string) int {
	t.Helper()
	for i, r := range rules {
		if list := stringList(r[key]); len(list) == 1 && list[0] == value {
			return i
		}
	}
	return -1
}

// singboxRuleSetIndex finds the first rule that routes a rule_set reference. A
// resolve rule for the same tag may precede the route rule, so actions are
// filtered explicitly.
func singboxRuleSetIndex(t *testing.T, rules []map[string]interface{}, tag string) int {
	t.Helper()
	for i, r := range rules {
		if r["action"] != "route" {
			continue
		}
		for _, ref := range ruleSetRefs(r) {
			if ref == tag {
				return i
			}
		}
	}
	return -1
}

func singboxRuleSetDefined(cfg map[string]interface{}, tag string) bool {
	route, _ := cfg["route"].(map[string]interface{})
	defs, _ := route["rule_set"].([]interface{})
	for _, raw := range defs {
		if def, ok := raw.(map[string]interface{}); ok && def["tag"] == tag {
			return true
		}
	}
	return false
}

// TestSingboxCountrySplit_RulesAfterUserRulesBeforeDefault pins the split
// ordering: an explicit operator rule still wins, the two split rules follow it,
// and unmatched traffic keeps the default proxy.
func TestSingboxCountrySplit_RulesAfterUserRulesBeforeDefault(t *testing.T) {
	writeValidGeoRuleSet(t, "geosite", "ir")
	writeValidGeoRuleSet(t, "geoip", "ir")

	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:internal.example", Outbound: "proxy"},
		{Match: "default", Outbound: "proxy"},
	}
	cg.CountrySplit = "ir"

	cfg := loadJSON(t, mustGenerateSingBox(t, cg))
	rules := getSingboxRules(t, cfg)

	userIdx := singboxRuleIndexWith(t, rules, "domain_suffix", "internal.example")
	geositeIdx := singboxRuleSetIndex(t, rules, "geosite-ir")
	geoipIdx := singboxRuleSetIndex(t, rules, "geoip-ir")
	if userIdx < 0 || geositeIdx < 0 || geoipIdx < 0 {
		t.Fatalf("missing rule: user=%d geosite=%d geoip=%d\n%v", userIdx, geositeIdx, geoipIdx, rules)
	}
	if !(userIdx < geositeIdx && geositeIdx < geoipIdx) {
		t.Errorf("split order violated: user=%d geosite=%d geoip=%d", userIdx, geositeIdx, geoipIdx)
	}
	for _, idx := range []int{geositeIdx, geoipIdx} {
		if rules[idx]["action"] != "route" || rules[idx]["outbound"] != "direct" {
			t.Errorf("split rule %d = %v, want route direct", idx, rules[idx])
		}
	}
	if final, _ := cfg["route"].(map[string]interface{})["final"].(string); final != "proxy" {
		t.Errorf("route.final = %q, want proxy", final)
	}
	if !singboxRuleSetDefined(cfg, "geosite-ir") || !singboxRuleSetDefined(cfg, "geoip-ir") {
		t.Error("split rules reference an undeclared rule_set")
	}
}

// TestSingboxCountrySplit_MissingAssetsStayProxied is the fail-closed contract:
// with no usable .srs files the split emits nothing, so every destination —
// including the split country's — keeps the default proxy outbound.
func TestSingboxCountrySplit_MissingAssetsStayProxied(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{{Match: "default", Outbound: "proxy"}}
	cg.CountrySplit = "qq"

	cfg := loadJSON(t, mustGenerateSingBox(t, cg))
	for _, r := range getSingboxRules(t, cfg) {
		for _, tag := range ruleSetRefs(r) {
			if tag == "geosite-qq" || tag == "geoip-qq" {
				t.Fatalf("missing asset still produced a split rule: %v", r)
			}
		}
	}
	if singboxRuleSetDefined(cfg, "geosite-qq") || singboxRuleSetDefined(cfg, "geoip-qq") {
		t.Fatal("missing asset still produced a rule_set definition")
	}
	if final, _ := cfg["route"].(map[string]interface{})["final"].(string); final != "proxy" {
		t.Errorf("route.final = %q, want proxy", final)
	}
}

// TestSingboxCountrySplit_BrokenAssetDropsOnlyThatRule proves the two halves are
// gated independently: an unusable geosite rule set must not suppress a valid
// geoip rule, and the unusable half stays on the proxy.
func TestSingboxCountrySplit_BrokenAssetDropsOnlyThatRule(t *testing.T) {
	writeBrokenGeoFixture(t, "geosite-qq.srs")
	writeValidGeoRuleSet(t, "geoip", "qq")

	cg := NewConfigGenerator(t.TempDir())
	cg.CountrySplit = "qq"

	cfg := loadJSON(t, mustGenerateSingBox(t, cg))
	rules := getSingboxRules(t, cfg)
	if idx := singboxRuleSetIndex(t, rules, "geosite-qq"); idx >= 0 {
		t.Fatalf("broken geosite asset still produced a rule: %v", rules[idx])
	}
	idx := singboxRuleSetIndex(t, rules, "geoip-qq")
	if idx < 0 {
		t.Fatal("valid geoip asset produced no split rule")
	}
	if rules[idx]["outbound"] != "direct" {
		t.Errorf("geoip split rule outbound = %v, want direct", rules[idx]["outbound"])
	}
}

// TestRoutingPlan_CountrySplit reports split entries to the panel with the
// engine-specific tag or the reason the asset is unusable.
func TestRoutingPlan_CountrySplit(t *testing.T) {
	writeValidGeoRuleSet(t, "geosite", "ir")
	writeXrayGeoDat(t, "geoip.dat", []string{"IR"})

	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{{Match: "default", Outbound: "proxy"}}
	cg.CountrySplit = "ir"

	sb := cg.RoutingPlan("sing-box")
	if len(sb) < 3 {
		t.Fatalf("sing-box plan too short: %+v", sb)
	}
	geosite, geoip := sb[len(sb)-3], sb[len(sb)-2]
	if geosite.Scope != "country-split" || geosite.Resolved != "geosite-ir" || geosite.Skip != "" {
		t.Errorf("sing-box split geosite = %+v", geosite)
	}
	if geoip.Scope != "country-split" || geoip.Skip == "" {
		t.Errorf("sing-box split geoip = %+v, want a skip reason (no .srs)", geoip)
	}
	if last := sb[len(sb)-1]; last.Kind != "default" || last.Outbound != "proxy" {
		t.Errorf("sing-box plan default = %+v", last)
	}

	xray := cg.RoutingPlan("xray")
	geosite, geoip = xray[len(xray)-3], xray[len(xray)-2]
	// xray cannot route the split's resolver through the tunnel, so the plan
	// reports both entries as skipped with the refusal reason.
	if geosite.Scope != "country-split" || geosite.Skip != xraySplitRefusal {
		t.Errorf("xray split geosite = %+v, want the xray refusal", geosite)
	}
	if geoip.Scope != "country-split" || geoip.Skip != xraySplitRefusal {
		t.Errorf("xray split geoip = %+v, want the xray refusal", geoip)
	}
}

// TestRoutingPlan_NoCountrySplitKeepsProxyOnly guards the shipped default: an
// empty CountrySplit adds no entry and the plan stays a single catch-all.
func TestRoutingPlan_NoCountrySplitKeepsProxyOnly(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{{Match: "default", Outbound: "proxy"}}

	plan := cg.SingboxRoutingPlan()
	for _, entry := range plan {
		if entry.Scope == "country-split" {
			t.Fatalf("split entry emitted without config: %+v", entry)
		}
	}
	if last := plan[len(plan)-1]; last.Kind != "default" || last.Outbound != "proxy" {
		t.Fatalf("default = %+v", last)
	}
}

// TestTunnelManagerCarriesCountrySplit pins that standalone tunnels (started
// from the manager rather than the gateway) apply the same split policy.
func TestTunnelManagerCarriesCountrySplit(t *testing.T) {
	cfg := &config.Config{}
	cfg.Routing.CountrySplit = "ir"

	m := NewManager(cfg, nil)
	if m.configGen.CountrySplit != "ir" {
		t.Fatalf("manager generator CountrySplit = %q, want %q", m.configGen.CountrySplit, "ir")
	}
}
