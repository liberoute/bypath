package tunnel

import (
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/engine"
)

func ruleHasProbeSuffix(rule map[string]interface{}, outbound string) bool {
	tag, _ := rule["outbound"].(string)
	if tag == "" {
		tag, _ = rule["outboundTag"].(string)
	}
	if tag != outbound {
		return false
	}
	list, _ := rule["domain_suffix"].([]interface{})
	for _, raw := range list {
		for _, probe := range StartupProbeDomains {
			if raw == probe {
				return true
			}
		}
	}
	list, _ = rule["domain"].([]interface{})
	for _, raw := range list {
		s, _ := raw.(string)
		for _, probe := range StartupProbeDomains {
			if s == "domain:"+probe {
				return true
			}
		}
	}
	return false
}

func indexOfRule(rules []map[string]interface{}, match func(map[string]interface{}) bool) int {
	for i, rule := range rules {
		if match(rule) {
			return i
		}
	}
	return -1
}

// A startup HTTPS probe must never be able to pass on a DIRECT rule: the forced
// probe rule has to precede an operator rule that routes the same host direct.
func TestSingboxProbeRulePrecedesOperatorDirectRule(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:www.example.com", Outbound: "direct"},
		{Match: "default", Outbound: "direct"},
	}

	cfg := loadJSON(t, mustGenerateSingBox(t, cg))
	rules := getSingboxRules(t, cfg)
	probeIdx := indexOfRule(rules, func(r map[string]interface{}) bool { return ruleHasProbeSuffix(r, "proxy") })
	directIdx := indexOfRule(rules, func(r map[string]interface{}) bool {
		return r["outbound"] == "direct" && ruleMatchesDomain(r, "www.example.com")
	})
	if probeIdx < 0 {
		t.Fatalf("no forced probe rule in %v", rules)
	}
	if directIdx < 0 {
		t.Fatalf("operator direct rule missing in %v", rules)
	}
	if probeIdx >= directIdx {
		t.Fatalf("probe rule (idx %d) must precede the direct rule (idx %d)", probeIdx, directIdx)
	}
	route := cfg["route"].(map[string]interface{})
	if route["final"] != "direct" {
		t.Fatalf("route.final = %v, want the operator's direct default", route["final"])
	}
}

// The legacy generation path (no routing rules) must force the probes too, or a
// country/whitelist DIRECT rule could satisfy the startup check.
func TestSingboxLegacyProbeRulePrecedesBypassRule(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.WhitelistCountries = []string{"xx"}
	cg.BypassDomains = []string{"www.example.com", "www.gstatic.com"}

	rules := getSingboxRules(t, loadJSON(t, mustGenerateSingBox(t, cg)))
	probeIdx := indexOfRule(rules, func(r map[string]interface{}) bool { return ruleHasProbeSuffix(r, "proxy") })
	bypassIdx := indexOfRule(rules, func(r map[string]interface{}) bool {
		return r["outbound"] == "direct" && ruleMatchesDomain(r, "www.example.com")
	})
	if probeIdx < 0 || bypassIdx < 0 {
		t.Fatalf("probe=%d bypass=%d in %v", probeIdx, bypassIdx, rules)
	}
	if probeIdx >= bypassIdx {
		t.Fatalf("probe rule (idx %d) must precede bypass (idx %d)", probeIdx, bypassIdx)
	}
}

func TestXrayProbeRulePrecedesOperatorDirectRule(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:www.example.com", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}

	file, err := cg.Generate(&engine.Engine{Name: "xray"}, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	rules := getXrayRules(t, loadJSON(t, file))
	probeIdx := indexOfRule(rules, func(r map[string]interface{}) bool { return ruleHasProbeSuffix(r, "proxy") })
	directIdx := indexOfRule(rules, func(r map[string]interface{}) bool {
		return r["outboundTag"] == "direct" && ruleMatchesDomain(r, "www.example.com")
	})
	if probeIdx < 0 {
		t.Fatalf("no forced probe rule in %v", rules)
	}
	if directIdx < 0 {
		t.Fatalf("operator direct rule missing in %v", rules)
	}
	if probeIdx >= directIdx {
		t.Fatalf("probe rule (idx %d) must precede the direct rule (idx %d)", probeIdx, directIdx)
	}
}

// The explain plan must describe the same forced rule the engine emits.
func TestProbeRuleAppearsInBothPlansBeforeDirectRules(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:www.gstatic.com", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
	for _, name := range []string{"sing-box", "xray"} {
		plan := cg.RoutingPlan(name)
		probe, direct := -1, -1
		for i, entry := range plan {
			if entry.Scope == "probe" && EffectiveOutbound(entry.Outbound) == "proxy" {
				probe = i
			}
			if entry.Scope == "rule" && EffectiveOutbound(entry.Outbound) == "direct" &&
				(entry.Value == "www.gstatic.com" || strings.Contains(strings.Join(entry.Domains, ","), "gstatic.com")) {
				direct = i
			}
		}
		if probe < 0 || direct < 0 || probe >= direct {
			t.Fatalf("%s plan order wrong: probe=%d direct=%d (%+v)", name, probe, direct, plan)
		}
	}
}

func ruleMatchesDomain(rule map[string]interface{}, host string) bool {
	if list, ok := rule["domain_suffix"].([]interface{}); ok {
		for _, raw := range list {
			if raw == host || raw == strings.TrimPrefix(host, "www.") {
				return true
			}
		}
	}
	if list, ok := rule["domain"].([]interface{}); ok {
		for _, raw := range list {
			if s, _ := raw.(string); s == "domain:"+host || s == "domain:"+strings.TrimPrefix(host, "www.") {
				return true
			}
		}
	}
	return false
}
