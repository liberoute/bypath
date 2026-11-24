package tunnel

import (
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/engine"
)

// probeInboundTagOf reports the single inbound condition of a sing-box rule.
func probeInboundTagOf(rule map[string]interface{}) string {
	list, _ := rule["inbound"].([]interface{})
	if len(list) != 1 {
		return ""
	}
	tag, _ := list[0].(string)
	return tag
}

// xrayInboundTagOf reports the single inboundTag condition of an xray rule.
func xrayInboundTagOf(rule map[string]interface{}) string {
	list, _ := rule["inboundTag"].([]interface{})
	if len(list) != 1 {
		return ""
	}
	tag, _ := list[0].(string)
	return tag
}

func matchesProbeDomain(rule map[string]interface{}) bool {
	for _, key := range []string{"domain_suffix", "domain"} {
		list, _ := rule[key].([]interface{})
		for _, raw := range list {
			if probeHostMatches(raw) {
				return true
			}
		}
	}
	return false
}

func probeHostMatches(raw interface{}) bool {
	s, _ := raw.(string)
	s = strings.TrimPrefix(s, "domain:")
	s = strings.TrimPrefix(s, "full:")
	s = strings.TrimPrefix(s, ".")
	host := strings.TrimPrefix(strings.ToLower(s), "www.")
	for _, probe := range StartupProbeDomains {
		if host == probe || strings.HasSuffix(host, "."+probe) {
			return true
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

func singboxInboundByTag(cfg map[string]interface{}, tag string) map[string]interface{} {
	list, _ := cfg["inbounds"].([]interface{})
	for _, raw := range list {
		inbound, _ := raw.(map[string]interface{})
		if inbound["tag"] == tag {
			return inbound
		}
	}
	return nil
}

// The forced probe route must be carried by the daemon's own inbound: the
// client listener keeps the operator's DIRECT and deny rules, including for
// the probe hostnames.
func TestProbeInboundCarriesForcedRouteOnlyForItsOwnTraffic(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.ProbePort = 3999
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:www.example.com", Outbound: "block"},
		{Match: "default", Outbound: "direct"},
	}

	cfg := loadJSON(t, mustGenerateSingBox(t, cg))
	inbound := singboxInboundByTag(cfg, ProbeInboundTag)
	if inbound == nil {
		t.Fatalf("no %s inbound in %v", ProbeInboundTag, cfg["inbounds"])
	}
	if inbound["listen"] != "127.0.0.1" || inbound["listen_port"] != float64(3999) {
		t.Fatalf("probe inbound is not the reserved loopback port: %v", inbound)
	}
	if _, ok := inbound["users"]; ok {
		t.Fatalf("probe inbound must not accept credentials: %v", inbound)
	}

	rules := getSingboxRules(t, cfg)
	forced := indexOfRule(rules, func(r map[string]interface{}) bool {
		return probeInboundTagOf(r) == ProbeInboundTag && r["outbound"] == "proxy" && matchesProbeDomain(r)
	})
	if forced < 0 {
		t.Fatalf("no inbound-scoped probe route in %v", rules)
	}
	closed := indexOfRule(rules, func(r map[string]interface{}) bool {
		return probeInboundTagOf(r) == ProbeInboundTag && r["action"] == "reject" && !matchesProbeDomain(r)
	})
	if closed < 0 || closed <= forced {
		t.Fatalf("probe inbound is not closed after its forced route (forced=%d closed=%d): %v", forced, closed, rules)
	}

	// The operator's deny rule for the same host must survive unmodified and
	// must not be restricted to the probe inbound (that would exempt clients).
	deny := indexOfRule(rules, func(r map[string]interface{}) bool {
		return r["action"] == "reject" && r["outbound"] == nil && matchesProbeDomain(r)
	})
	if deny < 0 {
		t.Fatalf("operator deny rule for a probe host is missing: %v", rules)
	}
	if tag := probeInboundTagOf(rules[deny]); tag != "" {
		t.Fatalf("operator deny rule was rewritten to inbound %q: %v", tag, rules[deny])
	}
	if route := cfg["route"].(map[string]interface{}); route["final"] != "direct" {
		t.Fatalf("route.final = %v, want the operator's direct default", route["final"])
	}

	// No forced route may exist without the inbound condition: that is exactly
	// the silent override this change removes.
	for i, rule := range rules {
		if rule["outbound"] == "proxy" && matchesProbeDomain(rule) && probeInboundTagOf(rule) != ProbeInboundTag {
			t.Fatalf("rule %d forces probe domains for every client: %v", i, rule)
		}
	}
}

// Without a reserved probe port no exemption may exist at all: the daemon then
// probes through the client listener and must accept the operator's policy.
func TestNoProbeExemptionWithoutProbePort(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:www.example.com", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}

	cfg := loadJSON(t, mustGenerateSingBox(t, cg))
	if singboxInboundByTag(cfg, ProbeInboundTag) != nil {
		t.Fatalf("probe inbound emitted without a reserved port")
	}
	for i, rule := range getSingboxRules(t, cfg) {
		if rule["outbound"] == "proxy" && matchesProbeDomain(rule) {
			t.Fatalf("rule %d still forces probe domains without an exemption inbound: %v", i, rule)
		}
	}
	if raw, _ := cfg["inbounds"].([]interface{}); len(raw) != 1 {
		t.Fatalf("unexpected extra inbounds: %v", raw)
	}
}

// The legacy path (no routing.rules) must scope the exception the same way; a
// bypass or country DIRECT rule must keep applying to client traffic.
func TestLegacyProbeRouteStaysInboundScoped(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.ProbePort = 3999
	cg.WhitelistCountries = []string{"xx"}
	cg.BypassDomains = []string{"www.example.com", "www.gstatic.com"}

	rules := getSingboxRules(t, loadJSON(t, mustGenerateSingBox(t, cg)))
	forced := indexOfRule(rules, func(r map[string]interface{}) bool {
		return probeInboundTagOf(r) == ProbeInboundTag && r["outbound"] == "proxy" && matchesProbeDomain(r)
	})
	bypass := indexOfRule(rules, func(r map[string]interface{}) bool {
		return r["outbound"] == "direct" && matchesProbeDomain(r)
	})
	if forced < 0 || bypass < 0 {
		t.Fatalf("forced=%d bypass=%d in %v", forced, bypass, rules)
	}
	if forced >= bypass {
		t.Fatalf("probe route (idx %d) must precede the bypass rule (idx %d)", forced, bypass)
	}
	if probeInboundTagOf(rules[bypass]) != "" {
		t.Fatalf("bypass rule was scoped to the probe inbound: %v", rules[bypass])
	}
}

func TestXrayProbeRouteIsInboundScoped(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.ProbePort = 3999
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:www.example.com", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}

	file, err := cg.Generate(&engine.Engine{Name: "xray"}, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cfg := loadJSON(t, file)
	inbounds, _ := cfg["inbounds"].([]interface{})
	foundProbe := false
	for _, raw := range inbounds {
		inbound, _ := raw.(map[string]interface{})
		if inbound["tag"] == ProbeInboundTag {
			foundProbe = true
			if inbound["listen"] != "127.0.0.1" || inbound["port"] != float64(3999) {
				t.Fatalf("xray probe inbound is not the reserved loopback port: %v", inbound)
			}
		}
	}
	if !foundProbe {
		t.Fatalf("no %s inbound in %v", ProbeInboundTag, inbounds)
	}

	rules := getXrayRules(t, cfg)
	forced := indexOfRule(rules, func(r map[string]interface{}) bool {
		return xrayInboundTagOf(r) == ProbeInboundTag && r["outboundTag"] == "proxy" && matchesProbeDomain(r)
	})
	closed := indexOfRule(rules, func(r map[string]interface{}) bool {
		return xrayInboundTagOf(r) == ProbeInboundTag && r["outboundTag"] == xrayBlockOutboundTag
	})
	if forced < 0 || closed <= forced {
		t.Fatalf("probe inbound is not forced then closed (forced=%d closed=%d): %v", forced, closed, rules)
	}
	direct := indexOfRule(rules, func(r map[string]interface{}) bool {
		return r["outboundTag"] == "direct" && matchesProbeDomain(r)
	})
	if direct < 0 {
		t.Fatalf("operator direct rule missing: %v", rules)
	}
	if tag := xrayInboundTagOf(rules[direct]); tag != "" {
		t.Fatalf("operator direct rule was rewritten to inbound %q: %v", tag, rules[direct])
	}
	for i, rule := range rules {
		if rule["outboundTag"] == "proxy" && matchesProbeDomain(rule) && xrayInboundTagOf(rule) != ProbeInboundTag {
			t.Fatalf("rule %d forces probe domains for every client: %v", i, rule)
		}
	}
}

// The client-facing plan and the explainer must not describe a probe exception
// that only exists for the daemon's own inbound.
func TestRoutingPlanHasNoProbeOverride(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:www.gstatic.com", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
	for _, name := range []string{"sing-box", "xray"} {
		plan := cg.RoutingPlan(name)
		direct := false
		for _, entry := range plan {
			if entry.Scope == "probe" {
				t.Fatalf("%s plan still contains a probe override: %+v", name, plan)
			}
			if entry.Scope == "rule" && EffectiveOutbound(entry.Outbound) == "direct" &&
				(strings.Contains(entry.Value, "gstatic.com") || strings.Contains(strings.Join(entry.Domains, ","), "gstatic.com")) {
				direct = true
			}
		}
		if !direct {
			t.Fatalf("%s plan lost the operator's direct rule: %+v", name, plan)
		}
	}
}
