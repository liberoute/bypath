package tunnel

import (
	"testing"

	"github.com/liberoute/bypath/internal/engine"
)

// xrayAllAddressRule returns the rule whose ip condition covers every address
// (0.0.0.0/0). Under IPIfNonMatch an all-addresses condition is evaluated only
// in the second pass, after every domain and IP rule, so this is the shape a
// non-proxy default must use: a condition-less rule would match in the first
// pass and hide later geoip/ip_cidr rules from a domain destination (R2-12).
func xrayAllAddressRule(rules []map[string]interface{}) map[string]interface{} {
	for _, r := range rules {
		for _, ip := range stringList(r["ip"]) {
			if ip == "0.0.0.0/0" {
				return r
			}
		}
	}
	return nil
}

// xrayConditionlessRule returns any rule that matches without a domain or ip
// condition. Such a rule short-circuits the second IPIfNonMatch pass.
func xrayConditionlessRule(rules []map[string]interface{}) map[string]interface{} {
	for _, r := range rules {
		if _, hasDomain := r["domain"]; hasDomain {
			continue
		}
		if _, hasIP := r["ip"]; hasIP {
			continue
		}
		if r["outboundTag"] == nil {
			continue
		}
		return r
	}
	return nil
}

func generateXrayRules(t *testing.T, cg *ConfigGenerator) []map[string]interface{} {
	t.Helper()
	path, err := cg.Generate(&engine.Engine{Name: "xray"}, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return getXrayRules(t, loadJSON(t, path))
}

// TestXrayCatchAll_OmittedForProxyFinal pins F-005: with the proxy final xray
// already falls back to outbounds[0], so the generator must not emit any
// all-addresses or condition-less rule. The geoip rule must survive so a domain
// destination still reaches DIRECT after its address is resolved.
func TestXrayCatchAll_OmittedForProxyFinal(t *testing.T) {
	writeXrayGeoDat(t, "geoip.dat", []string{"DE"})

	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:carrier.example", Outbound: "direct"},
		{Match: "geoip:de", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
	rules := generateXrayRules(t, cg)

	if r := xrayAllAddressRule(rules); r != nil {
		t.Fatalf("all-addresses rule emitted for a proxy final: %v", r)
	}
	if r := xrayConditionlessRule(rules); r != nil {
		t.Fatalf("condition-less rule emitted for a proxy final: %v", r)
	}
	geoip := ruleHasIP(rules, "geoip:de")
	if geoip == nil {
		t.Fatalf("geoip:de rule missing: %v", rules)
	}
	if ruleByDomain(rules, "carrier.example") == nil {
		t.Fatalf("domain rule missing: %v", rules)
	}
	// The suffix rule must run before the geoip rule so a domain matching both
	// is decided by name; nothing condition-less may sit between them.
	suffixIdx, geoipIdx := -1, -1
	for i, r := range rules {
		if suffixIdx == -1 {
			for _, d := range stringList(r["domain"]) {
				if d == "domain:carrier.example" {
					suffixIdx = i
				}
			}
		}
		for _, ip := range stringList(r["ip"]) {
			if ip == "geoip:de" {
				geoipIdx = i
			}
		}
	}
	if suffixIdx == -1 || geoipIdx == -1 {
		t.Fatalf("rule indexes: suffix=%d geoip=%d", suffixIdx, geoipIdx)
	}
	if !(suffixIdx < geoipIdx) {
		t.Errorf("suffix rule at %d must precede geoip rule at %d", suffixIdx, geoipIdx)
	}
}

// TestXrayCatchAll_AllAddressesForDirectFinal keeps a default for a direct
// final: without the rule xray's dispatcher would send unmatched traffic to the
// proxy. The rule must carry the all-addresses condition so it runs after the
// operator's IP rules rather than hiding them.
func TestXrayCatchAll_AllAddressesForDirectFinal(t *testing.T) {
	writeXrayGeoDat(t, "geoip.dat", []string{"DE"})

	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:internal.example", Outbound: "proxy"},
		{Match: "geoip:de", Outbound: "proxy"},
		{Match: "default", Outbound: "direct"},
	}
	rules := generateXrayRules(t, cg)

	catchAll := xrayAllAddressRule(rules)
	if catchAll == nil {
		t.Fatalf("no all-addresses rule for a direct final: %v", rules)
	}
	if catchAll["outboundTag"] != "direct" {
		t.Fatalf("catch-all outboundTag = %v, want direct", catchAll["outboundTag"])
	}
	if rules[len(rules)-1]["outboundTag"] != "direct" {
		t.Errorf("catch-all must be the last rule: %v", rules)
	}
	// The geoip rule must sit before the catch-all, so a domain destination that
	// resolves into DE is matched by the operator's rule first.
	geoipIdx := -1
	for i, r := range rules {
		for _, ip := range stringList(r["ip"]) {
			if ip == "geoip:de" {
				geoipIdx = i
			}
		}
	}
	if geoipIdx == -1 || geoipIdx >= len(rules)-1 {
		t.Fatalf("geoip rule at %d is hidden by the catch-all: %v", geoipIdx, rules)
	}
}

// TestXrayCatchAll_AllAddressesForDenyFinal keeps an explicit block for a deny final.
func TestXrayCatchAll_AllAddressesForDenyFinal(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:corp.example", Outbound: "direct"},
		{Match: "default", Outbound: "deny"},
	}
	rules := generateXrayRules(t, cg)

	catchAll := xrayAllAddressRule(rules)
	if catchAll == nil {
		t.Fatalf("no all-addresses rule for a deny final: %v", rules)
	}
	if catchAll["outboundTag"] != xrayBlockOutboundTag {
		t.Fatalf("catch-all outboundTag = %v, want %q", catchAll["outboundTag"], xrayBlockOutboundTag)
	}
}

// TestXrayCatchAll_AllAddressesForNamedFinal covers an external outbound used as
// the default: the rule must name that tag and the tag must exist in outbounds.
func TestXrayCatchAll_AllAddressesForNamedFinal(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.ExternalOutbounds = map[string]string{"office": "socks5://192.0.2.10:1080"}
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:blocked.example", Outbound: "deny"},
		{Match: "default", Outbound: "office"},
	}
	rulesPath, err := cg.Generate(&engine.Engine{Name: "xray"}, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cfg := loadJSON(t, rulesPath)
	rules := getXrayRules(t, cfg)

	catchAll := xrayAllAddressRule(rules)
	if catchAll == nil {
		t.Fatalf("no all-addresses rule for a named final: %v", rules)
	}
	if catchAll["outboundTag"] != "office" {
		t.Fatalf("catch-all outboundTag = %v, want office", catchAll["outboundTag"])
	}

	tagFound := false
	for _, raw := range cfg["outbounds"].([]interface{}) {
		if ob, ok := raw.(map[string]interface{}); ok && ob["tag"] == "office" {
			tagFound = true
		}
	}
	if !tagFound {
		t.Fatalf("catch-all names tag %q that no outbound defines: %v", catchAll["outboundTag"], cfg["outbounds"])
	}
}

// TestXrayResolverPin_PrecedesUserRules pins the tunnel resolver to the proxy.
// xray dials every https resolver through the router, so without this rule a
// whitelist/geoip rule covering the resolver address would send the tunnel's
// own DNS traffic direct.
func TestXrayResolverPin_PrecedesUserRules(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.DNSUpstream = []string{"1.1.1.1", "8.8.8.8"}
	cg.RoutingRules = []RoutingRule{
		{Match: "geoip:us", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
	rules := generateXrayRules(t, cg)
	if len(rules) == 0 {
		t.Fatal("no rules generated")
	}
	pin := rules[0]
	if got := stringList(pin["ip"]); len(got) != 1 || got[0] != "8.8.8.8/32" {
		t.Fatalf("first rule = %v, want the 8.8.8.8/32 resolver pin", pin)
	}
	if pin["outboundTag"] != "proxy" {
		t.Fatalf("resolver pin outboundTag = %v, want proxy", pin["outboundTag"])
	}
}
