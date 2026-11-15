package tunnel

import (
	"testing"
)

// F-001: a name the plan sends DIRECT must be resolved by the direct resolver.
// sing-box re-resolves every destination that still carries a name, so the
// tunnel resolve has to exclude exactly the set the direct resolve covered.

func resolveRuleIndex(rules []map[string]interface{}, server string) int {
	for i, rule := range rules {
		if rule["action"] == "resolve" && rule["server"] == server {
			return i
		}
	}
	return -1
}

// defaultResolveRuleIndex finds the plan's catch-all resolve step: the last
// resolve rule and the one with no positive class condition.
func defaultResolveRuleIndex(rules []map[string]interface{}, server string) int {
	for i := len(rules) - 1; i >= 0; i-- {
		rule := rules[i]
		if rule["action"] != "resolve" || rule["server"] != server {
			continue
		}
		if len(ruleConditions(rule)) == 0 {
			return i
		}
	}
	return -1
}

// childRules reads a logical rule's children from either a decoded JSON array
// or a map slice built directly in code.
func childRules(rule map[string]interface{}) []map[string]interface{} {
	switch raw := rule["rules"].(type) {
	case []map[string]interface{}:
		return raw
	case []interface{}:
		out := make([]map[string]interface{}, 0, len(raw))
		for _, item := range raw {
			if child, ok := item.(map[string]interface{}); ok {
				out = append(out, child)
			}
		}
		return out
	}
	return nil
}

// extractCondition keeps only the matcher fields of a rule.
func extractCondition(rule map[string]interface{}) map[string]interface{} {
	condition := map[string]interface{}{}
	for _, key := range []string{"rule_set", "domain", "domain_suffix"} {
		if value, ok := rule[key]; ok && rule["invert"] != true {
			condition[key] = value
		}
	}
	return condition
}

// ruleConditions returns the positive conditions a resolve step applies to.
// A step that excludes earlier classes is an AND whose first branch carries the
// class condition; the inverted branches are exclusions and are not returned.
func ruleConditions(rule map[string]interface{}) []map[string]interface{} {
	if rule["type"] == "logical" {
		if rule["mode"] != "and" {
			return nil
		}
		var out []map[string]interface{}
		for _, child := range childRules(rule) {
			if child["invert"] == true {
				continue
			}
			if condition := extractCondition(child); len(condition) > 0 {
				out = append(out, condition)
			}
		}
		return out
	}
	if condition := extractCondition(rule); len(condition) > 0 {
		return []map[string]interface{}{condition}
	}
	return nil
}

func resolveRuleIndexWithRuleSet(rules []map[string]interface{}, server, tag string) int {
	for i, rule := range rules {
		if rule["action"] != "resolve" || rule["server"] != server {
			continue
		}
		for _, condition := range ruleConditions(rule) {
			for _, ref := range ruleSetRefs(condition) {
				if ref == tag {
					return i
				}
			}
		}
	}
	return -1
}

func resolveRuleIndexWithDomains(rules []map[string]interface{}, server, key, value string) int {
	for i, rule := range rules {
		if rule["action"] != "resolve" || rule["server"] != server {
			continue
		}
		for _, condition := range ruleConditions(rule) {
			for _, domain := range stringList(condition[key]) {
				if domain == value {
					return i
				}
			}
		}
	}
	return -1
}

// excludedConditions returns the sub-rules of an inverted resolve rule: a
// single-class exclusion is inlined, several classes are a logical OR.
func excludedConditions(t *testing.T, rule map[string]interface{}) []map[string]interface{} {
	t.Helper()
	if raw, ok := rule["rules"]; ok {
		if rule["type"] != "logical" || rule["mode"] != "or" {
			t.Fatalf("multi-class exclusion must be a logical OR: %v", rule)
		}
		items, ok := raw.([]interface{})
		if !ok {
			t.Fatalf("logical rules is not a list: %v", rule)
		}
		out := make([]map[string]interface{}, len(items))
		for i, item := range items {
			out[i], _ = item.(map[string]interface{})
		}
		return out
	}
	condition := map[string]interface{}{}
	for _, key := range []string{"rule_set", "domain", "domain_suffix"} {
		if value, ok := rule[key]; ok {
			condition[key] = value
		}
	}
	return []map[string]interface{}{condition}
}

func conditionsContainRuleSet(conditions []map[string]interface{}, tag string) bool {
	for _, condition := range conditions {
		for _, ref := range ruleSetRefs(condition) {
			if ref == tag {
				return true
			}
		}
	}
	return false
}

func conditionsContainDomain(conditions []map[string]interface{}, key, value string) bool {
	for _, condition := range conditions {
		for _, domain := range stringList(condition[key]) {
			if domain == value {
				return true
			}
		}
	}
	return false
}

func dnsRuleServerFor(t *testing.T, cfg map[string]interface{}, key, value string) string {
	t.Helper()
	dns, ok := cfg["dns"].(map[string]interface{})
	if !ok {
		t.Fatal("missing dns section")
	}
	raw, _ := dns["rules"].([]interface{})
	for _, item := range raw {
		rule, _ := item.(map[string]interface{})
		for _, found := range stringList(rule[key]) {
			if found == value {
				server, _ := rule["server"].(string)
				return server
			}
		}
	}
	return ""
}

func dnsServerDefined(cfg map[string]interface{}, tag string) bool {
	dns, ok := cfg["dns"].(map[string]interface{})
	if !ok {
		return false
	}
	raw, _ := dns["servers"].([]interface{})
	for _, item := range serversOf(raw) {
		if item["tag"] == tag {
			return true
		}
	}
	return false
}

func serversOf(raw []interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(raw))
	for _, item := range raw {
		if server, ok := item.(map[string]interface{}); ok {
			out = append(out, server)
		}
	}
	return out
}

// TestSingboxSplit_DomesticNamesResolveDirect is the F-001 regression: the
// split's geosite rule set is resolved by dns-direct, and the tunnel resolve
// that follows excludes it so the domestic answer cannot be overwritten.
func TestSingboxSplit_DomesticNamesResolveDirect(t *testing.T) {
	writeValidGeoRuleSet(t, "geosite", "ir")
	writeValidGeoRuleSet(t, "geoip", "ir")

	cg := NewConfigGenerator(t.TempDir())
	cg.GatewayMode = true
	cg.CountrySplit = "ir"
	cg.RoutingRules = []RoutingRule{{Match: "default", Outbound: "proxy"}}

	cfg := loadJSON(t, mustGenerateSingBox(t, cg))
	rules := getSingboxRules(t, cfg)

	direct := resolveRuleIndexWithRuleSet(rules, "dns-direct", "geosite-ir")
	tunnel := defaultResolveRuleIndex(rules, "dns-tunnel")
	if direct < 0 {
		t.Fatalf("no dns-direct resolve for the split geosite set: %v", rules)
	}
	if tunnel < 0 || tunnel < direct {
		t.Fatalf("tunnel resolve position %d must follow the direct resolve %d: %v", tunnel, direct, rules)
	}
	if rules[tunnel]["invert"] != true {
		t.Fatalf("tunnel resolve must exclude the directly resolved names: %v", rules[tunnel])
	}
	excluded := excludedConditions(t, rules[tunnel])
	if !conditionsContainRuleSet(excluded, "geosite-ir") {
		t.Fatalf("tunnel resolve does not exclude geosite-ir: %v", excluded)
	}
	if !singboxRuleSetDefined(cfg, "geosite-ir") {
		t.Fatal("direct resolve references an undefined rule_set")
	}

	if server := dnsRuleServerFor(t, cfg, "rule_set", "geosite-ir"); server != "dns-direct" {
		t.Fatalf("dns rule for geosite-ir uses %q, want dns-direct", server)
	}
}

// TestSingboxRules_DirectNamesResolveDirect covers the rules path: every
// domain-shaped DIRECT matcher gets a dns-direct resolve before the tunnel
// resolve, and a name routed to the proxy is in neither set.
func TestSingboxRules_DirectNamesResolveDirect(t *testing.T) {
	writeValidGeoRuleSet(t, "geosite", "ir")
	writeValidGeoRuleSet(t, "geoip", "ir")

	cg := NewConfigGenerator(t.TempDir())
	cg.CountrySplit = "ir"
	cg.RoutingRules = []RoutingRule{
		{Match: "geosite:ir", Outbound: "direct"},
		{Match: "domain:portal.example", Outbound: "direct"},
		{Match: "domain_suffix:shop.example", Outbound: "direct"},
		{Match: "domain_suffix:blocked.example", Outbound: "proxy"},
		{Match: "default", Outbound: "proxy"},
	}

	cfg := loadJSON(t, mustGenerateSingBox(t, cg))
	rules := getSingboxRules(t, cfg)

	for _, check := range []struct {
		key   string
		value string
	}{
		{"rule_set", "geosite-ir"},
		{"domain", "portal.example"},
		{"domain_suffix", "shop.example"},
	} {
		if idx := resolveRuleIndexWithDomains(rules, "dns-direct", check.key, check.value); idx < 0 {
			t.Fatalf("no dns-direct resolve for %s %q: %v", check.key, check.value, rules)
		}
	}

	tunnel := defaultResolveRuleIndex(rules, "dns-tunnel")
	if tunnel < 0 {
		t.Fatalf("no tunnel resolve: %v", rules)
	}
	excluded := excludedConditions(t, rules[tunnel])
	if !conditionsContainRuleSet(excluded, "geosite-ir") ||
		!conditionsContainDomain(excluded, "domain", "portal.example") ||
		!conditionsContainDomain(excluded, "domain_suffix", "shop.example") {
		t.Fatalf("tunnel resolve does not exclude every direct class: %v", excluded)
	}
	if !conditionsContainDomain(excluded, "domain_suffix", "blocked.example") {
		t.Fatalf("catch-all resolve does not exclude the earlier proxy class: %v", excluded)
	}
	if resolveRuleIndexWithDomains(rules, "dns-direct", "domain_suffix", "blocked.example") >= 0 {
		t.Fatal("a proxied name received a dns-direct resolve")
	}
	if resolveRuleIndexWithDomains(rules, "dns-tunnel", "domain_suffix", "blocked.example") < 0 {
		t.Fatal("a proxied name has no tunnel resolve step")
	}

	for _, check := range []struct {
		key   string
		value string
	}{
		{"rule_set", "geosite-ir"},
		{"domain", "portal.example"},
		{"domain_suffix", "shop.example"},
	} {
		if server := dnsRuleServerFor(t, cfg, check.key, check.value); server != "dns-direct" {
			t.Fatalf("dns rule for %s %q uses %q, want dns-direct", check.key, check.value, server)
		}
	}
}

// TestSingboxLegacy_TunnelResolverIsDefinedForBypassOnly guards the widened DNS
// fallback: a non-gateway config whose only route inputs are bypass_domains or a
// country split must still define the dns-tunnel server the route resolves with.
func TestSingboxLegacy_TunnelResolverIsDefinedForBypassOnly(t *testing.T) {
	writeValidGeoRuleSet(t, "geosite", "ir")

	cg := NewConfigGenerator(t.TempDir())
	cg.BypassDomains = []string{"probe.example"}
	cg.CountrySplit = "ir"

	cfg := loadJSON(t, mustGenerateSingBox(t, cg))
	if !dnsServerDefined(cfg, "dns-tunnel") {
		t.Fatalf("dns-tunnel referenced by the route is not defined: %v", cfg["dns"])
	}

	rules := getSingboxRules(t, cfg)
	if idx := resolveRuleIndexWithDomains(rules, "dns-direct", "domain_suffix", "probe.example"); idx < 0 {
		t.Fatalf("bypass domains get no dns-direct resolve: %v", rules)
	}
	if idx := resolveRuleIndexWithRuleSet(rules, "dns-direct", "geosite-ir"); idx < 0 {
		t.Fatalf("split geosite set gets no dns-direct resolve: %v", rules)
	}
	tunnel := defaultResolveRuleIndex(rules, "dns-tunnel")
	if tunnel < 0 {
		t.Fatalf("no tunnel resolve: %v", rules)
	}
	excluded := excludedConditions(t, rules[tunnel])
	if !conditionsContainRuleSet(excluded, "geosite-ir") ||
		!conditionsContainDomain(excluded, "domain_suffix", "probe.example") {
		t.Fatalf("tunnel resolve does not exclude both direct classes: %v", excluded)
	}
}

// TestSingboxSplitOnly_KeepsTunnelResolverDefined pins the split-only proxy
// configuration: no assets means no DIRECT rule (fail closed), but the route
// still resolves through a dns-tunnel server that the DNS section defines.
func TestSingboxSplitOnly_KeepsTunnelResolverDefined(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.CountrySplit = "qq"

	cfg := loadJSON(t, mustGenerateSingBox(t, cg))
	if !dnsServerDefined(cfg, "dns-tunnel") {
		t.Fatalf("dns-tunnel referenced by the route is not defined: %v", cfg["dns"])
	}
	rules := getSingboxRules(t, cfg)
	if idx := resolveRuleIndexWithRuleSet(rules, "dns-direct", "geosite-qq"); idx >= 0 {
		t.Fatalf("missing asset still produced a dns-direct resolve: %v", rules[idx])
	}
	for _, rule := range rules {
		for _, ref := range ruleSetRefs(rule) {
			if ref == "geosite-qq" || ref == "geoip-qq" {
				t.Fatalf("missing asset still produced a rule: %v", rule)
			}
		}
	}
}

// TestSingboxDirectRule_LocalDNSKeepsItsServer keeps the local resolver
// authoritative when a routing rule would otherwise send the same suffix
// direct: the home answer must not be replaced by dns-direct or dns-tunnel.
func TestSingboxDirectRule_LocalDNSKeepsItsServer(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.LocalDNSRules = []LocalDNSRule{{Server: "192.0.2.53", Domains: []string{"home"}}}
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:home", Outbound: "direct"},
		{Match: "domain_suffix:shop.example", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}

	cfg := loadJSON(t, mustGenerateSingBox(t, cg))
	rules := getSingboxRules(t, cfg)

	if idx := resolveRuleIndexWithDomains(rules, "dns-direct", "domain_suffix", "home"); idx >= 0 {
		t.Fatalf("local_dns suffix received a dns-direct resolve: %v", rules[idx])
	}
	if idx := resolveRuleIndexWithDomains(rules, "dns-direct", "domain_suffix", "shop.example"); idx < 0 {
		t.Fatalf("direct rule received no dns-direct resolve: %v", rules)
	}
	tunnel := defaultResolveRuleIndex(rules, "dns-tunnel")
	if tunnel < 0 {
		t.Fatalf("no tunnel resolve: %v", rules)
	}
	excluded := excludedConditions(t, rules[tunnel])
	if !conditionsContainDomain(excluded, "domain_suffix", "home") ||
		!conditionsContainDomain(excluded, "domain_suffix", "shop.example") {
		t.Fatalf("tunnel resolve must exclude home and shop.example: %v", excluded)
	}
	if server := dnsRuleServerFor(t, cfg, "domain_suffix", "home"); server != localDNSTag(0) {
		t.Fatalf("dns rule for home uses %q, want %q", server, localDNSTag(0))
	}
}

// TestSingboxProxyOnly_KeepsNoRoutePolicy is INV-1: the shipped default still
// emits no route or DNS policy that could resolve through the tunnel.
func TestSingboxProxyOnly_KeepsNoRoutePolicy(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cfg := loadJSON(t, mustGenerateSingBox(t, cg))
	if _, ok := cfg["route"]; ok {
		t.Fatalf("proxy-only config gained a route section: %v", cfg["route"])
	}
	if _, ok := cfg["dns"]; ok {
		t.Fatalf("proxy-only config gained a dns section: %v", cfg["dns"])
	}
}

// resolveExclusions returns the class conditions a resolve step excludes.
func resolveExclusions(t *testing.T, rule map[string]interface{}) []map[string]interface{} {
	t.Helper()
	if rule["type"] != "logical" || rule["mode"] != "and" {
		return nil
	}
	for _, child := range childRules(rule) {
		if child["invert"] != true {
			continue
		}
		if child["type"] == "logical" {
			return excludedConditions(t, child)
		}
		condition := map[string]interface{}{}
		for _, key := range []string{"rule_set", "domain", "domain_suffix"} {
			if value, ok := child[key]; ok {
				condition[key] = value
			}
		}
		if len(condition) > 0 {
			return []map[string]interface{}{condition}
		}
	}
	return nil
}

func dnsRuleIndexFor(t *testing.T, cfg map[string]interface{}, key, value string) int {
	t.Helper()
	dns, _ := cfg["dns"].(map[string]interface{})
	raw, _ := dns["rules"].([]interface{})
	for i, item := range raw {
		rule, _ := item.(map[string]interface{})
		for _, found := range stringList(rule[key]) {
			if found == value {
				return i
			}
		}
	}
	return -1
}

// TestSingboxProxyExceptionAboveDirectKeepsDNSOnTunnel is the R2-11 regression:
// a proxy exception above a DIRECT class must keep its name off the direct
// resolver, in the connection resolve steps and in the DNS listener rules.
func TestSingboxProxyExceptionAboveDirectKeepsDNSOnTunnel(t *testing.T) {
	writeValidGeoRuleSet(t, "geosite", "ir")
	writeValidGeoRuleSet(t, "geoip", "ir")

	cg := NewConfigGenerator(t.TempDir())
	cg.CountrySplit = "ir"
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:private.ir.example", Outbound: "proxy"},
		{Match: "default", Outbound: "proxy"},
	}

	cfg := loadJSON(t, mustGenerateSingBox(t, cg))
	rules := getSingboxRules(t, cfg)

	// The exception resolves through the tunnel...
	if idx := resolveRuleIndexWithDomains(rules, "dns-tunnel", "domain_suffix", "private.ir.example"); idx < 0 {
		t.Fatalf("proxy exception has no tunnel resolve: %v", rules)
	}
	// ...and the direct resolve for the split excludes it, so the direct
	// resolver never sees the name.
	direct := resolveRuleIndexWithRuleSet(rules, "dns-direct", "geosite-ir")
	if direct < 0 {
		t.Fatalf("split geosite has no direct resolve: %v", rules)
	}
	if !conditionsContainDomain(resolveExclusions(t, rules[direct]), "domain_suffix", "private.ir.example") {
		t.Fatalf("direct resolve does not exclude the proxy exception: %v", rules[direct])
	}

	// The DNS listener must apply the same order: exception first.
	exceptionIdx := dnsRuleIndexFor(t, cfg, "domain_suffix", "private.ir.example")
	splitIdx := dnsRuleIndexFor(t, cfg, "rule_set", "geosite-ir")
	if exceptionIdx < 0 || splitIdx < 0 {
		t.Fatalf("dns rule indexes: exception=%d split=%d", exceptionIdx, splitIdx)
	}
	if exceptionIdx > splitIdx {
		t.Fatalf("split DNS rule at %d precedes the exception at %d", splitIdx, exceptionIdx)
	}
	if server := dnsRuleServerFor(t, cfg, "domain_suffix", "private.ir.example"); server != "dns-tunnel" {
		t.Fatalf("proxy exception DNS server = %q, want dns-tunnel", server)
	}
}
