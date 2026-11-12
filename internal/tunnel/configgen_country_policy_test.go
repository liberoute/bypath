package tunnel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/engine"
)

// exampleCountryPolicy is an illustrative split: one country direct and
// everything else through the tunnel. It is deliberately not loaded from the
// shipped configuration, which starts with only the default rule.
func exampleCountryPolicy() []RoutingRule {
	return []RoutingRule{
		{Match: "geoip:de", Outbound: "direct"},
		{Match: "geosite:de", Outbound: "direct"},
		{Match: "domain_suffix:de", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
}

// xrayDomainOutbound evaluates the domain matchers of a generated xray routing
// section in order and returns the outbound tag of the first rule that matches.
// Rules that match on IP only (geoip/ip_cidr) and geosite rule sets are skipped:
// they need a database lookup and are covered by the geo database tests.
func xrayDomainOutbound(rules []map[string]interface{}, domain string) (string, bool) {
	for _, r := range rules {
		domains, ok := r["domain"].([]interface{})
		if !ok {
			continue
		}
		for _, raw := range domains {
			s, _ := raw.(string)
			var matched bool
			switch {
			case strings.HasPrefix(s, "full:"):
				matched = domain == strings.TrimPrefix(s, "full:")
			case strings.HasPrefix(s, "domain:"):
				// Xray's domain matcher is a suffix match on label boundaries.
				suffix := strings.TrimPrefix(s, "domain:")
				matched = domain == suffix || strings.HasSuffix(domain, "."+suffix)
			}
			if matched {
				tag, _ := r["outboundTag"].(string)
				return tag, true
			}
		}
	}
	return "", false
}

func findXrayRuleIndex(rules []map[string]interface{}, pred func(map[string]interface{}) bool) int {
	for i, r := range rules {
		if pred(r) {
			return i
		}
	}
	return -1
}

// TestXrayCountryPolicy_CountryDomainsRouteDirect generates the xray
// configuration from an illustrative country policy and verifies that domains
// under the country TLD are classified by the suffix rule with the direct
// outbound tag, with no domain-specific exception ahead of it.
func TestXrayCountryPolicy_CountryDomainsRouteDirect(t *testing.T) {
	policy := exampleCountryPolicy()
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("./engines", 0755); err != nil {
		t.Fatal(err)
	}
	for name, codes := range map[string][]string{
		"geoip.dat":   {"DE", "US"},
		"geosite.dat": {"de"},
	} {
		if err := os.WriteFile(filepath.Join("./engines", name), buildXrayDat(codes, 1600), 0644); err != nil {
			t.Fatal(err)
		}
	}

	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = policy

	path, err := cg.Generate(&engine.Engine{Name: "xray"}, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	rules := getXrayRules(t, loadJSON(t, path))

	for _, domain := range []string{"probe.example.de", "login.example.de"} {
		tag, ok := xrayDomainOutbound(rules, domain)
		if !ok {
			t.Errorf("%s matched no domain rule; it would only match after DNS resolution", domain)
			continue
		}
		if tag != "direct" {
			t.Errorf("%s is routed by rule to %q, want direct", domain, tag)
		}
	}

	// A foreign destination must not be captured by any country domain matcher.
	if tag, ok := xrayDomainOutbound(rules, "www.example.net"); ok && tag != "proxy" {
		t.Errorf("www.example.net matched a domain rule routing to %q, want no match (proxy catch-all)", tag)
	}

	// No rule may mention a domain-specific exception.
	for _, r := range rules {
		domains, _ := r["domain"].([]interface{})
		for _, raw := range domains {
			s, _ := raw.(string)
			for _, banned := range []string{"shecan", "samandehi", "cloudflare", "ip-api"} {
				if strings.Contains(strings.ToLower(s), banned) {
					t.Errorf("generated xray config contains a domain-specific exception %q", s)
				}
			}
		}
	}

	// The policy order must be preserved: geoip, geosite, country suffix, catch-all proxy.
	geoipIdx := findXrayRuleIndex(rules, func(r map[string]interface{}) bool {
		ips, _ := r["ip"].([]interface{})
		for _, raw := range ips {
			if raw == "geoip:de" {
				return true
			}
		}
		return false
	})
	geositeIdx := findXrayRuleIndex(rules, func(r map[string]interface{}) bool {
		domains, _ := r["domain"].([]interface{})
		for _, raw := range domains {
			if raw == "geosite:de" {
				return true
			}
		}
		return false
	})
	suffixIdx := findXrayRuleIndex(rules, func(r map[string]interface{}) bool {
		domains, _ := r["domain"].([]interface{})
		for _, raw := range domains {
			if raw == "domain:de" {
				return true
			}
		}
		return false
	})
	catchAllIdx := findXrayRuleIndex(rules, func(r map[string]interface{}) bool {
		if r["network"] != "tcp,udp" {
			return false
		}
		_, hasDomain := r["domain"]
		_, hasIP := r["ip"]
		return !hasDomain && !hasIP
	})

	if geoipIdx == -1 || geositeIdx == -1 || suffixIdx == -1 || catchAllIdx == -1 {
		t.Fatalf("missing policy rule (geoip=%d geosite=%d suffix=%d catchAll=%d): %v", geoipIdx, geositeIdx, suffixIdx, catchAllIdx, rules)
	}
	if !(geoipIdx < geositeIdx && geositeIdx < suffixIdx && suffixIdx < catchAllIdx) {
		t.Errorf("policy order violated: geoip=%d geosite=%d suffix=%d catchAll=%d", geoipIdx, geositeIdx, suffixIdx, catchAllIdx)
	}
	if rules[catchAllIdx]["outboundTag"] != "proxy" {
		t.Errorf("catch-all outboundTag = %v, want proxy", rules[catchAllIdx]["outboundTag"])
	}
}
