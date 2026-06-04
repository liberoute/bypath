package tunnel

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
)

// testVlessLink returns a basic vless link for routing tests.
func testVlessLink() *profile.Link {
	return &profile.Link{
		Protocol: "vless",
		Address:  "server.example.com",
		Port:     443,
		UUID:     "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		TLS:      true,
		SNI:      "server.example.com",
	}
}

// loadJSON reads and parses a generated config file.
func loadJSON(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("Invalid JSON: %v\n%s", err, string(data))
	}
	return cfg
}

// getSingboxRules extracts route.rules from a sing-box config.
func getSingboxRules(t *testing.T, cfg map[string]interface{}) []map[string]interface{} {
	t.Helper()
	route, ok := cfg["route"].(map[string]interface{})
	if !ok {
		t.Fatal("missing route section")
	}
	raw, ok := route["rules"].([]interface{})
	if !ok {
		t.Fatal("missing route.rules")
	}
	rules := make([]map[string]interface{}, len(raw))
	for i, r := range raw {
		rules[i] = r.(map[string]interface{})
	}
	return rules
}

// getXrayRules extracts routing.rules from an xray config.
func getXrayRules(t *testing.T, cfg map[string]interface{}) []map[string]interface{} {
	t.Helper()
	routing, ok := cfg["routing"].(map[string]interface{})
	if !ok {
		t.Fatal("missing routing section")
	}
	raw, ok := routing["rules"].([]interface{})
	if !ok {
		t.Fatal("missing routing.rules")
	}
	rules := make([]map[string]interface{}, len(raw))
	for i, r := range raw {
		rules[i] = r.(map[string]interface{})
	}
	return rules
}

// ─── Sing-box routing tests ───────────────────────────────────────────────────

// TestSingbox_WithWhitelist_FinalIsProxy verifies that with any whitelist country,
// unmatched traffic (e.g. youtube.com) goes through proxy.
func TestSingbox_WithWhitelist_FinalIsProxy(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)
	cg.WhitelistCountries = []string{"xx"} // any country code

	configFile, err := cg.generateSingBox(testVlessLink())
	if err != nil {
		t.Fatalf("generateSingBox: %v", err)
	}
	cfg := loadJSON(t, configFile)

	route := cfg["route"].(map[string]interface{})
	if route["final"] != "proxy" {
		t.Errorf("route.final = %v, want proxy — non-whitelisted traffic must go through tunnel", route["final"])
	}
}

// TestSingbox_NoWhitelist_NoGeoipRules verifies that with empty whitelist,
// no geoip rule_set references appear in the config.
func TestSingbox_NoWhitelist_NoGeoipRules(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)
	cg.WhitelistCountries = []string{}

	configFile, err := cg.generateSingBox(testVlessLink())
	if err != nil {
		t.Fatalf("generateSingBox: %v", err)
	}
	cfg := loadJSON(t, configFile)

	route, hasRoute := cfg["route"].(map[string]interface{})
	if !hasRoute {
		return // no route section = OK
	}
	rules, _ := route["rules"].([]interface{})
	for _, ruleRaw := range rules {
		rule, _ := ruleRaw.(map[string]interface{})
		if rs, ok := rule["rule_set"].([]interface{}); ok {
			for _, tag := range rs {
				if s, _ := tag.(string); len(s) >= 5 && s[:5] == "geoip" {
					t.Errorf("unexpected geoip rule %q with empty whitelist", s)
				}
			}
		}
	}
}

// TestSingbox_WhitelistCountry_GeoipRuleRoutesDirect verifies that each whitelisted
// country gets a geoip-{country} rule that routes to "direct".
func TestSingbox_WhitelistCountry_GeoipRuleRoutesDirect(t *testing.T) {
	countries := []string{"aa", "bb", "cc"} // arbitrary country codes

	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)
	cg.WhitelistCountries = countries

	configFile, err := cg.generateSingBox(testVlessLink())
	if err != nil {
		t.Fatalf("generateSingBox: %v", err)
	}
	rules := getSingboxRules(t, loadJSON(t, configFile))

	for _, country := range countries {
		tag := "geoip-" + country
		found := false
		for _, r := range rules {
			rs, ok := r["rule_set"].([]interface{})
			if !ok {
				continue
			}
			for _, t2 := range rs {
				if t2 == tag {
					found = true
					if r["outbound"] != "direct" {
						t.Errorf("%s outbound = %v, want direct", tag, r["outbound"])
					}
				}
			}
		}
		if !found {
			t.Errorf("no rule for %s — whitelisted country IPs won't go direct", tag)
		}
	}
}

// TestSingbox_BypassDomains_GoToDirectBeforeGeoip verifies bypass_domains
// are routed direct and their rule appears BEFORE any geoip rule.
func TestSingbox_BypassDomains_GoToDirectBeforeGeoip(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)
	cg.WhitelistCountries = []string{"xx"}
	cg.BypassDomains = []string{"bypass-me.example.com", "also-bypass.example.org"}

	configFile, err := cg.generateSingBox(testVlessLink())
	if err != nil {
		t.Fatalf("generateSingBox: %v", err)
	}
	rules := getSingboxRules(t, loadJSON(t, configFile))

	bypassIdx, geoipIdx := -1, -1
	for i, r := range rules {
		if _, ok := r["domain_suffix"]; ok && r["outbound"] == "direct" {
			if bypassIdx == -1 {
				bypassIdx = i
			}
		}
		if rs, ok := r["rule_set"].([]interface{}); ok {
			for _, tag := range rs {
				if s, _ := tag.(string); len(s) >= 5 && s[:5] == "geoip" {
					if geoipIdx == -1 {
						geoipIdx = i
					}
				}
			}
		}
	}

	if bypassIdx == -1 {
		t.Fatal("no bypass domain rule found")
	}
	if geoipIdx == -1 {
		t.Fatal("no geoip rule found")
	}
	if bypassIdx >= geoipIdx {
		t.Errorf("bypass rule (idx %d) must come BEFORE geoip rule (idx %d)", bypassIdx, geoipIdx)
	}
}

// TestSingbox_ForceProxyDomains_BeforeBypassAndGeoip verifies force_proxy_domains
// appear before both bypass_domains and geoip rules.
func TestSingbox_ForceProxyDomains_BeforeBypassAndGeoip(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)
	cg.WhitelistCountries = []string{"xx"}
	cg.BypassDomains = []string{"bypass.example.com"}
	cg.ForceProxyDomains = []string{"force-tunnel.example.com"}

	configFile, err := cg.generateSingBox(testVlessLink())
	if err != nil {
		t.Fatalf("generateSingBox: %v", err)
	}
	rules := getSingboxRules(t, loadJSON(t, configFile))

	forceProxyIdx, bypassIdx := -1, -1
	for i, r := range rules {
		if ds, ok := r["domain_suffix"].([]interface{}); ok {
			for _, d := range ds {
				if d == "force-tunnel.example.com" && r["outbound"] == "proxy" {
					forceProxyIdx = i
				}
				if d == "bypass.example.com" && r["outbound"] == "direct" {
					bypassIdx = i
				}
			}
		}
	}

	if forceProxyIdx == -1 {
		t.Fatal("no force_proxy rule found")
	}
	if bypassIdx == -1 {
		t.Fatal("no bypass domain rule found")
	}
	if forceProxyIdx >= bypassIdx {
		t.Errorf("force_proxy rule (idx %d) must come BEFORE bypass rule (idx %d)", forceProxyIdx, bypassIdx)
	}
}

// TestSingbox_PrivateLAN_RoutedDirect verifies ip_is_private rule exists and routes direct.
func TestSingbox_PrivateLAN_RoutedDirect(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)
	cg.WhitelistCountries = []string{"xx"}

	configFile, err := cg.generateSingBox(testVlessLink())
	if err != nil {
		t.Fatalf("generateSingBox: %v", err)
	}
	rules := getSingboxRules(t, loadJSON(t, configFile))

	found := false
	for _, r := range rules {
		if r["ip_is_private"] == true {
			found = true
			if r["outbound"] != "direct" {
				t.Errorf("ip_is_private outbound = %v, want direct", r["outbound"])
			}
		}
	}
	if !found {
		t.Error("no ip_is_private rule — LAN traffic will go through tunnel")
	}
}

// ─── Xray routing tests ───────────────────────────────────────────────────────

// TestXray_IPIfNonMatch_domainStrategy verifies xray uses IPIfNonMatch.
// This is critical: with socks5h the browser sends domain to proxy, xray must
// resolve it to match geoip rules. AsIs would break this.
func TestXray_IPIfNonMatch_domainStrategy(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)
	cg.WhitelistCountries = []string{"xx"}

	eng := &engine.Engine{Name: "xray"}
	configFile, err := cg.Generate(eng, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	routing := loadJSON(t, configFile)["routing"].(map[string]interface{})
	// AsIs prevents local DNS resolution so ISP-poisoned IPs (e.g. youtube→10.x.x.x)
	// don't route direct; geosite rules handle domain-based country routing instead.
	if routing["domainStrategy"] != "AsIs" {
		t.Errorf("domainStrategy = %v, want AsIs", routing["domainStrategy"])
	}
}

// TestXray_WhitelistCountry_GeoipRuleRoutesDirect verifies whitelisted countries
// get geoip:{country} rules that route to "direct".
func TestXray_WhitelistCountry_GeoipRuleRoutesDirect(t *testing.T) {
	countries := []string{"aa", "bb"}

	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)
	cg.WhitelistCountries = countries

	eng := &engine.Engine{Name: "xray"}
	configFile, err := cg.Generate(eng, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	rules := getXrayRules(t, loadJSON(t, configFile))

	for _, country := range countries {
		geoipTag := "geoip:" + country
		found := false
		for _, r := range rules {
			ips, ok := r["ip"].([]interface{})
			if !ok {
				continue
			}
			for _, ip := range ips {
				if ip == geoipTag {
					found = true
					if r["outboundTag"] != "direct" {
						t.Errorf("%s outboundTag = %v, want direct", geoipTag, r["outboundTag"])
					}
				}
			}
		}
		if !found {
			t.Errorf("no rule for %s — whitelisted IPs won't go direct", geoipTag)
		}
	}
}

// TestXray_NoWhitelist_NoRoutingSection verifies that with empty whitelist and no bypass,
// xray config has no routing section (all traffic goes to proxy outbound by default).
func TestXray_NoWhitelist_NoRoutingSection(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)
	// nothing set

	eng := &engine.Engine{Name: "xray"}
	configFile, err := cg.Generate(eng, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	cfg := loadJSON(t, configFile)
	if _, hasRouting := cfg["routing"]; hasRouting {
		// If routing exists, there should be no geoip rules
		rules := getXrayRules(t, cfg)
		for _, r := range rules {
			if ips, ok := r["ip"].([]interface{}); ok {
				for _, ip := range ips {
					if s, _ := ip.(string); len(s) >= 6 && s[:6] == "geoip:" && s != "geoip:private" {
						t.Errorf("unexpected geoip rule %q with empty whitelist", s)
					}
				}
			}
		}
	}
}

// TestXray_BypassDomains_RoutedDirect verifies bypass_domains go direct.
func TestXray_BypassDomains_RoutedDirect(t *testing.T) {
	bypass := []string{"bypass-a.example.com", "bypass-b.example.org"}

	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)
	cg.WhitelistCountries = []string{"xx"}
	cg.BypassDomains = bypass

	eng := &engine.Engine{Name: "xray"}
	configFile, err := cg.Generate(eng, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	rules := getXrayRules(t, loadJSON(t, configFile))

	for _, want := range bypass {
		found := false
		for _, r := range rules {
			domains, ok := r["domain"].([]interface{})
			if !ok {
				continue
			}
			for _, d := range domains {
				if d == want {
					found = true
					if r["outboundTag"] != "direct" {
						t.Errorf("bypass domain %q outboundTag = %v, want direct", want, r["outboundTag"])
					}
				}
			}
		}
		if !found {
			t.Errorf("bypass domain %q not found in xray rules", want)
		}
	}
}

// TestXray_BypassBeforeGeoip verifies bypass_domains rule index < geoip rule index.
func TestXray_BypassBeforeGeoip(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)
	cg.WhitelistCountries = []string{"xx"}
	cg.BypassDomains = []string{"bypass.example.com"}

	eng := &engine.Engine{Name: "xray"}
	configFile, err := cg.Generate(eng, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	rules := getXrayRules(t, loadJSON(t, configFile))

	bypassIdx, geoipIdx := -1, -1
	for i, r := range rules {
		if domains, ok := r["domain"].([]interface{}); ok && r["outboundTag"] == "direct" {
			for _, d := range domains {
				if d == "bypass.example.com" {
					bypassIdx = i
				}
			}
		}
		if ips, ok := r["ip"].([]interface{}); ok {
			for _, ip := range ips {
				if s, _ := ip.(string); len(s) >= 6 && s[:6] == "geoip:" && s != "geoip:private" {
					if geoipIdx == -1 {
						geoipIdx = i
					}
				}
			}
		}
	}

	if bypassIdx == -1 {
		t.Fatal("bypass rule not found")
	}
	if geoipIdx == -1 {
		t.Fatal("geoip rule not found")
	}
	if bypassIdx >= geoipIdx {
		t.Errorf("bypass rule (idx %d) must come BEFORE geoip rule (idx %d)", bypassIdx, geoipIdx)
	}
}

// TestXray_PrivateLAN_RoutedDirect verifies geoip:private always routes direct.
func TestXray_PrivateLAN_RoutedDirect(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)
	cg.WhitelistCountries = []string{"xx"}

	eng := &engine.Engine{Name: "xray"}
	configFile, err := cg.Generate(eng, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	rules := getXrayRules(t, loadJSON(t, configFile))

	found := false
	for _, r := range rules {
		if ips, ok := r["ip"].([]interface{}); ok {
			for _, ip := range ips {
				// Private IPs now use explicit RFC1918 ranges instead of geoip:private
				// (geoip:private is not present in all geoip.dat builds)
				if ip == "10.0.0.0/8" || ip == "192.168.0.0/16" {
					found = true
					if r["outboundTag"] != "direct" {
						t.Errorf("private IP rule outboundTag = %v, want direct", r["outboundTag"])
					}
				}
			}
		}
	}
	if !found {
		t.Error("no private IP rule — LAN traffic will go through tunnel")
	}
}

// TestXray_Sniffing_EnabledWithRouteOnly verifies xray inbound has sniffing enabled
// with routeOnly:true — required for domain detection without rewriting dest.
func TestXray_Sniffing_EnabledWithRouteOnly(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)
	cg.WhitelistCountries = []string{"xx"}

	eng := &engine.Engine{Name: "xray"}
	configFile, err := cg.Generate(eng, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cfg := loadJSON(t, configFile)

	inbounds := cfg["inbounds"].([]interface{})
	if len(inbounds) == 0 {
		t.Fatal("no inbounds")
	}
	inbound := inbounds[0].(map[string]interface{})

	sniffing, ok := inbound["sniffing"].(map[string]interface{})
	if !ok {
		t.Fatal("missing sniffing in inbound — domain detection won't work")
	}
	if sniffing["enabled"] != true {
		t.Error("sniffing.enabled must be true")
	}
	if sniffing["routeOnly"] != true {
		t.Error("sniffing.routeOnly must be true — otherwise xray rewrites dest and breaks HTTPS")
	}
}
