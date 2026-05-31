package tunnel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
	"pgregory.net/rapid"
)

func TestGenerateSingBoxVmess(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)

	eng := &engine.Engine{Name: "sing-box"}
	link := &profile.Link{
		Protocol: "vmess",
		Address:  "1.2.3.4",
		Port:     443,
		UUID:     "test-uuid",
		Security: "auto",
		Network:  "ws",
		Path:     "/ws",
		Host:     "example.com",
		TLS:      true,
		SNI:      "example.com",
	}

	configFile, err := cg.Generate(eng, link)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Read and validate JSON
	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	// Check structure
	if _, ok := cfg["inbounds"]; !ok {
		t.Error("missing inbounds")
	}
	if _, ok := cfg["outbounds"]; !ok {
		t.Error("missing outbounds")
	}

	outbounds := cfg["outbounds"].([]interface{})
	if len(outbounds) < 1 {
		t.Fatal("no outbounds")
	}

	proxy := outbounds[0].(map[string]interface{})
	if proxy["type"] != "vmess" {
		t.Errorf("outbound type: got %v", proxy["type"])
	}
	if proxy["server"] != "1.2.3.4" {
		t.Errorf("server: got %v", proxy["server"])
	}
}

func TestGenerateXrayVless(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)

	eng := &engine.Engine{Name: "xray"}
	link := &profile.Link{
		Protocol: "vless",
		Address:  "server.com",
		Port:     443,
		UUID:     "vless-uuid",
		Network:  "tcp",
		TLS:      true,
		SNI:      "server.com",
	}

	configFile, err := cg.Generate(eng, link)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	data, _ := os.ReadFile(configFile)
	var cfg map[string]interface{}
	json.Unmarshal(data, &cfg)

	outbounds := cfg["outbounds"].([]interface{})
	proxy := outbounds[0].(map[string]interface{})
	if proxy["protocol"] != "vless" {
		t.Errorf("protocol: got %v", proxy["protocol"])
	}
}

func TestGenerateWireGuard(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)

	eng := &engine.Engine{Name: "wireguard-go"}
	link := &profile.Link{
		Protocol:   "wireguard",
		Address:    "wg.server.com",
		Port:       51820,
		PrivateKey: "privkey123",
		PublicKey:  "pubkey456",
		Remark:     "wg-test",
	}

	configFile, err := cg.Generate(eng, link)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	data, _ := os.ReadFile(configFile)
	content := string(data)

	if !strings.Contains(content, "PrivateKey = privkey123") {
		t.Error("missing PrivateKey")
	}
	if !strings.Contains(content, "PublicKey = pubkey456") {
		t.Error("missing PublicKey")
	}
	if !strings.Contains(content, "Endpoint = wg.server.com:51820") {
		t.Error("missing Endpoint")
	}
}

func TestGenerateUnsupported(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)

	eng := &engine.Engine{Name: "unknown-engine"}
	link := &profile.Link{Protocol: "vmess"}

	_, err := cg.Generate(eng, link)
	if err == nil {
		t.Error("expected error for unsupported engine")
	}
}

// --- GenerateChainConfig unit tests ---

// parseChainConfig is a test helper that generates a chain config and parses the JSON output.
func parseChainConfig(t *testing.T, cg *ConfigGenerator, chainName string, links []*profile.Link) map[string]interface{} {
	t.Helper()

	configFile, err := cg.GenerateChainConfig(chainName, links)
	if err != nil {
		t.Fatalf("GenerateChainConfig failed: %v", err)
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	return cfg
}

// getOutbounds extracts the outbounds array from a parsed config.
func getOutbounds(t *testing.T, cfg map[string]interface{}) []map[string]interface{} {
	t.Helper()

	raw, ok := cfg["outbounds"]
	if !ok {
		t.Fatal("missing outbounds in config")
	}

	arr, ok := raw.([]interface{})
	if !ok {
		t.Fatal("outbounds is not an array")
	}

	result := make([]map[string]interface{}, len(arr))
	for i, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			t.Fatalf("outbound[%d] is not an object", i)
		}
		result[i] = m
	}
	return result
}

func TestGenerateChainConfig_TwoHopDetourLinkage(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)

	links := []*profile.Link{
		{
			Protocol: "vmess",
			Address:  "iran-server.com",
			Port:     443,
			UUID:     "uuid-hop0",
			Security: "auto",
			Network:  "ws",
			Path:     "/ws",
			Host:     "cdn.example.com",
			TLS:      true,
			SNI:      "cdn.example.com",
		},
		{
			Protocol: "vless",
			Address:  "germany-server.com",
			Port:     443,
			UUID:     "uuid-hop1",
			TLS:      true,
			SNI:      "germany-server.com",
		},
	}

	cfg := parseChainConfig(t, cg, "mychain", links)
	outbounds := getOutbounds(t, cfg)

	// 2 hop outbounds + 1 direct = 3 total
	if len(outbounds) != 3 {
		t.Fatalf("expected 3 outbounds, got %d", len(outbounds))
	}

	// Verify tags follow format chain-<name>-hop-<index>
	if outbounds[0]["tag"] != "chain-mychain-hop-0" {
		t.Errorf("hop-0 tag: got %v, want chain-mychain-hop-0", outbounds[0]["tag"])
	}
	if outbounds[1]["tag"] != "chain-mychain-hop-1" {
		t.Errorf("hop-1 tag: got %v, want chain-mychain-hop-1", outbounds[1]["tag"])
	}

	// First hop has NO detour field (connects directly)
	if _, hasDetour := outbounds[0]["detour"]; hasDetour {
		t.Errorf("hop-0 should not have detour field, got %v", outbounds[0]["detour"])
	}

	// Second hop has detour pointing to first hop's tag (connects through hop-0)
	if outbounds[1]["detour"] != "chain-mychain-hop-0" {
		t.Errorf("hop-1 detour: got %v, want chain-mychain-hop-0", outbounds[1]["detour"])
	}

	// Last outbound is direct
	if outbounds[2]["type"] != "direct" {
		t.Errorf("last outbound type: got %v, want direct", outbounds[2]["type"])
	}
}

func TestGenerateChainConfig_ThreeHopChain(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)

	links := []*profile.Link{
		{
			Protocol: "vmess",
			Address:  "hop0.example.com",
			Port:     443,
			UUID:     "uuid-0",
			Security: "auto",
		},
		{
			Protocol: "vless",
			Address:  "hop1.example.com",
			Port:     443,
			UUID:     "uuid-1",
			TLS:      true,
			SNI:      "hop1.example.com",
		},
		{
			Protocol: "trojan",
			Address:  "hop2.example.com",
			Port:     443,
			UUID:     "uuid-2",
			TLS:      true,
			SNI:      "hop2.example.com",
		},
	}

	cfg := parseChainConfig(t, cg, "triple", links)
	outbounds := getOutbounds(t, cfg)

	// 3 hop outbounds + 1 direct = 4 total
	if len(outbounds) != 4 {
		t.Fatalf("expected 4 outbounds, got %d", len(outbounds))
	}

	// Verify detour chain: hop-0 (no detour), hop-1 → hop-0, hop-2 → hop-1
	if _, hasDetour := outbounds[0]["detour"]; hasDetour {
		t.Errorf("hop-0 should not have detour field, got %v", outbounds[0]["detour"])
	}
	if outbounds[1]["detour"] != "chain-triple-hop-0" {
		t.Errorf("hop-1 detour: got %v, want chain-triple-hop-0", outbounds[1]["detour"])
	}
	if outbounds[2]["detour"] != "chain-triple-hop-1" {
		t.Errorf("hop-2 detour: got %v, want chain-triple-hop-1", outbounds[2]["detour"])
	}

	// All tags are unique
	tags := make(map[string]bool)
	for i, ob := range outbounds {
		tag, ok := ob["tag"].(string)
		if !ok {
			t.Fatalf("outbound[%d] missing tag", i)
		}
		if tags[tag] {
			t.Errorf("duplicate tag: %s", tag)
		}
		tags[tag] = true
	}
}

func TestGenerateChainConfig_MixedProtocols(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)

	links := []*profile.Link{
		{
			Protocol: "vmess",
			Address:  "vmess.example.com",
			Port:     443,
			UUID:     "uuid-vmess",
			Security: "auto",
		},
		{
			Protocol: "trojan",
			Address:  "trojan.example.com",
			Port:     443,
			UUID:     "pass-trojan",
			TLS:      true,
			SNI:      "trojan.example.com",
		},
		{
			Protocol: "shadowsocks",
			Address:  "ss.example.com",
			Port:     8388,
			UUID:     "ss-password",
			Security: "aes-256-gcm",
		},
	}

	cfg := parseChainConfig(t, cg, "mixed", links)
	outbounds := getOutbounds(t, cfg)

	// Verify each outbound has the correct type field
	expectedTypes := []string{"vmess", "trojan", "shadowsocks", "direct"}
	if len(outbounds) != len(expectedTypes) {
		t.Fatalf("expected %d outbounds, got %d", len(expectedTypes), len(outbounds))
	}

	for i, expected := range expectedTypes {
		if outbounds[i]["type"] != expected {
			t.Errorf("outbound[%d] type: got %v, want %s", i, outbounds[i]["type"], expected)
		}
	}
}

// --- Reality sing-box config generation unit tests ---
// Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 5.1

func TestGenerateSingBoxVlessReality(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)

	eng := &engine.Engine{Name: "sing-box"}
	link := &profile.Link{
		Protocol:         "vless",
		Address:          "reality.example.com",
		Port:             443,
		UUID:             "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		Security:         "reality",
		TLS:              true,
		SNI:              "www.microsoft.com",
		RealityPublicKey: "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc",
		RealityShortID:   "a1b2c3d4",
		Fingerprint:      "chrome",
	}

	configFile, err := cg.Generate(eng, link)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	// Verify basic structure
	outbounds := cfg["outbounds"].([]interface{})
	if len(outbounds) < 1 {
		t.Fatal("no outbounds")
	}

	proxy := outbounds[0].(map[string]interface{})

	// Verify outbound type and basic fields
	if proxy["type"] != "vless" {
		t.Errorf("outbound type: got %v, want vless", proxy["type"])
	}
	if proxy["server"] != "reality.example.com" {
		t.Errorf("server: got %v, want reality.example.com", proxy["server"])
	}
	if proxy["server_port"] != float64(443) {
		t.Errorf("server_port: got %v, want 443", proxy["server_port"])
	}
	if proxy["uuid"] != "a1b2c3d4-e5f6-7890-abcd-ef1234567890" {
		t.Errorf("uuid: got %v", proxy["uuid"])
	}

	// Verify TLS object exists
	tlsRaw, hasTLS := proxy["tls"]
	if !hasTLS {
		t.Fatal("expected tls object in outbound")
	}
	tls := tlsRaw.(map[string]interface{})

	// TLS enabled
	if tls["enabled"] != true {
		t.Errorf("tls.enabled: got %v, want true", tls["enabled"])
	}

	// TLS server_name matches SNI
	if tls["server_name"] != "www.microsoft.com" {
		t.Errorf("tls.server_name: got %v, want www.microsoft.com", tls["server_name"])
	}

	// Reality sub-object
	realityRaw, hasReality := tls["reality"]
	if !hasReality {
		t.Fatal("expected tls.reality object")
	}
	reality := realityRaw.(map[string]interface{})

	if reality["enabled"] != true {
		t.Errorf("reality.enabled: got %v, want true", reality["enabled"])
	}
	if reality["public_key"] != "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc" {
		t.Errorf("reality.public_key: got %v", reality["public_key"])
	}
	if reality["short_id"] != "a1b2c3d4" {
		t.Errorf("reality.short_id: got %v, want a1b2c3d4", reality["short_id"])
	}

	// UTLS sub-object
	utlsRaw, hasUTLS := tls["utls"]
	if !hasUTLS {
		t.Fatal("expected tls.utls object")
	}
	utls := utlsRaw.(map[string]interface{})

	if utls["enabled"] != true {
		t.Errorf("utls.enabled: got %v, want true", utls["enabled"])
	}
	if utls["fingerprint"] != "chrome" {
		t.Errorf("utls.fingerprint: got %v, want chrome", utls["fingerprint"])
	}

	// Reality links SHALL NOT have insecure
	if _, hasInsecure := tls["insecure"]; hasInsecure {
		t.Errorf("tls.insecure should not be present for Reality links, got %v", tls["insecure"])
	}
}

func TestGenerateSingBoxVlessStandardTLS_NoReality(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)

	eng := &engine.Engine{Name: "sing-box"}
	link := &profile.Link{
		Protocol: "vless",
		Address:  "standard.example.com",
		Port:     443,
		UUID:     "b2c3d4e5-f6a7-8901-bcde-f12345678901",
		Security: "tls",
		TLS:      true,
		SNI:      "standard.example.com",
	}

	configFile, err := cg.Generate(eng, link)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	outbounds := cfg["outbounds"].([]interface{})
	if len(outbounds) < 1 {
		t.Fatal("no outbounds")
	}

	proxy := outbounds[0].(map[string]interface{})

	// Verify outbound type
	if proxy["type"] != "vless" {
		t.Errorf("outbound type: got %v, want vless", proxy["type"])
	}

	// Verify TLS object exists
	tlsRaw, hasTLS := proxy["tls"]
	if !hasTLS {
		t.Fatal("expected tls object in outbound")
	}
	tls := tlsRaw.(map[string]interface{})

	// TLS enabled
	if tls["enabled"] != true {
		t.Errorf("tls.enabled: got %v, want true", tls["enabled"])
	}

	// Standard TLS has insecure: true
	if tls["insecure"] != true {
		t.Errorf("tls.insecure: got %v, want true", tls["insecure"])
	}

	// Standard TLS SHALL NOT have reality sub-object
	if _, hasReality := tls["reality"]; hasReality {
		t.Error("tls.reality should not be present for standard TLS links")
	}

	// No UTLS since Fingerprint is empty
	if _, hasUTLS := tls["utls"]; hasUTLS {
		t.Error("tls.utls should not be present when Fingerprint is empty")
	}
}

func TestGenerateChainConfig_SingleHopNoDetour(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)

	links := []*profile.Link{
		{
			Protocol: "vmess",
			Address:  "single.example.com",
			Port:     443,
			UUID:     "uuid-single",
			Security: "auto",
			Network:  "tcp",
		},
	}

	cfg := parseChainConfig(t, cg, "solo", links)
	outbounds := getOutbounds(t, cfg)

	// 1 hop outbound + 1 direct = 2 total
	if len(outbounds) != 2 {
		t.Fatalf("expected 2 outbounds, got %d", len(outbounds))
	}

	// The single hop has NO detour field (it connects directly)
	if _, hasDetour := outbounds[0]["detour"]; hasDetour {
		t.Errorf("single hop should not have detour field, got %v", outbounds[0]["detour"])
	}

	// Verify tag format
	if outbounds[0]["tag"] != "chain-solo-hop-0" {
		t.Errorf("hop-0 tag: got %v, want chain-solo-hop-0", outbounds[0]["tag"])
	}

	// Last outbound is direct
	if outbounds[1]["type"] != "direct" {
		t.Errorf("last outbound type: got %v, want direct", outbounds[1]["type"])
	}
}


// Feature: vpn-detection-bypass, Property 3: Generated config contains correct domain bypass rule
//
// For any non-empty list of bypass domains (regardless of whether whitelist countries
// are configured), the generated sing-box config SHALL contain a route rule with
// `domain_suffix` matching those exact domains and routing to the "direct" outbound.
//
// **Validates: Requirements 2.1, 2.3, 2.4**

// Feature: vpn-detection-bypass, Property 4: Domain bypass rule precedes geoip rules
//
// For any generated sing-box config that contains both domain bypass rules and geoip
// whitelist rules, the domain bypass rule SHALL appear at a lower index in the rules
// array than any geoip rule.
//
// **Validates: Requirements 2.2**

func TestProperty_DomainBypassRulePrecedesGeoipRules(t *testing.T) {
	// Generator for valid domain labels
	labelGen := rapid.StringMatching(`[a-z][a-z0-9\-]{1,12}`)

	// Generator for valid TLDs
	tldGen := rapid.SampledFrom([]string{"com", "net", "org", "io", "ir", "info", "co"})

	// Generator for a single valid domain
	domainGen := rapid.Custom(func(t *rapid.T) string {
		label := labelGen.Draw(t, "label")
		tld := tldGen.Draw(t, "tld")
		return label + "." + tld
	})

	// Generator for a non-empty list of unique bypass domains (1 to 10 domains)
	domainsGen := rapid.Custom(func(t *rapid.T) []string {
		count := rapid.IntRange(1, 10).Draw(t, "count")
		seen := make(map[string]bool)
		domains := make([]string, 0, count)
		for len(domains) < count {
			d := domainGen.Draw(t, "domain")
			if !seen[d] {
				seen[d] = true
				domains = append(domains, d)
			}
		}
		return domains
	})

	// Generator for non-empty whitelist countries (must be non-empty to produce geoip rules)
	countriesGen := rapid.Custom(func(t *rapid.T) []string {
		pool := []string{"ir", "cn", "ru", "tr", "ae", "de", "fr"}
		count := rapid.IntRange(1, 4).Draw(t, "countryCount")
		seen := make(map[string]bool)
		countries := make([]string, 0, count)
		for len(countries) < count {
			c := rapid.SampledFrom(pool).Draw(t, "country")
			if !seen[c] {
				seen[c] = true
				countries = append(countries, c)
			}
		}
		return countries
	})

	// Generator for valid protocols supported by sing-box
	protocolGen := rapid.SampledFrom([]string{"vmess", "vless", "trojan", "shadowsocks"})

	// Generator for valid hostnames
	hostGen := rapid.StringMatching(`[a-z][a-z0-9]{2,10}\.(com|net|org|io)`)

	// Generator for valid ports
	portGen := rapid.IntRange(1, 65535)

	// Generator for UUIDs
	uuidGen := rapid.StringMatching(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	tmpDir := t.TempDir()

	rapid.Check(t, func(t *rapid.T) {
		bypassDomains := domainsGen.Draw(t, "bypassDomains")
		countries := countriesGen.Draw(t, "countries")
		protocol := protocolGen.Draw(t, "protocol")
		address := hostGen.Draw(t, "address")
		port := portGen.Draw(t, "port")
		uuid := uuidGen.Draw(t, "uuid")

		link := &profile.Link{
			Protocol: protocol,
			Address:  address,
			Port:     port,
			UUID:     uuid,
			Security: "auto",
			TLS:      true,
			SNI:      address,
		}

		cg := NewConfigGenerator(tmpDir)
		cg.BypassDomains = bypassDomains
		cg.WhitelistCountries = countries

		// Generate the full sing-box config
		configFile, err := cg.generateSingBox(link)
		if err != nil {
			t.Fatalf("generateSingBox failed: %v", err)
		}

		data, err := os.ReadFile(configFile)
		if err != nil {
			t.Fatalf("ReadFile failed: %v", err)
		}

		var cfg map[string]interface{}
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatalf("Invalid JSON: %v", err)
		}

		// Extract route.rules
		routeRaw, hasRoute := cfg["route"]
		if !hasRoute {
			t.Fatal("expected 'route' section in config")
		}
		route, ok := routeRaw.(map[string]interface{})
		if !ok {
			t.Fatalf("route is not a map, got %T", routeRaw)
		}

		rulesRaw, hasRules := route["rules"]
		if !hasRules {
			t.Fatal("expected 'rules' in route section")
		}
		rules, ok := rulesRaw.([]interface{})
		if !ok {
			t.Fatalf("rules is not an array, got %T", rulesRaw)
		}

		// Find the index of the domain_suffix rule (domain bypass rule)
		domainBypassIdx := -1
		for i, ruleRaw := range rules {
			rule, ok := ruleRaw.(map[string]interface{})
			if !ok {
				continue
			}
			if _, hasDomainSuffix := rule["domain_suffix"]; hasDomainSuffix {
				domainBypassIdx = i
				break
			}
		}

		if domainBypassIdx == -1 {
			t.Fatal("expected a rule with 'domain_suffix' in route rules, but none found")
		}

		// Find all geoip rule indices (rules with "rule_set" containing geoip-* tags)
		for i, ruleRaw := range rules {
			rule, ok := ruleRaw.(map[string]interface{})
			if !ok {
				continue
			}
			ruleSetRaw, hasRuleSet := rule["rule_set"]
			if !hasRuleSet {
				continue
			}
			// Check if this rule_set contains geoip references
			ruleSetArr, ok := ruleSetRaw.([]interface{})
			if !ok {
				continue
			}
			for _, tagRaw := range ruleSetArr {
				tag, ok := tagRaw.(string)
				if !ok {
					continue
				}
				if strings.HasPrefix(tag, "geoip-") {
					// Property: domain bypass rule index must be less than geoip rule index
					if domainBypassIdx >= i {
						t.Fatalf("domain bypass rule (index %d) does NOT precede geoip rule (index %d) with tag %q",
							domainBypassIdx, i, tag)
					}
				}
			}
		}
	})
}

func TestProperty_GeneratedConfigContainsCorrectDomainBypassRule(t *testing.T) {
	// Generator for valid domain labels (e.g. "example", "my-site")
	labelGen := rapid.StringMatching(`[a-z][a-z0-9\-]{1,12}`)

	// Generator for valid TLDs
	tldGen := rapid.SampledFrom([]string{"com", "net", "org", "io", "ir", "info", "co"})

	// Generator for a single valid domain
	domainGen := rapid.Custom(func(t *rapid.T) string {
		label := labelGen.Draw(t, "label")
		tld := tldGen.Draw(t, "tld")
		return label + "." + tld
	})

	// Generator for a non-empty list of unique bypass domains (1 to 20 domains)
	domainsGen := rapid.Custom(func(t *rapid.T) []string {
		count := rapid.IntRange(1, 20).Draw(t, "count")
		seen := make(map[string]bool)
		domains := make([]string, 0, count)
		for len(domains) < count {
			d := domainGen.Draw(t, "domain")
			if !seen[d] {
				seen[d] = true
				domains = append(domains, d)
			}
		}
		return domains
	})

	// Generator for optional whitelist countries (can be empty or non-empty)
	countriesGen := rapid.OneOf(
		rapid.Just([]string{}),
		rapid.Just([]string{"ir"}),
		rapid.Just([]string{"ir", "cn"}),
	)

	// Generator for valid protocols supported by sing-box
	protocolGen := rapid.SampledFrom([]string{"vmess", "vless", "trojan", "shadowsocks"})

	// Generator for valid hostnames (for link address)
	hostGen := rapid.StringMatching(`[a-z][a-z0-9]{2,10}\.(com|net|org|io)`)

	// Generator for valid ports
	portGen := rapid.IntRange(1, 65535)

	// Generator for UUIDs
	uuidGen := rapid.StringMatching(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	tmpDir := t.TempDir()

	rapid.Check(t, func(t *rapid.T) {
		bypassDomains := domainsGen.Draw(t, "bypassDomains")
		countries := countriesGen.Draw(t, "countries")
		protocol := protocolGen.Draw(t, "protocol")
		address := hostGen.Draw(t, "address")
		port := portGen.Draw(t, "port")
		uuid := uuidGen.Draw(t, "uuid")

		link := &profile.Link{
			Protocol: protocol,
			Address:  address,
			Port:     port,
			UUID:     uuid,
			Security: "auto",
			TLS:      true,
			SNI:      address,
		}

		cg := NewConfigGenerator(tmpDir)
		cg.BypassDomains = bypassDomains
		cg.WhitelistCountries = countries

		// Generate the full sing-box config
		configFile, err := cg.generateSingBox(link)
		if err != nil {
			t.Fatalf("generateSingBox failed: %v", err)
		}

		data, err := os.ReadFile(configFile)
		if err != nil {
			t.Fatalf("ReadFile failed: %v", err)
		}

		var cfg map[string]interface{}
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatalf("Invalid JSON: %v", err)
		}

		// Property: route section must exist when BypassDomains is non-empty
		routeRaw, hasRoute := cfg["route"]
		if !hasRoute {
			t.Fatal("expected 'route' section in config when BypassDomains is non-empty")
		}
		route, ok := routeRaw.(map[string]interface{})
		if !ok {
			t.Fatalf("route is not a map, got %T", routeRaw)
		}

		// Property: route must contain rules array
		rulesRaw, hasRules := route["rules"]
		if !hasRules {
			t.Fatal("expected 'rules' in route section")
		}
		rules, ok := rulesRaw.([]interface{})
		if !ok {
			t.Fatalf("rules is not an array, got %T", rulesRaw)
		}

		// Find the domain_suffix rule
		var domainRule map[string]interface{}
		for _, ruleRaw := range rules {
			rule, ok := ruleRaw.(map[string]interface{})
			if !ok {
				continue
			}
			if _, hasDomainSuffix := rule["domain_suffix"]; hasDomainSuffix {
				domainRule = rule
				break
			}
		}

		if domainRule == nil {
			t.Fatal("expected a rule with 'domain_suffix' in route rules, but none found")
		}

		// Property: domain_suffix must match the exact bypass domains
		domainSuffixRaw := domainRule["domain_suffix"]
		domainSuffixArr, ok := domainSuffixRaw.([]interface{})
		if !ok {
			t.Fatalf("domain_suffix is not an array, got %T", domainSuffixRaw)
		}

		if len(domainSuffixArr) != len(bypassDomains) {
			t.Fatalf("domain_suffix length: got %d, want %d", len(domainSuffixArr), len(bypassDomains))
		}

		for i, expected := range bypassDomains {
			got, ok := domainSuffixArr[i].(string)
			if !ok {
				t.Fatalf("domain_suffix[%d] is not a string, got %T", i, domainSuffixArr[i])
			}
			if got != expected {
				t.Fatalf("domain_suffix[%d]: got %q, want %q", i, got, expected)
			}
		}

		// Property: the rule must route to "direct" outbound
		if domainRule["outbound"] != "direct" {
			t.Fatalf("domain bypass rule outbound: got %v, want \"direct\"", domainRule["outbound"])
		}

		// Property: the rule must have action "route"
		if domainRule["action"] != "route" {
			t.Fatalf("domain bypass rule action: got %v, want \"route\"", domainRule["action"])
		}
	})
}


// TestEndToEnd_ConfigLoadToSingBoxBypassDomains is an integration test that verifies
// the full flow: load YAML config with bypass_domains → create ConfigGenerator →
// generate sing-box config → verify domain_suffix rule is present and routes to "direct".
//
// **Validates: Requirements 2.1, 3.1, 3.2**
func TestEndToEnd_ConfigLoadToSingBoxBypassDomains(t *testing.T) {
	tmpDir := t.TempDir()

	// Step 1: Write a YAML config file with bypass_domains
	yamlContent := `
server:
  listen: "0.0.0.0"
  api_port: 8080
  socks_port: 2801
whitelist:
  countries: ["ir"]
  bypass_domains:
    - "cloudflare.com"
    - "ip-api.com"
    - "custom-check.example.org"
`
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	// Step 2: Load the config using config.Load()
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}

	// Verify the loaded config has the expected bypass domains
	expectedDomains := []string{"cloudflare.com", "ip-api.com", "custom-check.example.org"}
	if len(cfg.Whitelist.BypassDomains) != len(expectedDomains) {
		t.Fatalf("loaded bypass_domains length: got %d, want %d",
			len(cfg.Whitelist.BypassDomains), len(expectedDomains))
	}
	for i, expected := range expectedDomains {
		if cfg.Whitelist.BypassDomains[i] != expected {
			t.Fatalf("loaded bypass_domains[%d]: got %q, want %q",
				i, cfg.Whitelist.BypassDomains[i], expected)
		}
	}

	// Step 3: Create a ConfigGenerator with BypassDomains from the loaded config
	genDir := filepath.Join(tmpDir, "gen")
	cg := NewConfigGenerator(genDir)
	cg.BypassDomains = cfg.Whitelist.BypassDomains
	cg.WhitelistCountries = cfg.Whitelist.Countries

	// Step 4: Generate a sing-box config with a valid link
	eng := &engine.Engine{Name: "sing-box"}
	link := &profile.Link{
		Protocol: "vmess",
		Address:  "proxy.example.com",
		Port:     443,
		UUID:     "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		Security: "auto",
		Network:  "ws",
		Path:     "/ws",
		Host:     "cdn.example.com",
		TLS:      true,
		SNI:      "cdn.example.com",
	}

	configFile, err := cg.Generate(eng, link)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Step 5: Parse the JSON output and verify the domain_suffix rule
	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	var singboxCfg map[string]interface{}
	if err := json.Unmarshal(data, &singboxCfg); err != nil {
		t.Fatalf("Invalid JSON output: %v", err)
	}

	// Verify route section exists
	routeRaw, hasRoute := singboxCfg["route"]
	if !hasRoute {
		t.Fatal("expected 'route' section in generated sing-box config")
	}
	route, ok := routeRaw.(map[string]interface{})
	if !ok {
		t.Fatalf("route is not a map, got %T", routeRaw)
	}

	// Verify rules array exists
	rulesRaw, hasRules := route["rules"]
	if !hasRules {
		t.Fatal("expected 'rules' in route section")
	}
	rules, ok := rulesRaw.([]interface{})
	if !ok {
		t.Fatalf("rules is not an array, got %T", rulesRaw)
	}

	// Find the domain_suffix rule
	var domainRule map[string]interface{}
	for _, ruleRaw := range rules {
		rule, ok := ruleRaw.(map[string]interface{})
		if !ok {
			continue
		}
		if _, hasDomainSuffix := rule["domain_suffix"]; hasDomainSuffix {
			domainRule = rule
			break
		}
	}

	if domainRule == nil {
		t.Fatal("expected a rule with 'domain_suffix' in route rules, but none found")
	}

	// Verify domain_suffix contains the exact domains from config
	domainSuffixRaw := domainRule["domain_suffix"]
	domainSuffixArr, ok := domainSuffixRaw.([]interface{})
	if !ok {
		t.Fatalf("domain_suffix is not an array, got %T", domainSuffixRaw)
	}

	if len(domainSuffixArr) != len(expectedDomains) {
		t.Fatalf("domain_suffix length: got %d, want %d", len(domainSuffixArr), len(expectedDomains))
	}

	for i, expected := range expectedDomains {
		got, ok := domainSuffixArr[i].(string)
		if !ok {
			t.Fatalf("domain_suffix[%d] is not a string, got %T", i, domainSuffixArr[i])
		}
		if got != expected {
			t.Fatalf("domain_suffix[%d]: got %q, want %q", i, got, expected)
		}
	}

	// Verify the rule routes to "direct" outbound
	if domainRule["outbound"] != "direct" {
		t.Fatalf("domain bypass rule outbound: got %v, want \"direct\"", domainRule["outbound"])
	}

	// Verify the rule has action "route"
	if domainRule["action"] != "route" {
		t.Fatalf("domain bypass rule action: got %v, want \"route\"", domainRule["action"])
	}
}
