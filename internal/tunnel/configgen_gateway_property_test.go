package tunnel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
	"pgregory.net/rapid"
)

// --- Generators for property tests ---

// genProtocol generates a random supported protocol.
var genProtocol = rapid.SampledFrom([]string{
	"vmess", "vless", "trojan", "shadowsocks", "wireguard", "socks5", "http",
})

// genNetwork generates a random transport network type.
var genNetwork = rapid.SampledFrom([]string{"tcp", "ws", "grpc", ""})

// genPort generates a valid port number.
var genPort = rapid.IntRange(1, 65535)

// genAddress generates a random server address.
var genAddress = rapid.StringMatching(`[a-z][a-z0-9]{2,10}\.(com|net|org|io|ir)`)

// genUUID generates a random UUID-like string.
var genUUID = rapid.StringMatching(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// genSecurity generates a random security method.
var genSecurity = rapid.SampledFrom([]string{"auto", "aes-128-gcm", "chacha20-poly1305", "none", "reality", "tls"})

// genCountryCode generates a random country code.
var genCountryCode = rapid.SampledFrom([]string{"ir", "cn", "ru", "tr", "ae", "de", "fr", "us", "gb"})

// genLink generates a random profile.Link struct with varying fields.
var genLink = rapid.Custom(func(t *rapid.T) *profile.Link {
	protocol := genProtocol.Draw(t, "protocol")
	address := genAddress.Draw(t, "address")
	port := genPort.Draw(t, "port")
	uuid := genUUID.Draw(t, "uuid")
	security := genSecurity.Draw(t, "security")
	network := genNetwork.Draw(t, "network")
	tls := rapid.Bool().Draw(t, "tls")
	sni := ""
	if tls {
		sni = address
	}
	path := ""
	host := ""
	if network == "ws" {
		path = "/" + rapid.StringMatching(`[a-z]{2,8}`).Draw(t, "path")
		host = address
	}

	link := &profile.Link{
		Protocol: protocol,
		Address:  address,
		Port:     port,
		UUID:     uuid,
		Security: security,
		Network:  network,
		TLS:      tls,
		SNI:      sni,
		Path:     path,
		Host:     host,
		Remark:   "test-link",
	}

	// Add Reality fields for vless with reality security
	if protocol == "vless" && security == "reality" {
		link.TLS = true
		link.RealityPublicKey = rapid.StringMatching(`[A-Za-z0-9\-_]{32,44}`).Draw(t, "realityPubKey")
		link.RealityShortID = rapid.StringMatching(`[0-9a-f]{8}`).Draw(t, "realityShortID")
		link.Fingerprint = rapid.SampledFrom([]string{"chrome", "firefox", "safari", ""}).Draw(t, "fingerprint")
	}

	// Add WireGuard fields
	if protocol == "wireguard" {
		link.PrivateKey = rapid.StringMatching(`[A-Za-z0-9+/]{43}=`).Draw(t, "privateKey")
		link.PublicKey = rapid.StringMatching(`[A-Za-z0-9+/]{43}=`).Draw(t, "publicKey")
	}

	return link
})

// genWhitelistCountries generates a non-empty list of unique country codes.
var genWhitelistCountries = rapid.Custom(func(t *rapid.T) []string {
	count := rapid.IntRange(1, 5).Draw(t, "countryCount")
	pool := []string{"ir", "cn", "ru", "tr", "ae", "de", "fr", "us", "gb"}
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

// --- Helper functions ---

// parseSingBoxConfig generates a sing-box config and parses the JSON output.
func parseSingBoxConfig(t *rapid.T, cg *ConfigGenerator, link *profile.Link) map[string]interface{} {
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

	return cfg
}

// getInbounds extracts the inbounds array from a parsed config.
func getInboundsFromConfig(cfg map[string]interface{}) ([]map[string]interface{}, bool) {
	raw, ok := cfg["inbounds"]
	if !ok {
		return nil, false
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return nil, false
	}
	result := make([]map[string]interface{}, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			return nil, false
		}
		result = append(result, m)
	}
	return result, true
}

// getDNSFromConfig extracts the dns section from a parsed config.
func getDNSFromConfig(cfg map[string]interface{}) (map[string]interface{}, bool) {
	raw, ok := cfg["dns"]
	if !ok {
		return nil, false
	}
	dns, ok := raw.(map[string]interface{})
	return dns, ok
}

// getDNSServers extracts the servers array from a DNS section.
func getDNSServers(dns map[string]interface{}) ([]map[string]interface{}, bool) {
	raw, ok := dns["servers"]
	if !ok {
		return nil, false
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return nil, false
	}
	result := make([]map[string]interface{}, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			return nil, false
		}
		result = append(result, m)
	}
	return result, true
}

// getDNSRules extracts the rules array from a DNS section.
func getDNSRules(dns map[string]interface{}) ([]map[string]interface{}, bool) {
	raw, ok := dns["rules"]
	if !ok {
		return nil, false
	}
	arr, ok := raw.([]interface{})
	if !ok {
		return nil, false
	}
	result := make([]map[string]interface{}, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]interface{})
		if !ok {
			return nil, false
		}
		result = append(result, m)
	}
	return result, true
}

// --- Property Tests ---

// Feature: singbox-tun-inbound, Property 1: Gateway mode produces both TUN and Mixed inbounds
//
// For any valid Link struct, when the ConfigGenerator has GatewayMode enabled,
// the generated sing-box configuration SHALL contain exactly two inbounds:
// one with type: "tun" and one with type: "mixed".
//
// **Validates: Requirements 1.1, 1.3**
func TestProperty_GatewayModeProducesTUNAndMixedInbounds(t *testing.T) {
	tmpDir := t.TempDir()

	rapid.Check(t, func(t *rapid.T) {
		link := genLink.Draw(t, "link")
		countries := genWhitelistCountries.Draw(t, "countries")

		cg := NewConfigGenerator(tmpDir)
		cg.GatewayMode = true
		cg.DNSPort = 53
		cg.WhitelistCountries = countries

		cfg := parseSingBoxConfig(t, cg, link)

		inbounds, ok := getInboundsFromConfig(cfg)
		if !ok {
			t.Fatal("expected inbounds array in config")
		}

		if len(inbounds) < 2 {
			t.Fatalf("expected at least 2 inbounds in gateway mode, got %d", len(inbounds))
		}

		// Check that one is TUN and one is Mixed
		hasTUN := false
		hasMixed := false
		for _, inbound := range inbounds {
			switch inbound["type"] {
			case "tun":
				hasTUN = true
			case "mixed":
				hasMixed = true
			}
		}

		if !hasTUN {
			t.Fatal("expected a TUN inbound in gateway mode, but none found")
		}
		if !hasMixed {
			t.Fatal("expected a Mixed inbound in gateway mode, but none found")
		}
	})
}

// Feature: singbox-tun-inbound, Property 2: TUN inbound has correct constant fields
//
// For any valid Link struct with GatewayMode enabled, the TUN inbound in the generated
// configuration SHALL have inet4_address equal to "10.0.0.1/30", stack equal to "system",
// and auto_route equal to true.
//
// **Validates: Requirements 1.4, 1.5, 1.6**
func TestProperty_TUNInboundHasCorrectConstantFields(t *testing.T) {
	tmpDir := t.TempDir()

	rapid.Check(t, func(t *rapid.T) {
		link := genLink.Draw(t, "link")
		countries := genWhitelistCountries.Draw(t, "countries")

		cg := NewConfigGenerator(tmpDir)
		cg.GatewayMode = true
		cg.DNSPort = 53
		cg.WhitelistCountries = countries

		cfg := parseSingBoxConfig(t, cg, link)

		inbounds, ok := getInboundsFromConfig(cfg)
		if !ok {
			t.Fatal("expected inbounds array in config")
		}

		// Find the TUN inbound
		var tunInbound map[string]interface{}
		for _, inbound := range inbounds {
			if inbound["type"] == "tun" {
				tunInbound = inbound
				break
			}
		}

		if tunInbound == nil {
			t.Fatal("expected a TUN inbound in gateway mode, but none found")
		}

		// Verify constant fields
		addrRaw, ok := tunInbound["address"]
		if !ok {
			t.Fatalf("TUN address field missing")
		}
		addrOK := false
		switch v := addrRaw.(type) {
		case []string:
			addrOK = len(v) > 0 && v[0] == "10.0.0.1/30"
		case []interface{}:
			addrOK = len(v) > 0 && fmt.Sprint(v[0]) == "10.0.0.1/30"
		}
		if !addrOK {
			t.Fatalf("TUN address: got %v, want [\"10.0.0.1/30\"]", addrRaw)
		}
		if tunInbound["stack"] != "system" {
			t.Fatalf("TUN stack: got %v, want \"system\"", tunInbound["stack"])
		}
		if tunInbound["auto_route"] != true {
			t.Fatalf("TUN auto_route: got %v, want true", tunInbound["auto_route"])
		}
	})
}

// Feature: singbox-tun-inbound, Property 3: Proxy-only mode produces only Mixed inbound
//
// For any valid Link struct, when the ConfigGenerator has GatewayMode disabled,
// the generated sing-box configuration SHALL contain exactly one inbound with
// type: "mixed" and no inbound with type: "tun".
//
// **Validates: Requirements 1.2**
func TestProperty_ProxyOnlyModeProducesOnlyMixedInbound(t *testing.T) {
	tmpDir := t.TempDir()

	rapid.Check(t, func(t *rapid.T) {
		link := genLink.Draw(t, "link")

		cg := NewConfigGenerator(tmpDir)
		cg.GatewayMode = false

		cfg := parseSingBoxConfig(t, cg, link)

		inbounds, ok := getInboundsFromConfig(cfg)
		if !ok {
			t.Fatal("expected inbounds array in config")
		}

		if len(inbounds) != 1 {
			t.Fatalf("expected exactly 1 inbound in proxy-only mode, got %d", len(inbounds))
		}

		if inbounds[0]["type"] != "mixed" {
			t.Fatalf("expected inbound type \"mixed\" in proxy-only mode, got %v", inbounds[0]["type"])
		}

		// Ensure no TUN inbound exists
		for _, inbound := range inbounds {
			if inbound["type"] == "tun" {
				t.Fatal("TUN inbound should NOT be present in proxy-only mode")
			}
		}
	})
}

// Feature: singbox-tun-inbound, Property 4: Gateway DNS has tunnel and direct servers with correct routing
//
// For any valid Link struct with GatewayMode enabled, the generated DNS section SHALL
// contain at least two servers where one has detour: "proxy" (tunnel) and one has
// detour: "direct".
//
// **Validates: Requirements 2.1, 2.2, 2.3**
func TestProperty_GatewayDNSHasTunnelAndDirectServers(t *testing.T) {
	tmpDir := t.TempDir()

	rapid.Check(t, func(t *rapid.T) {
		link := genLink.Draw(t, "link")
		countries := genWhitelistCountries.Draw(t, "countries")

		cg := NewConfigGenerator(tmpDir)
		cg.GatewayMode = true
		cg.DNSPort = 53
		cg.WhitelistCountries = countries

		cfg := parseSingBoxConfig(t, cg, link)

		dns, ok := getDNSFromConfig(cfg)
		if !ok {
			t.Fatal("expected dns section in gateway mode config")
		}

		servers, ok := getDNSServers(dns)
		if !ok {
			t.Fatal("expected servers array in dns section")
		}

		if len(servers) < 2 {
			t.Fatalf("expected at least 2 DNS servers, got %d", len(servers))
		}

		// Check for tunnel server (detour: "proxy")
		// Check for direct server (tag: "dns-direct", no detour needed since it resolves directly)
		hasTunnel := false
		hasDirect := false
		for _, server := range servers {
			if server["detour"] == "proxy" {
				hasTunnel = true
			}
			if server["tag"] == "dns-direct" {
				hasDirect = true
			}
		}

		if !hasTunnel {
			t.Fatal("expected a DNS server with detour \"proxy\" (tunnel), but none found")
		}
		if !hasDirect {
			t.Fatal("expected a DNS server with tag \"dns-direct\", but none found")
		}
	})
}

// Feature: singbox-tun-inbound, Property 5: DNS rules reference whitelist countries
//
// For any non-empty whitelist country list with GatewayMode enabled, the generated DNS
// rules SHALL contain rule_set references for each whitelisted country (as geosite entries)
// routing to the direct DNS server.
//
// **Validates: Requirements 2.4**
func TestProperty_DNSRulesReferenceWhitelistCountries(t *testing.T) {
	tmpDir := t.TempDir()

	rapid.Check(t, func(t *rapid.T) {
		link := genLink.Draw(t, "link")
		countries := genWhitelistCountries.Draw(t, "countries")

		// Create dummy geosite files so the file-existence check passes
		geoDir := paths.Get().GeoDir
		os.MkdirAll(geoDir, 0755)
		for _, c := range countries {
			os.WriteFile(filepath.Join(geoDir, fmt.Sprintf("geosite-%s.srs", c)), []byte("dummy"), 0644)
		}

		cg := NewConfigGenerator(tmpDir)
		cg.GatewayMode = true
		cg.DNSPort = 53
		cg.WhitelistCountries = countries

		cfg := parseSingBoxConfig(t, cg, link)

		dns, ok := getDNSFromConfig(cfg)
		if !ok {
			t.Fatal("expected dns section in gateway mode config")
		}

		rules, ok := getDNSRules(dns)
		if !ok {
			t.Fatal("expected rules array in dns section")
		}

		// Find the rule that references geosite rule_sets
		var geositeRule map[string]interface{}
		for _, rule := range rules {
			if _, hasRuleSet := rule["rule_set"]; hasRuleSet {
				geositeRule = rule
				break
			}
		}

		if geositeRule == nil {
			t.Fatal("expected a DNS rule with rule_set references, but none found")
		}

		// Verify it routes to dns-direct
		if geositeRule["server"] != "dns-direct" {
			t.Fatalf("DNS geosite rule server: got %v, want \"dns-direct\"", geositeRule["server"])
		}

		// Verify all whitelist countries are referenced as geosite-<country>
		ruleSetRaw := geositeRule["rule_set"]
		ruleSetArr, ok := ruleSetRaw.([]interface{})
		if !ok {
			t.Fatalf("rule_set is not an array, got %T", ruleSetRaw)
		}

		// Build a set of expected geosite tags
		expectedTags := make(map[string]bool)
		for _, country := range countries {
			expectedTags["geosite-"+country] = true
		}

		// Build a set of actual tags
		actualTags := make(map[string]bool)
		for _, tagRaw := range ruleSetArr {
			tag, ok := tagRaw.(string)
			if !ok {
				continue
			}
			actualTags[tag] = true
		}

		// Every expected tag must be present
		for tag := range expectedTags {
			if !actualTags[tag] {
				t.Fatalf("expected DNS rule_set to contain %q, but it was missing. Got: %v", tag, ruleSetArr)
			}
		}
	})
}

// Feature: singbox-tun-inbound, Property 6: DNS listen is present only in gateway mode
//
// For any valid Link struct, the generated DNS section SHALL include a listen address
// and port when GatewayMode is enabled, and SHALL omit the listen configuration when
// GatewayMode is disabled.
//
// **Validates: Requirements 2.5, 2.6**
func TestProperty_DNSListenPresentOnlyInGatewayMode(t *testing.T) {
	tmpDir := t.TempDir()

	rapid.Check(t, func(t *rapid.T) {
		link := genLink.Draw(t, "link")
		countries := genWhitelistCountries.Draw(t, "countries")
		gatewayMode := rapid.Bool().Draw(t, "gatewayMode")
		dnsPort := rapid.IntRange(53, 5353).Draw(t, "dnsPort")

		cg := NewConfigGenerator(tmpDir)
		cg.GatewayMode = gatewayMode
		cg.DNSPort = dnsPort
		cg.WhitelistCountries = countries

		cfg := parseSingBoxConfig(t, cg, link)

		// Check inbounds for dns-in (sing-box 1.12+ uses separate inbound for DNS)
		inboundsRaw, hasInbounds := cfg["inbounds"]
		if !hasInbounds {
			t.Fatal("expected inbounds in config")
		}
		inbounds, ok := inboundsRaw.([]interface{})
		if !ok {
			t.Fatal("inbounds is not an array")
		}

		hasDNSInbound := false
		var dnsInboundPort interface{}
		for _, ibRaw := range inbounds {
			ib, ok := ibRaw.(map[string]interface{})
			if !ok {
				continue
			}
			if ib["tag"] == "dns-in" {
				hasDNSInbound = true
				dnsInboundPort = ib["listen_port"]
			}
		}

		if gatewayMode {
			if !hasDNSInbound {
				t.Fatal("expected dns-in inbound in gateway mode config")
			}
			portFloat, ok := dnsInboundPort.(float64)
			if ok {
				if int(portFloat) != dnsPort {
					t.Fatalf("dns-in listen_port: got %v, want %d", portFloat, dnsPort)
				}
			} else {
				portInt, ok := dnsInboundPort.(int)
				if !ok {
					t.Fatalf("dns-in listen_port is not a number, got %T: %v", dnsInboundPort, dnsInboundPort)
				}
				if portInt != dnsPort {
					t.Fatalf("dns-in listen_port: got %d, want %d", portInt, dnsPort)
				}
			}
		} else {
			if hasDNSInbound {
				t.Fatal("dns-in inbound should NOT be present in proxy-only mode")
			}
		}
	})
}
