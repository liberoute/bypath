package tunnel

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
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
