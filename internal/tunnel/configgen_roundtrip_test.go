package tunnel

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/liberoute/bypath/internal/profile"
)

// TestRoundTrip_GatewayMode_AllProtocols verifies that for each supported protocol,
// generating a config in gateway mode produces valid JSON with the expected structure:
// - TUN inbound + Mixed inbound
// - TUN has correct fields (inet4_address, stack, auto_route)
// - DNS section has tunnel + direct servers
// - DNS has listen address and port
//
// Validates: Requirements 1.1, 1.3, 1.4, 1.5, 1.6, 2.1, 2.2, 2.3, 2.5
func TestRoundTrip_GatewayMode_AllProtocols(t *testing.T) {
	tests := []struct {
		name string
		link *profile.Link
	}{
		{
			name: "vmess",
			link: &profile.Link{
				Protocol: "vmess",
				Address:  "vmess.example.com",
				Port:     443,
				UUID:     "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
				Security: "auto",
				Network:  "ws",
				Path:     "/ws",
				Host:     "cdn.example.com",
				TLS:      true,
				SNI:      "cdn.example.com",
				Remark:   "vmess-test",
			},
		},
		{
			name: "vless",
			link: &profile.Link{
				Protocol:         "vless",
				Address:          "vless.example.com",
				Port:             443,
				UUID:             "b2c3d4e5-f6a7-8901-bcde-f12345678901",
				Security:         "reality",
				TLS:              true,
				SNI:              "www.microsoft.com",
				RealityPublicKey: "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc",
				RealityShortID:   "a1b2c3d4",
				Fingerprint:      "chrome",
				Remark:           "vless-reality-test",
			},
		},
		{
			name: "trojan",
			link: &profile.Link{
				Protocol: "trojan",
				Address:  "trojan.example.com",
				Port:     443,
				UUID:     "trojan-password-123",
				TLS:      true,
				SNI:      "trojan.example.com",
				Remark:   "trojan-test",
			},
		},
		{
			name: "shadowsocks",
			link: &profile.Link{
				Protocol: "shadowsocks",
				Address:  "ss.example.com",
				Port:     8388,
				UUID:     "ss-password-456",
				Security: "aes-256-gcm",
				Remark:   "ss-test",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cg := NewConfigGenerator(tmpDir)
			cg.GatewayMode = true
			cg.DNSPort = 53
			cg.WhitelistCountries = []string{"ir", "cn"}

			configFile, err := cg.generateSingBox(tc.link)
			if err != nil {
				t.Fatalf("generateSingBox failed: %v", err)
			}

			data, err := os.ReadFile(configFile)
			if err != nil {
				t.Fatalf("ReadFile failed: %v", err)
			}

			var cfg map[string]interface{}
			if err := json.Unmarshal(data, &cfg); err != nil {
				t.Fatalf("Invalid JSON output: %v", err)
			}

			// --- Verify inbounds ---
			inboundsRaw, ok := cfg["inbounds"]
			if !ok {
				t.Fatal("missing 'inbounds' in config")
			}
			inboundsArr, ok := inboundsRaw.([]interface{})
			if !ok {
				t.Fatalf("inbounds is not an array, got %T", inboundsRaw)
			}
			if len(inboundsArr) < 2 {
				t.Fatalf("expected at least 2 inbounds (TUN + Mixed), got %d", len(inboundsArr))
			}

			// Find TUN and Mixed inbounds
			var tunInbound, mixedInbound map[string]interface{}
			for _, ibRaw := range inboundsArr {
				ib, ok := ibRaw.(map[string]interface{})
				if !ok {
					t.Fatal("inbound entry is not a map")
				}
				switch ib["type"] {
				case "tun":
					tunInbound = ib
				case "mixed":
					mixedInbound = ib
				}
			}

			if tunInbound == nil {
				t.Fatal("expected a TUN inbound, but none found")
			}
			if mixedInbound == nil {
				t.Fatal("expected a Mixed inbound, but none found")
			}

			// Verify TUN constant fields (Req 1.4, 1.5, 1.6)
			if tunInbound["inet4_address"] != "10.0.0.1/30" {
				t.Errorf("TUN inet4_address: got %v, want \"10.0.0.1/30\"", tunInbound["inet4_address"])
			}
			if tunInbound["stack"] != "system" {
				t.Errorf("TUN stack: got %v, want \"system\"", tunInbound["stack"])
			}
			if tunInbound["auto_route"] != true {
				t.Errorf("TUN auto_route: got %v, want true", tunInbound["auto_route"])
			}

			// --- Verify DNS section ---
			dnsRaw, hasDNS := cfg["dns"]
			if !hasDNS {
				t.Fatal("expected 'dns' section in gateway mode config")
			}
			dns, ok := dnsRaw.(map[string]interface{})
			if !ok {
				t.Fatalf("dns is not a map, got %T", dnsRaw)
			}

			// Verify DNS servers (Req 2.1, 2.2, 2.3)
			serversRaw, hasServers := dns["servers"]
			if !hasServers {
				t.Fatal("expected 'servers' in dns section")
			}
			serversArr, ok := serversRaw.([]interface{})
			if !ok {
				t.Fatalf("dns.servers is not an array, got %T", serversRaw)
			}
			if len(serversArr) < 2 {
				t.Fatalf("expected at least 2 DNS servers, got %d", len(serversArr))
			}

			hasTunnelServer := false
			hasDirectServer := false
			for _, sRaw := range serversArr {
				s, ok := sRaw.(map[string]interface{})
				if !ok {
					continue
				}
				if s["detour"] == "proxy" {
					hasTunnelServer = true
				}
				if s["tag"] == "dns-direct" {
					hasDirectServer = true
				}
			}
			if !hasTunnelServer {
				t.Error("expected a DNS server with detour \"proxy\" (tunnel)")
			}
			if !hasDirectServer {
				t.Error("expected a DNS server with tag \"dns-direct\"")
			}

			// Verify DNS inbound exists (Req 2.5) - sing-box 1.12+ uses separate inbound
			hasDNSInbound := false
			for _, ibRaw := range inboundsArr {
				ib, ok := ibRaw.(map[string]interface{})
				if !ok {
					continue
				}
				if ib["tag"] == "dns-in" {
					hasDNSInbound = true
					break
				}
			}
			if !hasDNSInbound {
				t.Error("expected dns-in inbound in gateway mode")
			}

			// --- Verify outbound has correct protocol type ---
			outboundsRaw, hasOutbounds := cfg["outbounds"]
			if !hasOutbounds {
				t.Fatal("missing 'outbounds' in config")
			}
			outboundsArr, ok := outboundsRaw.([]interface{})
			if !ok {
				t.Fatalf("outbounds is not an array, got %T", outboundsRaw)
			}
			if len(outboundsArr) < 1 {
				t.Fatal("expected at least 1 outbound")
			}
			proxy, ok := outboundsArr[0].(map[string]interface{})
			if !ok {
				t.Fatal("first outbound is not a map")
			}

			// Map protocol names to expected sing-box type
			expectedType := tc.link.Protocol
			if proxy["type"] != expectedType {
				t.Errorf("outbound type: got %v, want %q", proxy["type"], expectedType)
			}
		})
	}
}

// TestRoundTrip_ProxyMode_AllProtocols verifies that for each supported protocol,
// generating a config in proxy mode (GatewayMode=false) produces valid JSON with:
// - Only Mixed inbound (no TUN)
// - No DNS listen config
//
// Validates: Requirements 1.2, 2.6
func TestRoundTrip_ProxyMode_AllProtocols(t *testing.T) {
	tests := []struct {
		name string
		link *profile.Link
	}{
		{
			name: "vmess",
			link: &profile.Link{
				Protocol: "vmess",
				Address:  "vmess.example.com",
				Port:     443,
				UUID:     "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
				Security: "auto",
				Network:  "ws",
				Path:     "/ws",
				Host:     "cdn.example.com",
				TLS:      true,
				SNI:      "cdn.example.com",
				Remark:   "vmess-test",
			},
		},
		{
			name: "vless",
			link: &profile.Link{
				Protocol:         "vless",
				Address:          "vless.example.com",
				Port:             443,
				UUID:             "b2c3d4e5-f6a7-8901-bcde-f12345678901",
				Security:         "reality",
				TLS:              true,
				SNI:              "www.microsoft.com",
				RealityPublicKey: "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc",
				RealityShortID:   "a1b2c3d4",
				Fingerprint:      "chrome",
				Remark:           "vless-reality-test",
			},
		},
		{
			name: "trojan",
			link: &profile.Link{
				Protocol: "trojan",
				Address:  "trojan.example.com",
				Port:     443,
				UUID:     "trojan-password-123",
				TLS:      true,
				SNI:      "trojan.example.com",
				Remark:   "trojan-test",
			},
		},
		{
			name: "shadowsocks",
			link: &profile.Link{
				Protocol: "shadowsocks",
				Address:  "ss.example.com",
				Port:     8388,
				UUID:     "ss-password-456",
				Security: "aes-256-gcm",
				Remark:   "ss-test",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cg := NewConfigGenerator(tmpDir)
			cg.GatewayMode = false

			configFile, err := cg.generateSingBox(tc.link)
			if err != nil {
				t.Fatalf("generateSingBox failed: %v", err)
			}

			data, err := os.ReadFile(configFile)
			if err != nil {
				t.Fatalf("ReadFile failed: %v", err)
			}

			var cfg map[string]interface{}
			if err := json.Unmarshal(data, &cfg); err != nil {
				t.Fatalf("Invalid JSON output: %v", err)
			}

			// --- Verify inbounds: only Mixed, no TUN ---
			inboundsRaw, ok := cfg["inbounds"]
			if !ok {
				t.Fatal("missing 'inbounds' in config")
			}
			inboundsArr, ok := inboundsRaw.([]interface{})
			if !ok {
				t.Fatalf("inbounds is not an array, got %T", inboundsRaw)
			}
			if len(inboundsArr) != 1 {
				t.Fatalf("expected 1 inbound in proxy mode, got %d", len(inboundsArr))
			}

			inbound, ok := inboundsArr[0].(map[string]interface{})
			if !ok {
				t.Fatal("inbound entry is not a map")
			}
			if inbound["type"] != "mixed" {
				t.Errorf("inbound type: got %v, want \"mixed\"", inbound["type"])
			}

			// Ensure no TUN inbound exists
			for _, ibRaw := range inboundsArr {
				ib, ok := ibRaw.(map[string]interface{})
				if !ok {
					continue
				}
				if ib["type"] == "tun" {
					t.Fatal("TUN inbound should NOT be present in proxy mode")
				}
			}

			// --- Verify no DNS listen config (Req 2.6) ---
			if dnsRaw, hasDNS := cfg["dns"]; hasDNS {
				dns, ok := dnsRaw.(map[string]interface{})
				if ok {
					if _, hasListen := dns["listen"]; hasListen {
						t.Error("dns.listen should NOT be present in proxy mode")
					}
					if _, hasPort := dns["listen_port"]; hasPort {
						t.Error("dns.listen_port should NOT be present in proxy mode")
					}
				}
			}

			// --- Verify outbound has correct protocol type ---
			outboundsRaw, hasOutbounds := cfg["outbounds"]
			if !hasOutbounds {
				t.Fatal("missing 'outbounds' in config")
			}
			outboundsArr, ok := outboundsRaw.([]interface{})
			if !ok {
				t.Fatalf("outbounds is not an array, got %T", outboundsRaw)
			}
			if len(outboundsArr) < 1 {
				t.Fatal("expected at least 1 outbound")
			}
			proxy, ok := outboundsArr[0].(map[string]interface{})
			if !ok {
				t.Fatal("first outbound is not a map")
			}

			expectedType := tc.link.Protocol
			if proxy["type"] != expectedType {
				t.Errorf("outbound type: got %v, want %q", proxy["type"], expectedType)
			}
		})
	}
}
