package profile

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"

	"pgregory.net/rapid"
)

// Unit tests for Reality URI parsing
// Validates: Requirements 2.4, 2.5, 5.3

func TestParseVlessReality_AllParams(t *testing.T) {
	// Complete Reality URI with all parameters present
	uri := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@server.example.com:443?security=reality&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=a1b2c3d4&fp=chrome&sni=www.microsoft.com&type=tcp&flow=xtls-rprx-vision#reality-server"

	link, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI failed: %v", err)
	}

	if link.Protocol != "vless" {
		t.Errorf("protocol: got %q, want %q", link.Protocol, "vless")
	}
	if link.Address != "server.example.com" {
		t.Errorf("address: got %q, want %q", link.Address, "server.example.com")
	}
	if link.Port != 443 {
		t.Errorf("port: got %d, want %d", link.Port, 443)
	}
	if link.UUID != "b831381d-6324-4d53-ad4f-8cda48b30811" {
		t.Errorf("uuid: got %q, want %q", link.UUID, "b831381d-6324-4d53-ad4f-8cda48b30811")
	}
	if link.Security != "reality" {
		t.Errorf("security: got %q, want %q", link.Security, "reality")
	}
	if link.TLS != true {
		t.Error("tls: got false, want true (reality implies TLS)")
	}
	if link.RealityPublicKey != "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc" {
		t.Errorf("RealityPublicKey: got %q, want %q", link.RealityPublicKey, "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc")
	}
	if link.RealityShortID != "a1b2c3d4" {
		t.Errorf("RealityShortID: got %q, want %q", link.RealityShortID, "a1b2c3d4")
	}
	if link.Fingerprint != "chrome" {
		t.Errorf("Fingerprint: got %q, want %q", link.Fingerprint, "chrome")
	}
	if link.SNI != "www.microsoft.com" {
		t.Errorf("sni: got %q, want %q", link.SNI, "www.microsoft.com")
	}
	if link.Network != "tcp" {
		t.Errorf("network: got %q, want %q", link.Network, "tcp")
	}
	if link.Flow != "xtls-rprx-vision" {
		t.Errorf("flow: got %q, want %q", link.Flow, "xtls-rprx-vision")
	}
	if link.Remark != "reality-server" {
		t.Errorf("remark: got %q, want %q", link.Remark, "reality-server")
	}
}

func TestParseVlessReality_MissingSID(t *testing.T) {
	// Reality URI without sid parameter — should parse without error, RealityShortID empty
	uri := "vless://b831381d-6324-4d53-ad4f-8cda48b30811@server.example.com:443?security=reality&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&fp=firefox&sni=www.google.com&type=tcp#no-sid"

	link, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI failed: %v", err)
	}

	if link.Security != "reality" {
		t.Errorf("security: got %q, want %q", link.Security, "reality")
	}
	if link.RealityPublicKey != "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc" {
		t.Errorf("RealityPublicKey: got %q, want %q", link.RealityPublicKey, "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc")
	}
	if link.RealityShortID != "" {
		t.Errorf("RealityShortID: got %q, want empty string", link.RealityShortID)
	}
	if link.Fingerprint != "firefox" {
		t.Errorf("Fingerprint: got %q, want %q", link.Fingerprint, "firefox")
	}
	if link.TLS != true {
		t.Error("tls: got false, want true (reality implies TLS)")
	}
}

func TestParseVless_NonReality_EmptyRealityFields(t *testing.T) {
	// Standard VLESS TLS URI without Reality params — Reality fields should be empty
	uri := "vless://uuid-1234@example.com:443?type=ws&security=tls&sni=example.com&path=/vless#standard-tls"

	link, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI failed: %v", err)
	}

	if link.Protocol != "vless" {
		t.Errorf("protocol: got %q, want %q", link.Protocol, "vless")
	}
	if link.Security != "tls" {
		t.Errorf("security: got %q, want %q", link.Security, "tls")
	}
	if link.RealityPublicKey != "" {
		t.Errorf("RealityPublicKey: got %q, want empty string", link.RealityPublicKey)
	}
	if link.RealityShortID != "" {
		t.Errorf("RealityShortID: got %q, want empty string", link.RealityShortID)
	}
	if link.Fingerprint != "" {
		t.Errorf("Fingerprint: got %q, want empty string", link.Fingerprint)
	}
}

// Feature: reality-support, Property 1: Reality parameter round-trip preservation
//
// For any valid VLESS Reality URI containing `pbk`, `sid`, and `fp` parameters,
// parsing the URI into a Link struct SHALL produce `RealityPublicKey`, `RealityShortID`,
// and `Fingerprint` values identical to the original URI query parameter values.
//
// **Validates: Requirements 2.1, 2.2, 2.3, 2.6**

func TestProperty_RealityParameterRoundTrip(t *testing.T) {
	// Generator for valid hex strings (used for short IDs)
	hexGen := rapid.StringMatching(`[0-9a-f]{2,16}`)

	// Generator for base64url-safe strings (used for public keys)
	// Real x25519 public keys are 32 bytes base64-encoded, but we test with arbitrary safe strings
	pbkGen := rapid.StringMatching(`[A-Za-z0-9_-]{10,44}`)

	// Generator for UTLS fingerprint values
	fpValues := []string{"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}
	fpGen := rapid.SampledFrom(fpValues)

	// Generator for valid hostnames
	hostGen := rapid.StringMatching(`[a-z][a-z0-9]{2,10}\.(com|net|org|io)`)

	// Generator for valid ports
	portGen := rapid.IntRange(1, 65535)

	// Generator for UUIDs
	uuidGen := rapid.StringMatching(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	// Generator for SNI values (reuse host generator)
	sniGen := hostGen

	// Generator for network types
	networkGen := rapid.SampledFrom([]string{"tcp", "ws", "grpc", "h2"})

	rapid.Check(t, func(t *rapid.T) {
		// Generate random Reality parameters
		pbk := pbkGen.Draw(t, "pbk")
		sid := hexGen.Draw(t, "sid")
		fp := fpGen.Draw(t, "fp")
		host := hostGen.Draw(t, "host")
		port := portGen.Draw(t, "port")
		uuid := uuidGen.Draw(t, "uuid")
		sni := sniGen.Draw(t, "sni")
		network := networkGen.Draw(t, "network")

		// Build a valid VLESS Reality URI
		params := url.Values{}
		params.Set("security", "reality")
		params.Set("pbk", pbk)
		params.Set("sid", sid)
		params.Set("fp", fp)
		params.Set("sni", sni)
		params.Set("type", network)

		uri := fmt.Sprintf("vless://%s@%s:%d?%s#reality-test",
			uuid, host, port, params.Encode())

		// Parse the URI
		link, err := ParseURI(uri)
		if err != nil {
			t.Fatalf("ParseURI failed for valid Reality URI: %v\nURI: %s", err, uri)
		}

		// Verify round-trip preservation of Reality parameters
		if link.RealityPublicKey != pbk {
			t.Fatalf("RealityPublicKey mismatch:\n  got:  %q\n  want: %q\n  URI: %s", link.RealityPublicKey, pbk, uri)
		}
		if link.RealityShortID != sid {
			t.Fatalf("RealityShortID mismatch:\n  got:  %q\n  want: %q\n  URI: %s", link.RealityShortID, sid, uri)
		}
		if link.Fingerprint != fp {
			t.Fatalf("Fingerprint mismatch:\n  got:  %q\n  want: %q\n  URI: %s", link.Fingerprint, fp, uri)
		}
	})
}


// Unit test for legacy JSON deserialization (backward compatibility)
// Validates: Requirements 5.2

func TestLegacyJSONDeserialization_NoRealityFields(t *testing.T) {
	// Simulate a legacy saved profile JSON that has no Reality fields
	legacyJSON := `{
		"remark": "legacy-server",
		"protocol": "vless",
		"address": "example.com",
		"port": 443,
		"uuid": "some-uuid",
		"security": "tls",
		"tls": true,
		"sni": "example.com",
		"network": "tcp"
	}`

	var link Link
	err := json.Unmarshal([]byte(legacyJSON), &link)
	if err != nil {
		t.Fatalf("json.Unmarshal failed on legacy JSON: %v", err)
	}

	// Verify Reality fields are empty
	if link.RealityPublicKey != "" {
		t.Errorf("RealityPublicKey: got %q, want empty string", link.RealityPublicKey)
	}
	if link.RealityShortID != "" {
		t.Errorf("RealityShortID: got %q, want empty string", link.RealityShortID)
	}
	if link.Fingerprint != "" {
		t.Errorf("Fingerprint: got %q, want empty string", link.Fingerprint)
	}

	// Verify other fields deserialized correctly
	if link.Protocol != "vless" {
		t.Errorf("Protocol: got %q, want %q", link.Protocol, "vless")
	}
	if link.Address != "example.com" {
		t.Errorf("Address: got %q, want %q", link.Address, "example.com")
	}
	if link.Port != 443 {
		t.Errorf("Port: got %d, want %d", link.Port, 443)
	}
	if link.Remark != "legacy-server" {
		t.Errorf("Remark: got %q, want %q", link.Remark, "legacy-server")
	}
	if link.UUID != "some-uuid" {
		t.Errorf("UUID: got %q, want %q", link.UUID, "some-uuid")
	}
	if link.Security != "tls" {
		t.Errorf("Security: got %q, want %q", link.Security, "tls")
	}
	if link.TLS != true {
		t.Error("TLS: got false, want true")
	}
	if link.SNI != "example.com" {
		t.Errorf("SNI: got %q, want %q", link.SNI, "example.com")
	}
	if link.Network != "tcp" {
		t.Errorf("Network: got %q, want %q", link.Network, "tcp")
	}
}
