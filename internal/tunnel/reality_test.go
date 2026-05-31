package tunnel

import (
	"testing"

	"github.com/liberoute/bypath/internal/profile"
	"pgregory.net/rapid"
)

// Feature: reality-support, Property 3: UTLS fingerprint inclusion
//
// For any Link with a non-empty `Fingerprint` field, the generated sing-box
// config SHALL contain `tls.utls.enabled == true` and `tls.utls.fingerprint`
// matching the Link's `Fingerprint` value.
//
// **Validates: Requirements 3.3**

func TestProperty_UTLSFingerprintInclusion(t *testing.T) {
	// Generator for valid hostnames
	hostGen := rapid.StringMatching(`[a-z][a-z0-9]{2,10}\.(com|net|org|io)`)

	// Generator for valid ports
	portGen := rapid.IntRange(1, 65535)

	// Generator for UUIDs
	uuidGen := rapid.StringMatching(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	// Generator for non-empty fingerprint values (the property requires non-empty)
	fpGen := rapid.SampledFrom([]string{"chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"})

	// Generator for security type (Reality or standard TLS — both should produce UTLS)
	securityGen := rapid.SampledFrom([]string{"reality", "tls"})

	// Generator for base64url-safe strings (Reality public keys)
	pbkGen := rapid.StringMatching(`[A-Za-z0-9_-]{10,44}`)

	// Generator for optional short IDs (hex strings)
	sidGen := rapid.OneOf(
		rapid.Just(""),
		rapid.StringMatching(`[0-9a-f]{2,16}`),
	)

	// Generator for optional SNI values
	sniGen := rapid.OneOf(
		rapid.Just(""),
		hostGen,
	)

	tmpDir := t.TempDir()

	rapid.Check(t, func(t *rapid.T) {
		// Generate a random Link with non-empty Fingerprint (can be Reality or standard TLS)
		fp := fpGen.Draw(t, "fingerprint")
		security := securityGen.Draw(t, "security")
		address := hostGen.Draw(t, "address")
		port := portGen.Draw(t, "port")
		uuid := uuidGen.Draw(t, "uuid")
		sni := sniGen.Draw(t, "sni")

		link := &profile.Link{
			Protocol:    "vless",
			Address:     address,
			Port:        port,
			UUID:        uuid,
			Security:    security,
			TLS:         true,
			SNI:         sni,
			Fingerprint: fp,
		}

		// For Reality links, add a public key (required for valid Reality config)
		if security == "reality" {
			link.RealityPublicKey = pbkGen.Draw(t, "pbk")
			link.RealityShortID = sidGen.Draw(t, "sid")
		}

		// Create a ConfigGenerator and generate outbounds
		cg := NewConfigGenerator(tmpDir)
		outbounds := cg.singboxOutbounds(link)

		// Find the proxy outbound (first one)
		if len(outbounds) < 1 {
			t.Fatal("expected at least 1 outbound")
		}
		proxy := outbounds[0]

		// Verify TLS object exists
		tlsRaw, hasTLS := proxy["tls"]
		if !hasTLS {
			t.Fatal("expected tls object in outbound, but none found")
		}
		tls, ok := tlsRaw.(map[string]interface{})
		if !ok {
			t.Fatalf("tls is not a map, got %T", tlsRaw)
		}

		// Property: tls must contain utls sub-object
		utlsRaw, hasUTLS := tls["utls"]
		if !hasUTLS {
			t.Fatalf("expected tls.utls object for fingerprint %q, but none found", fp)
		}
		utls, ok := utlsRaw.(map[string]interface{})
		if !ok {
			t.Fatalf("tls.utls is not a map, got %T", utlsRaw)
		}

		// Property: utls.enabled must be true
		if utls["enabled"] != true {
			t.Fatalf("utls.enabled: got %v, want true", utls["enabled"])
		}

		// Property: utls.fingerprint must match the Link's Fingerprint value
		if utls["fingerprint"] != fp {
			t.Fatalf("utls.fingerprint: got %v, want %q", utls["fingerprint"], fp)
		}
	})
}

// Feature: reality-support, Property 4: Non-Reality TLS backward compatibility
//
// For any Link with `TLS == true` and `Security != "reality"`, the generated
// sing-box config SHALL contain `tls.insecure == true` and SHALL NOT contain
// a `reality` sub-object.
//
// **Validates: Requirements 5.1**

func TestProperty_NonRealityTLSBackwardCompatibility(t *testing.T) {
	// Generator for valid hostnames
	hostGen := rapid.StringMatching(`[a-z][a-z0-9]{2,10}\.(com|net|org|io)`)

	// Generator for valid ports
	portGen := rapid.IntRange(1, 65535)

	// Generator for UUIDs
	uuidGen := rapid.StringMatching(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	// Generator for non-Reality security values (standard TLS)
	securityGen := rapid.SampledFrom([]string{"tls", "none", "", "auto"})

	// Generator for optional SNI values
	sniGen := rapid.OneOf(
		rapid.Just(""),
		hostGen,
	)

	// Generator for optional fingerprint values
	fpGen := rapid.OneOf(
		rapid.Just(""),
		rapid.SampledFrom([]string{"chrome", "firefox", "safari", "ios", "android", "edge", "random"}),
	)

	// Generator for optional network types
	networkGen := rapid.SampledFrom([]string{"", "tcp", "ws", "grpc"})

	tmpDir := t.TempDir()

	rapid.Check(t, func(t *rapid.T) {
		// Generate a random VLESS Link with TLS=true and Security != "reality"
		security := securityGen.Draw(t, "security")
		address := hostGen.Draw(t, "address")
		port := portGen.Draw(t, "port")
		uuid := uuidGen.Draw(t, "uuid")
		sni := sniGen.Draw(t, "sni")
		fp := fpGen.Draw(t, "fp")
		network := networkGen.Draw(t, "network")

		link := &profile.Link{
			Protocol:    "vless",
			Address:     address,
			Port:        port,
			UUID:        uuid,
			Security:    security,
			TLS:         true,
			SNI:         sni,
			Network:     network,
			Fingerprint: fp,
		}

		// Create a ConfigGenerator and generate outbounds
		cg := NewConfigGenerator(tmpDir)
		outbounds := cg.singboxOutbounds(link)

		// Find the proxy outbound (first one)
		if len(outbounds) < 1 {
			t.Fatal("expected at least 1 outbound")
		}
		proxy := outbounds[0]

		// Verify TLS object exists
		tlsRaw, hasTLS := proxy["tls"]
		if !hasTLS {
			t.Fatal("expected tls object in outbound, but none found")
		}
		tls, ok := tlsRaw.(map[string]interface{})
		if !ok {
			t.Fatalf("tls is not a map, got %T", tlsRaw)
		}

		// Property: tls.insecure must be true for non-Reality TLS
		insecureVal, hasInsecure := tls["insecure"]
		if !hasInsecure {
			t.Fatal("expected tls.insecure to be present for non-Reality TLS link")
		}
		if insecureVal != true {
			t.Fatalf("tls.insecure: got %v, want true", insecureVal)
		}

		// Property: tls SHALL NOT contain a "reality" sub-object
		if _, hasReality := tls["reality"]; hasReality {
			t.Fatalf("tls contains 'reality' key, which is forbidden for non-Reality TLS links (security=%q)", security)
		}
	})
}

// Feature: reality-support, Property 2: Reality config structure validity
//
// For any Link with `Security == "reality"` and non-empty `RealityPublicKey`,
// the generated sing-box config SHALL contain a `tls` object with
// `reality.enabled == true`, `reality.public_key` matching the Link's
// `RealityPublicKey`, and SHALL NOT contain `insecure`.
//
// **Validates: Requirements 3.1, 3.4, 3.5**

func TestProperty_RealityConfigStructureValidity(t *testing.T) {
	// Generator for base64url-safe strings (Reality public keys)
	pbkGen := rapid.StringMatching(`[A-Za-z0-9_-]{10,44}`)

	// Generator for valid hostnames
	hostGen := rapid.StringMatching(`[a-z][a-z0-9]{2,10}\.(com|net|org|io)`)

	// Generator for valid ports
	portGen := rapid.IntRange(1, 65535)

	// Generator for UUIDs
	uuidGen := rapid.StringMatching(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	// Generator for optional short IDs (hex strings)
	sidGen := rapid.OneOf(
		rapid.Just(""),
		rapid.StringMatching(`[0-9a-f]{2,16}`),
	)

	// Generator for optional SNI values
	sniGen := rapid.OneOf(
		rapid.Just(""),
		hostGen,
	)

	// Generator for optional fingerprint values
	fpGen := rapid.OneOf(
		rapid.Just(""),
		rapid.SampledFrom([]string{"chrome", "firefox", "safari", "ios", "android", "edge", "random"}),
	)

	tmpDir := t.TempDir()

	rapid.Check(t, func(t *rapid.T) {
		// Generate a random Link with Security="reality" and non-empty RealityPublicKey
		pbk := pbkGen.Draw(t, "pbk")
		address := hostGen.Draw(t, "address")
		port := portGen.Draw(t, "port")
		uuid := uuidGen.Draw(t, "uuid")
		sid := sidGen.Draw(t, "sid")
		sni := sniGen.Draw(t, "sni")
		fp := fpGen.Draw(t, "fp")

		link := &profile.Link{
			Protocol:         "vless",
			Address:          address,
			Port:             port,
			UUID:             uuid,
			Security:         "reality",
			TLS:              true,
			SNI:              sni,
			RealityPublicKey: pbk,
			RealityShortID:   sid,
			Fingerprint:      fp,
		}

		// Create a ConfigGenerator and generate outbounds
		cg := NewConfigGenerator(tmpDir)
		outbounds := cg.singboxOutbounds(link)

		// Find the proxy outbound (first one)
		if len(outbounds) < 1 {
			t.Fatal("expected at least 1 outbound")
		}
		proxy := outbounds[0]

		// Verify TLS object exists
		tlsRaw, hasTLS := proxy["tls"]
		if !hasTLS {
			t.Fatal("expected tls object in outbound, but none found")
		}
		tls, ok := tlsRaw.(map[string]interface{})
		if !ok {
			t.Fatalf("tls is not a map, got %T", tlsRaw)
		}

		// Property: tls.enabled must be true
		if tls["enabled"] != true {
			t.Fatalf("tls.enabled: got %v, want true", tls["enabled"])
		}

		// Property: tls.server_name must match SNI (when SNI is non-empty)
		if sni != "" {
			if tls["server_name"] != sni {
				t.Fatalf("tls.server_name: got %v, want %q", tls["server_name"], sni)
			}
		}

		// Property: tls must contain reality sub-object
		realityRaw, hasReality := tls["reality"]
		if !hasReality {
			t.Fatal("expected tls.reality object, but none found")
		}
		reality, ok := realityRaw.(map[string]interface{})
		if !ok {
			t.Fatalf("tls.reality is not a map, got %T", realityRaw)
		}

		// Property: reality.enabled must be true
		if reality["enabled"] != true {
			t.Fatalf("reality.enabled: got %v, want true", reality["enabled"])
		}

		// Property: reality.public_key must match the Link's RealityPublicKey
		if reality["public_key"] != pbk {
			t.Fatalf("reality.public_key: got %v, want %q", reality["public_key"], pbk)
		}

		// Property: tls SHALL NOT contain "insecure"
		if _, hasInsecure := tls["insecure"]; hasInsecure {
			t.Fatalf("tls contains 'insecure' key, which is forbidden for Reality links (value: %v)", tls["insecure"])
		}
	})
}
