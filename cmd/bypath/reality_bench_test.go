package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/tunnel"
	"pgregory.net/rapid"
)

// Feature: reality-support, Property 5: Config generator and bench builder equivalence
//
// For any Link with `Security == "reality"`, the TLS object produced by the
// Config_Generator and the TLS object produced by the Bench_Builder SHALL be
// structurally equivalent (same keys and values).
//
// **Validates: Requirements 4.3**

func TestProperty_ConfigGeneratorBenchBuilderEquivalence(t *testing.T) {
	// Generator for valid hostnames (no commas — avoids SNI splitting edge cases)
	hostGen := rapid.StringMatching(`[a-z][a-z0-9]{2,10}\.(com|net|org|io)`)

	// Generator for valid ports
	portGen := rapid.IntRange(1, 65535)

	// Generator for UUIDs
	uuidGen := rapid.StringMatching(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

	// Generator for base64url-safe strings (Reality public keys)
	pbkGen := rapid.StringMatching(`[A-Za-z0-9_-]{10,44}`)

	// Generator for optional short IDs (hex strings)
	sidGen := rapid.OneOf(
		rapid.Just(""),
		rapid.StringMatching(`[0-9a-f]{2,16}`),
	)

	// Generator for optional SNI values (no commas)
	sniGen := rapid.OneOf(
		rapid.Just(""),
		hostGen,
	)

	// Generator for optional fingerprint values
	fpGen := rapid.OneOf(
		rapid.Just(""),
		rapid.SampledFrom([]string{"chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"}),
	)

	tmpDir := t.TempDir()

	rapid.Check(t, func(t *rapid.T) {
		// Generate a random Reality Link
		address := hostGen.Draw(t, "address")
		port := portGen.Draw(t, "port")
		uuid := uuidGen.Draw(t, "uuid")
		pbk := pbkGen.Draw(t, "pbk")
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

		// --- Bench Builder output ---
		benchJSON := buildOutbound(link)

		// Parse the bench builder JSON to extract the TLS object
		var benchOutbound map[string]interface{}
		if err := json.Unmarshal([]byte(benchJSON), &benchOutbound); err != nil {
			t.Fatalf("failed to parse buildOutbound JSON: %v\nraw: %s", err, benchJSON)
		}

		benchTLSRaw, hasBenchTLS := benchOutbound["tls"]
		if !hasBenchTLS {
			t.Fatal("bench builder output missing 'tls' key for Reality link")
		}
		benchTLS, ok := benchTLSRaw.(map[string]interface{})
		if !ok {
			t.Fatalf("bench tls is not a map, got %T", benchTLSRaw)
		}

		// --- Config Generator output ---
		cg := tunnel.NewConfigGenerator(tmpDir)
		eng := &engine.Engine{Name: "sing-box"}

		configFile, err := cg.Generate(eng, link)
		if err != nil {
			t.Fatalf("ConfigGenerator.Generate failed: %v", err)
		}

		data, err := os.ReadFile(configFile)
		if err != nil {
			t.Fatalf("failed to read config file: %v", err)
		}

		var cfg map[string]interface{}
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatalf("failed to parse config JSON: %v", err)
		}

		outboundsRaw, ok := cfg["outbounds"]
		if !ok {
			t.Fatal("config generator output missing 'outbounds' key")
		}
		outbounds, ok := outboundsRaw.([]interface{})
		if !ok || len(outbounds) < 1 {
			t.Fatal("config generator outbounds is empty or not an array")
		}

		proxyOutbound, ok := outbounds[0].(map[string]interface{})
		if !ok {
			t.Fatal("first outbound is not a map")
		}

		cgTLSRaw, hasCGTLS := proxyOutbound["tls"]
		if !hasCGTLS {
			t.Fatal("config generator output missing 'tls' key for Reality link")
		}
		cgTLS, ok := cgTLSRaw.(map[string]interface{})
		if !ok {
			t.Fatalf("config generator tls is not a map, got %T", cgTLSRaw)
		}

		// --- Compare TLS objects structurally ---
		// Marshal both to canonical JSON and compare
		benchTLSJSON, err := json.Marshal(benchTLS)
		if err != nil {
			t.Fatalf("failed to marshal bench TLS: %v", err)
		}

		cgTLSJSON, err := json.Marshal(cgTLS)
		if err != nil {
			t.Fatalf("failed to marshal config generator TLS: %v", err)
		}

		if string(benchTLSJSON) != string(cgTLSJSON) {
			t.Fatalf("TLS objects differ!\n  Bench Builder: %s\n  Config Generator: %s", benchTLSJSON, cgTLSJSON)
		}
	})
}
