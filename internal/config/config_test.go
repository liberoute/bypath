package config

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
	"pgregory.net/rapid"
)

func TestLoadDefaults(t *testing.T) {
	// Create a minimal config file
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "test.yaml")
	os.WriteFile(cfgFile, []byte("server:\n  api_port: 9090\n"), 0644)

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Check defaults are applied
	if cfg.Server.Listen != "0.0.0.0" {
		t.Errorf("expected listen 0.0.0.0, got %s", cfg.Server.Listen)
	}
	if cfg.Server.APIPort != 9090 {
		t.Errorf("expected api_port 9090, got %d", cfg.Server.APIPort)
	}
	if cfg.Server.DNSPort != 53 {
		t.Errorf("expected dns_port 53, got %d", cfg.Server.DNSPort)
	}
	if cfg.Engines.Directory != "./engines" {
		t.Errorf("expected engines dir ./engines, got %s", cfg.Engines.Directory)
	}
	if cfg.Profiles.ActiveGroup != "default" {
		t.Errorf("expected active_group default, got %s", cfg.Profiles.ActiveGroup)
	}
	if len(cfg.Gateway.DNSUpstream) != 2 {
		t.Errorf("expected 2 dns upstreams, got %d", len(cfg.Gateway.DNSUpstream))
	}
}

func TestLoadFullConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "full.yaml")

	content := `
server:
  listen: "127.0.0.1"
  api_port: 3000
  dns_port: 5353

gateway:
  enabled: true
  interface: "eth0"
  dns_upstream:
    - "9.9.9.9"

engines:
  directory: "/opt/engines"
  prefer_system: false

whitelist:
  countries:
    - "ir"
    - "cn"
  custom_file: "/tmp/custom.txt"
  update_interval: "12h"

isolation:
  enabled: false

profiles:
  active_group: "work"
  directory: "/data/profiles"

chains:
  - name: "double"
    hops:
      - profile: "entry"
        engine: "xray"
        isolate: true
      - profile: "exit"
        engine: "sing-box"
`
	os.WriteFile(cfgFile, []byte(content), 0644)

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Server.Listen != "127.0.0.1" {
		t.Errorf("listen: got %s", cfg.Server.Listen)
	}
	if cfg.Server.APIPort != 3000 {
		t.Errorf("api_port: got %d", cfg.Server.APIPort)
	}
	if cfg.Gateway.Interface != "eth0" {
		t.Errorf("interface: got %s", cfg.Gateway.Interface)
	}
	if len(cfg.Whitelist.Countries) != 2 {
		t.Errorf("countries: got %d", len(cfg.Whitelist.Countries))
	}
	if cfg.Isolation.Enabled != false {
		t.Error("isolation should be false")
	}
	if len(cfg.Chains) != 1 {
		t.Fatalf("chains: got %d", len(cfg.Chains))
	}
	if len(cfg.Chains[0].Hops) != 2 {
		t.Errorf("hops: got %d", len(cfg.Chains[0].Hops))
	}
	if cfg.Chains[0].Hops[0].Engine != "xray" {
		t.Errorf("hop engine: got %s", cfg.Chains[0].Hops[0].Engine)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadInvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "bad.yaml")
	os.WriteFile(cfgFile, []byte("{{invalid yaml"), 0644)

	_, err := Load(cfgFile)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestBypassDomainsDefaultsApplied(t *testing.T) {
	// When bypass_domains is omitted, defaults should be applied
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "test.yaml")
	os.WriteFile(cfgFile, []byte("server:\n  api_port: 8080\n"), 0644)

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	expected := []string{"cloudflare.com", "ip-api.com", "ipinfo.io", "api.myip.com"}
	if len(cfg.Whitelist.BypassDomains) != len(expected) {
		t.Fatalf("expected %d bypass domains, got %d", len(expected), len(cfg.Whitelist.BypassDomains))
	}
	for i, d := range expected {
		if cfg.Whitelist.BypassDomains[i] != d {
			t.Errorf("bypass_domains[%d]: expected %q, got %q", i, d, cfg.Whitelist.BypassDomains[i])
		}
	}
}

func TestBypassDomainsExplicitPreserved(t *testing.T) {
	// When bypass_domains is explicitly set, it should be preserved (no defaults merged)
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "test.yaml")
	content := `
whitelist:
  bypass_domains:
    - "example.com"
    - "test.org"
`
	os.WriteFile(cfgFile, []byte(content), 0644)

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	expected := []string{"example.com", "test.org"}
	if len(cfg.Whitelist.BypassDomains) != len(expected) {
		t.Fatalf("expected %d bypass domains, got %d", len(expected), len(cfg.Whitelist.BypassDomains))
	}
	for i, d := range expected {
		if cfg.Whitelist.BypassDomains[i] != d {
			t.Errorf("bypass_domains[%d]: expected %q, got %q", i, d, cfg.Whitelist.BypassDomains[i])
		}
	}
}

func TestBypassDomainsEmptyStringsFiltered(t *testing.T) {
	// Empty strings in bypass_domains should be filtered out
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "test.yaml")
	content := `
whitelist:
  bypass_domains:
    - "cloudflare.com"
    - ""
    - "ipinfo.io"
    - ""
`
	os.WriteFile(cfgFile, []byte(content), 0644)

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	expected := []string{"cloudflare.com", "ipinfo.io"}
	if len(cfg.Whitelist.BypassDomains) != len(expected) {
		t.Fatalf("expected %d bypass domains after filtering, got %d: %v", len(expected), len(cfg.Whitelist.BypassDomains), cfg.Whitelist.BypassDomains)
	}
	for i, d := range expected {
		if cfg.Whitelist.BypassDomains[i] != d {
			t.Errorf("bypass_domains[%d]: expected %q, got %q", i, d, cfg.Whitelist.BypassDomains[i])
		}
	}
}


// Feature: vpn-detection-bypass, Property 5: Config serialization round-trip preserves bypass_domains
// **Validates: Requirements 4.1, 4.2**
func TestProperty5_ConfigSerializationRoundTripPreservesBypassDomains(t *testing.T) {
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

	tmpDir := t.TempDir()

	rapid.Check(t, func(t *rapid.T) {
		bypassDomains := domainsGen.Draw(t, "bypassDomains")

		// Create a Config with the generated bypass domains
		cfg := &Config{
			Whitelist: WhitelistConfig{
				BypassDomains: bypassDomains,
			},
		}

		// Serialize to YAML
		data, err := yaml.Marshal(cfg)
		if err != nil {
			t.Fatalf("yaml.Marshal failed: %v", err)
		}

		// Write to temp file and load via config.Load()
		cfgFile := filepath.Join(tmpDir, "roundtrip.yaml")
		if err := os.WriteFile(cfgFile, data, 0644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}

		loaded, err := Load(cfgFile)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}

		// Verify bypass_domains match exactly (same order, same content)
		if len(loaded.Whitelist.BypassDomains) != len(bypassDomains) {
			t.Fatalf("bypass_domains length mismatch: expected %d, got %d\nexpected: %v\ngot: %v",
				len(bypassDomains), len(loaded.Whitelist.BypassDomains), bypassDomains, loaded.Whitelist.BypassDomains)
		}
		for i, expected := range bypassDomains {
			if loaded.Whitelist.BypassDomains[i] != expected {
				t.Fatalf("bypass_domains[%d] mismatch: expected %q, got %q",
					i, expected, loaded.Whitelist.BypassDomains[i])
			}
		}
	})
}
