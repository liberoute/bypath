package config

import (
	"os"
	"path/filepath"
	"testing"
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
