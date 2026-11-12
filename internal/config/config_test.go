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

	// The management API and the proxy stay on loopback unless the operator
	// opts in explicitly.
	if cfg.Server.Listen != "127.0.0.1" {
		t.Errorf("expected listen 127.0.0.1, got %s", cfg.Server.Listen)
	}
	if cfg.Server.SOCKSListen != "127.0.0.1" {
		t.Errorf("expected socks_listen 127.0.0.1, got %s", cfg.Server.SOCKSListen)
	}
	if cfg.Server.SSHHostKey != SSHHostKeyAcceptNew {
		t.Errorf("expected ssh_host_key accept-new, got %s", cfg.Server.SSHHostKey)
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

	expected := []string{}
	if len(cfg.Whitelist.BypassDomains) != len(expected) {
		t.Fatalf("expected %d bypass domains (no hardcoded defaults), got %d", len(expected), len(cfg.Whitelist.BypassDomains))
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

func TestNativeTUNDefaultTrue(t *testing.T) {
	// When native_tun is not specified, it should default to true
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "test.yaml")
	os.WriteFile(cfgFile, []byte("server:\n  api_port: 8080\n"), 0644)

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !cfg.Gateway.NativeTUN {
		t.Error("expected NativeTUN to default to true when not specified")
	}
}

func TestNativeTUNExplicitFalse(t *testing.T) {
	// When native_tun is explicitly set to false, it should be false
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "test.yaml")
	content := `
gateway:
  enabled: true
  native_tun: false
`
	os.WriteFile(cfgFile, []byte(content), 0644)

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Gateway.NativeTUN {
		t.Error("expected NativeTUN to be false when explicitly set to false")
	}
}

func TestNativeTUNExplicitTrue(t *testing.T) {
	// When native_tun is explicitly set to true, it should be true
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "test.yaml")
	content := `
gateway:
  enabled: true
  native_tun: true
`
	os.WriteFile(cfgFile, []byte(content), 0644)

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !cfg.Gateway.NativeTUN {
		t.Error("expected NativeTUN to be true when explicitly set to true")
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

// Task 1.2: fallback config defaults and explicit values

func TestFallbackConfigDefaults(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "test.yaml")
	os.WriteFile(cfgFile, []byte("server:\n  api_port: 9090\n"), 0644)

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !cfg.Engines.Fallback.Enabled {
		t.Error("expected Fallback.Enabled to default to true")
	}
	if cfg.Engines.Fallback.Timeout != "10s" {
		t.Errorf("expected Fallback.Timeout \"10s\", got %q", cfg.Engines.Fallback.Timeout)
	}
	want := []string{"sing-box", "xray"}
	if len(cfg.Engines.Fallback.Order) != len(want) {
		t.Fatalf("expected Fallback.Order %v, got %v", want, cfg.Engines.Fallback.Order)
	}
	for i, e := range want {
		if cfg.Engines.Fallback.Order[i] != e {
			t.Errorf("Fallback.Order[%d]: expected %q, got %q", i, e, cfg.Engines.Fallback.Order[i])
		}
	}
	if cfg.Engines.Fallback.EndpointTimeout != "90s" {
		t.Errorf("expected Fallback.EndpointTimeout \"90s\", got %q", cfg.Engines.Fallback.EndpointTimeout)
	}
	if cfg.Engines.Fallback.TotalTimeout != "5m" {
		t.Errorf("expected Fallback.TotalTimeout \"5m\", got %q", cfg.Engines.Fallback.TotalTimeout)
	}
}

func TestFallbackConfigExplicitValues(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "test.yaml")
	content := `
engines:
  fallback:
    enabled: false
    timeout: "5s"
    endpoint_timeout: "20s"
    total_timeout: "45s"
    order:
      - "xray"
      - "sing-box"
`
	os.WriteFile(cfgFile, []byte(content), 0644)

	cfg, err := Load(cfgFile)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Engines.Fallback.Enabled {
		t.Error("expected Fallback.Enabled to be false when explicitly set")
	}
	if cfg.Engines.Fallback.Timeout != "5s" {
		t.Errorf("expected Fallback.Timeout \"5s\", got %q", cfg.Engines.Fallback.Timeout)
	}
	want := []string{"xray", "sing-box"}
	if len(cfg.Engines.Fallback.Order) != len(want) {
		t.Fatalf("expected Fallback.Order %v, got %v", want, cfg.Engines.Fallback.Order)
	}
	for i, e := range want {
		if cfg.Engines.Fallback.Order[i] != e {
			t.Errorf("Fallback.Order[%d]: expected %q, got %q", i, e, cfg.Engines.Fallback.Order[i])
		}
	}
	if cfg.Engines.Fallback.EndpointTimeout != "20s" {
		t.Errorf("expected Fallback.EndpointTimeout \"20s\", got %q", cfg.Engines.Fallback.EndpointTimeout)
	}
	if cfg.Engines.Fallback.TotalTimeout != "45s" {
		t.Errorf("expected Fallback.TotalTimeout \"45s\", got %q", cfg.Engines.Fallback.TotalTimeout)
	}
}

func TestLoadRejectsGeoPathTraversal(t *testing.T) {
	cases := []string{
		"whitelist:\n  geosite_countries: [\"../../etc\"]\n",
		"whitelist:\n  countries: [\"ir/../../root\"]\n",
		"routing:\n  rules:\n    - match: \"geoip:../x\"\n      outbound: direct\n",
	}
	for i, body := range cases {
		path := filepath.Join(t.TempDir(), "bad.yaml")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("case %d: Load accepted a path-like geo name", i)
		}
	}
}

func TestLoadAcceptsGeoRuleSetTags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ok.yaml")
	body := "whitelist:\n  geosite_countries: [ir, category-ads-all, geolocation-!cn]\n"
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load rejected valid geosite tags: %v", err)
	}
}

// TestValidateServerExposurePolicy covers the SOCKS bind policy: exact loopback
// or an explicit wildcard opt-in, and no credentials (the gateway's own probe,
// DNS and subscription clients connect without them).
func TestValidateServerExposurePolicy(t *testing.T) {
	base := ServerConfig{SOCKSListen: "127.0.0.1", SOCKSPort: 2801}
	if err := ValidateServer(base); err != nil {
		t.Fatalf("loopback bind was rejected: %v", err)
	}
	lan := base
	lan.SOCKSListen = "0.0.0.0"
	if err := ValidateServer(lan); err == nil {
		t.Fatal("LAN bind without socks_allow_lan was accepted")
	}
	lan.SOCKSAllowLAN = true
	if err := ValidateServer(lan); err != nil {
		t.Fatalf("explicit LAN bind was rejected: %v", err)
	}
	v6 := base
	v6.SOCKSListen = "[::]"
	v6.SOCKSAllowLAN = true
	if err := ValidateServer(v6); err == nil {
		t.Fatal("IPv6 wildcard accepted without IPv6 containment support")
	}
	nic := lan
	nic.SOCKSListen = "192.168.1.5"
	if err := ValidateServer(nic); err == nil {
		t.Fatal("unowned interface bind was accepted")
	}
	for _, listen := range []string{"proxy.example.com", "localhost", "::1", "127.0.0.2"} {
		c := base
		c.SOCKSListen = listen
		if err := ValidateServer(c); err == nil {
			t.Fatalf("%q was accepted; internal clients only reach 127.0.0.1", listen)
		}
	}
	auth := base
	auth.SOCKSUsername = "user"
	auth.SOCKSPassword = "pass"
	if err := ValidateServer(auth); err == nil {
		t.Fatal("SOCKS credentials were accepted even though internal clients cannot send them")
	}
	badKey := base
	badKey.SSHHostKey = "insecure"
	if err := ValidateServer(badKey); err == nil {
		t.Fatal("unknown ssh_host_key policy was accepted")
	}
}

// TestParseSeparatesDefaultsFromValidation proves a portable document can be
// parsed and merged with host-local fields before it is validated.
func TestParseSeparatesDefaultsFromValidation(t *testing.T) {
	cfg, err := Parse([]byte("server:\n  socks_listen: 0.0.0.0\n"))
	if err != nil {
		t.Fatalf("Parse rejected a document that needs merging: %v", err)
	}
	if cfg.Server.SOCKSPort != 2801 {
		t.Fatalf("defaults not applied: socks_port=%d", cfg.Server.SOCKSPort)
	}
	cfg.Server.SOCKSListen = "127.0.0.1"
	if err := cfg.NormalizeAndValidate(); err != nil {
		t.Fatalf("merged document rejected: %v", err)
	}
	if got := cfg.Server.SOCKSListenAddress(); got != "127.0.0.1" {
		t.Fatalf("listen address = %q", got)
	}
}

// TestLocalDNSDomainsAreNormalized proves the resolve rule and the direct route
// rule are generated from the same trimmed suffix list.
func TestLocalDNSDomainsAreNormalized(t *testing.T) {
	cfg, err := Parse([]byte("gateway:\n  local_dns:\n    - server: \" 192.0.2.53 \"\n      domains: [\" home \", \"\", \"lan\"]\n    - server: \"\"\n      domains: [ignored]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.NormalizeAndValidate(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Gateway.LocalDNS) != 1 {
		t.Fatalf("entries = %+v, want only the usable one", cfg.Gateway.LocalDNS)
	}
	entry := cfg.Gateway.LocalDNS[0]
	if entry.Server != "192.0.2.53" {
		t.Fatalf("server = %q", entry.Server)
	}
	if len(entry.Domains) != 2 || entry.Domains[0] != "home" || entry.Domains[1] != "lan" {
		t.Fatalf("domains = %v", entry.Domains)
	}
}

// TestLoadRejectsLANProxyWithoutOptIn proves a legacy config that exposed the
// proxy on every interface now fails closed with an actionable message.
func TestLoadRejectsLANProxyWithoutOptIn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lan.yaml")
	if err := os.WriteFile(path, []byte("server:\n  socks_listen: 0.0.0.0\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("LAN SOCKS bind loaded without socks_allow_lan")
	}
	if err := os.WriteFile(path, []byte("server:\n  socks_listen: 0.0.0.0\n  socks_allow_lan: true\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("opted-in LAN SOCKS bind was rejected: %v", err)
	}
	if cfg.Server.SOCKSListenAddress() != "0.0.0.0" {
		t.Fatalf("socks_listen = %q, want 0.0.0.0", cfg.Server.SOCKSListenAddress())
	}
}

func loadBody(t *testing.T, body string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestRoutingRuleValidation(t *testing.T) {
	bad := []string{
		"routing:\n  rules:\n    - match: \"asn:1234\"\n      outbound: direct\n",                                                 // unsupported matcher
		"routing:\n  rules:\n    - match: \"geoip:de\"\n      outbound: \"\"\n",                                                   // empty outbound
		"routing:\n  rules:\n    - match: \"geoip:de\"\n      outbound: office\n",                                                   // undefined outbound
		"routing:\n  rules:\n    - match: \"ip_cidr:10.0.0.0\"\n      outbound: direct\n",                                         // not a CIDR
		"routing:\n  rules:\n    - match: \"\"\n      outbound: direct\n",                                                         // empty matcher
		"routing:\n  rules:\n    - match: \"default\"\n      outbound: proxy\n    - match: \"default\"\n      outbound: direct\n", // duplicate default
		"routing:\n  rules:\n    - match: \"domain:.example.com\"\n      outbound: direct\n",                                      // dot form belongs to domain_suffix
		"routing:\n  external_outbounds:\n    office: \"wireguard://10.20.30.10:8088\"\n",                                         // unsupported scheme
		"routing:\n  external_outbounds:\n    office: \"socks5://10.20.30.10\"\n",                                                 // no port
		"routing:\n  external_outbounds:\n    proxy: \"socks5://10.20.30.10:8088\"\n",                                           // collides with builtin
	}
	for i, body := range bad {
		if _, err := loadBody(t, body); err == nil {
			t.Fatalf("case %d: invalid routing config was accepted:\n%s", i, body)
		}
	}

	good := `
routing:
  external_outbounds:
    office: "socks5://10.20.30.10:8088"
  rules:
    - match: "domain_suffix:de"
      outbound: direct
    - match: "geoip:de"
      outbound: direct
    - match: "domain_suffix:blocked.example"
      outbound: deny
    - match: "domain:ads.example"
      outbound: reject
    - match: "ip_cidr:203.0.113.0/24"
      outbound: office
    - match: "default"
      outbound: proxy
`
	cfg, err := loadBody(t, good)
	if err != nil {
		t.Fatalf("valid routing config rejected: %v", err)
	}
	if len(cfg.Routing.Rules) != 6 {
		t.Fatalf("rules = %d, want 6", len(cfg.Routing.Rules))
	}
	if !IsDenyOutbound("block") || !IsDenyOutbound("DENY") || IsDenyOutbound("direct") {
		t.Fatal("IsDenyOutbound does not recognize the deny spellings")
	}
}

// TestShippedDefaultConfigStartsNeutral guards the release default: a fresh
// installation must not ship a provider, a subscription, a selected connection,
// a geographic routing assumption or a LAN listener. The gateway stays off
// until the first-run wizard has verified a working connection.
func TestShippedDefaultConfigStartsNeutral(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "configs", "default.yaml"))
	if err != nil {
		t.Fatalf("shipped config does not load: %v", err)
	}
	if cfg.Gateway.Enabled {
		t.Error("shipped config enables the gateway before any connection exists")
	}
	if cfg.Gateway.Interface != "" {
		t.Errorf("shipped config pins gateway.interface = %q; it must auto-detect", cfg.Gateway.Interface)
	}
	if cfg.Server.SOCKSAllowLAN || cfg.Server.SOCKSListen != "127.0.0.1" {
		t.Errorf("shipped config exposes the proxy: listen=%q allow_lan=%v", cfg.Server.SOCKSListen, cfg.Server.SOCKSAllowLAN)
	}
	if len(cfg.Server.SOCKSAllowCIDRs) != 0 {
		t.Errorf("shipped config carries a trusted CIDR allow-list: %v", cfg.Server.SOCKSAllowCIDRs)
	}
	if cfg.Server.Web.Enabled {
		t.Error("shipped config enables the web panel")
	}
	if cfg.Server.APIToken != "" {
		t.Error("shipped config embeds an API token")
	}
	if len(cfg.Chains) != 0 {
		t.Errorf("shipped config defines chains: %+v", cfg.Chains)
	}
	if len(cfg.Routing.ExternalOutbounds) != 0 {
		t.Errorf("shipped config defines external outbounds: %v", cfg.Routing.ExternalOutbounds)
	}
	want := []RoutingRule{{Match: "default", Outbound: "proxy"}}
	if len(cfg.Routing.Rules) != len(want) || cfg.Routing.Rules[0] != want[0] {
		t.Fatalf("routing.rules = %+v, want exactly %+v", cfg.Routing.Rules, want)
	}
}

// TestUpdateFeedURLValidation keeps self-update pointed at a channel the build
// owner controls: https anywhere, http only for a loopback test feed.
func TestUpdateFeedURLValidation(t *testing.T) {
	accepted := []string{
		"",
		"https://releases.example.net/bypath/latest.json",
		"http://127.0.0.1:8089/release.json",
		"http://localhost:8089/release.json",
		"http://[::1]:8089/release.json",
	}
	for _, raw := range accepted {
		path := filepath.Join(t.TempDir(), "ok.yaml")
		body := "update:\n  url: \"" + raw + "\"\n"
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err != nil {
			t.Errorf("Load rejected update.url %q: %v", raw, err)
		}
	}

	rejected := []string{
		"http://releases.example.net/bypath/latest.json",
		"ftp://releases.example.net/bypath/latest.json",
		"releases.example.net/latest.json",
		"https://",
	}
	for _, raw := range rejected {
		path := filepath.Join(t.TempDir(), "bad.yaml")
		body := "update:\n  url: \"" + raw + "\"\n"
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("Load accepted update.url %q", raw)
		}
	}
}
