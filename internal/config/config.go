package config

import (
	"fmt"
	"log"
	"os"

	"github.com/liberoute/bypath/internal/paths"
	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure.
type Config struct {
	Server      ServerConfig      `yaml:"server"`
	Gateway     GatewayConfig     `yaml:"gateway"`
	Engines     EnginesConfig     `yaml:"engines"`
	Whitelist   WhitelistConfig   `yaml:"whitelist"`
	Isolation   IsolationConfig   `yaml:"isolation"`
	Profiles    ProfilesConfig    `yaml:"profiles"`
	Routing     RoutingConfig     `yaml:"routing,omitempty"`
	Chains      []ChainConfig     `yaml:"chains"`
	HealthCheck HealthCheckConfig `yaml:"health_check,omitempty"`
	SNISpoof    SNISpoofConfig    `yaml:"sni_spoof,omitempty"`
}

type ServerConfig struct {
	Listen    string `yaml:"listen"`
	APIPort   int    `yaml:"api_port"`
	DNSPort   int    `yaml:"dns_port"`
	SOCKSPort int    `yaml:"socks_port"`
	APIToken  string `yaml:"api_token,omitempty"`
}

type GatewayConfig struct {
	Enabled     bool           `yaml:"enabled"`
	Interface   string         `yaml:"interface"`
	DNSUpstream []string       `yaml:"dns_upstream"`
	NativeTUN   bool           `yaml:"native_tun"`
	LocalDNS    []LocalDNSEntry `yaml:"local_dns,omitempty"`
}

// LocalDNSEntry routes specific domain suffixes to a local DNS server (e.g. home DNS for .home TLD).
type LocalDNSEntry struct {
	Server  string   `yaml:"server"`            // IP of the local DNS server (e.g. "192.168.1.1")
	Domains []string `yaml:"domains,omitempty"` // domain suffixes without leading dot (e.g. ["home", "lan"])
}

type FallbackConfig struct {
	Enabled bool     `yaml:"enabled"`
	Timeout string   `yaml:"timeout"` // duration string, e.g. "10s"
	Order   []string `yaml:"order"`   // e.g. ["sing-box", "xray"]
}

type EnginesConfig struct {
	Directory       string         `yaml:"directory"`
	PreferSystem    bool           `yaml:"prefer_system"`
	PreferredEngine string         `yaml:"preferred,omitempty"` // "sing-box" or "xray" (empty = auto)
	Fallback        FallbackConfig `yaml:"fallback,omitempty"`
}

type WhitelistConfig struct {
	Countries        []string `yaml:"countries"`
	GeositeCountries []string `yaml:"geosite_countries,omitempty"`
	GeositeURL       string   `yaml:"geosite_url,omitempty"`
	BypassDomains    []string `yaml:"bypass_domains,omitempty"`
	// ForceProxyDomains are domains that must always go through the tunnel,
	// even if their resolved IP falls within a whitelisted country (e.g. geoip:ir).
	// These rules are evaluated before any geoip/geosite direct rules.
	ForceProxyDomains []string `yaml:"force_proxy_domains,omitempty"`
	UpdateInterval   string   `yaml:"update_interval"`
}

// RoutingRule maps a traffic matcher to a named outbound.
// Match syntax: "geoip:<cc>", "geosite:<tag>", "domain:<exact>", "domain_suffix:<suffix>", "ip_cidr:<cidr>", "default"
// Outbound: "direct", "proxy", or any name defined in RoutingConfig.ExternalOutbounds
type RoutingRule struct {
	Match    string `yaml:"match"`
	Outbound string `yaml:"outbound"`
}

// RoutingConfig is the new rule-based routing system.
// When Rules is non-empty it overrides the legacy whitelist config entirely.
// ExternalOutbounds defines proxy servers not managed by bypath profiles.
type RoutingConfig struct {
	Rules             []RoutingRule     `yaml:"rules,omitempty"`
	ExternalOutbounds map[string]string `yaml:"external_outbounds,omitempty"` // name → URL e.g. "lray-proxy": "socks5://172.20.100.12:8088"
}

type IsolationConfig struct {
	Enabled bool `yaml:"enabled"`
}

type HealthCheckConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Interval string `yaml:"interval"`
	URL      string `yaml:"url"`
}

type ProfilesConfig struct {
	ActiveGroup string `yaml:"active_group"`
	Directory   string `yaml:"directory"`
}

type ChainConfig struct {
	Name      string      `yaml:"name"`
	Hops      []HopConfig `yaml:"hops"`
	AutoStart bool        `yaml:"auto_start,omitempty"`
}

type HopConfig struct {
	Profile string `yaml:"profile"`
	Engine  string `yaml:"engine,omitempty"`  // force engine (empty = auto-detect)
	Isolate bool   `yaml:"isolate,omitempty"` // run in network namespace
}

type SNISpoofConfig struct {
	Enabled bool   `yaml:"enabled"`
	SNI     string `yaml:"sni,omitempty"`     // fake SNI to use (e.g. "digikala.com")
	Mode    string `yaml:"mode,omitempty"`    // "replace" or "fragment"
}

// Load reads and parses the YAML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := &Config{}
	// Set defaults that need to be true before unmarshaling
	// (YAML will override if explicitly set to false)
	cfg.Gateway.NativeTUN = true

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	applyDefaults(cfg)
	validateBypassDomains(cfg)
	warnLegacyRouting(cfg)
	return cfg, nil
}

// warnLegacyRouting prints a deprecation notice when whitelist-style config is used
// without a routing.rules block. Silence it by migrating to routing.rules.
func warnLegacyRouting(cfg *Config) {
	if len(cfg.Routing.Rules) > 0 {
		return // new system active
	}
	if len(cfg.Whitelist.Countries) > 0 || len(cfg.Whitelist.BypassDomains) > 0 ||
		len(cfg.Whitelist.ForceProxyDomains) > 0 || len(cfg.Whitelist.GeositeCountries) > 0 {
		log.Println("⚠️  [config] whitelist is deprecated — migrate to routing.rules for per-outbound control")
	}
}

// validateBypassDomains filters out empty strings from BypassDomains and logs a warning for each removed entry.
func validateBypassDomains(cfg *Config) {
	filtered := make([]string, 0, len(cfg.Whitelist.BypassDomains))
	for _, d := range cfg.Whitelist.BypassDomains {
		if d == "" {
			log.Printf("⚠️  bypass_domains: removed empty entry")
			continue
		}
		filtered = append(filtered, d)
	}
	cfg.Whitelist.BypassDomains = filtered
}

func applyDefaults(cfg *Config) {
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = "0.0.0.0"
	}
	if cfg.Server.APIPort == 0 {
		cfg.Server.APIPort = 8080
	}
	if cfg.Server.DNSPort == 0 {
		cfg.Server.DNSPort = 53
	}
	if cfg.Server.SOCKSPort == 0 {
		cfg.Server.SOCKSPort = 2801
	}
	if cfg.Engines.Directory == "" {
		cfg.Engines.Directory = paths.Get().EngineDir
	}
	if !cfg.Engines.Fallback.Enabled && len(cfg.Engines.Fallback.Order) == 0 {
		cfg.Engines.Fallback.Enabled = true
		cfg.Engines.Fallback.Timeout = "10s"
		cfg.Engines.Fallback.Order = []string{"sing-box", "xray"}
	}
	if cfg.Profiles.Directory == "" {
		cfg.Profiles.Directory = paths.Get().ProfileDir
	}
	if cfg.Profiles.ActiveGroup == "" {
		cfg.Profiles.ActiveGroup = "default"
	}
	if len(cfg.Gateway.DNSUpstream) == 0 {
		cfg.Gateway.DNSUpstream = []string{"1.1.1.1", "8.8.8.8"}
	}
	if len(cfg.Whitelist.BypassDomains) == 0 {
		// No hardcoded defaults — user configures bypass_domains in config.yaml
	}
	if cfg.Whitelist.GeositeURL == "" {
		cfg.Whitelist.GeositeURL = "https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite-{country}.srs"
	}
	if cfg.Whitelist.UpdateInterval == "" {
		cfg.Whitelist.UpdateInterval = "24h"
	}
	if cfg.HealthCheck.Interval == "" {
		cfg.HealthCheck.Interval = "60s"
	}
	if cfg.HealthCheck.URL == "" {
		cfg.HealthCheck.URL = "http://ip-api.com/json"
	}
}
