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
	Chains      []ChainConfig     `yaml:"chains"`
	HealthCheck HealthCheckConfig `yaml:"health_check,omitempty"`
	DHCP        DHCPConfig        `yaml:"dhcp,omitempty"`
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
	Enabled     bool     `yaml:"enabled"`
	Interface   string   `yaml:"interface"`
	DNSUpstream []string `yaml:"dns_upstream"`
	NativeTUN   bool     `yaml:"native_tun"`
}

type EnginesConfig struct {
	Directory       string `yaml:"directory"`
	PreferSystem    bool   `yaml:"prefer_system"`
	PreferredEngine string `yaml:"preferred,omitempty"` // "sing-box" or "xray" (empty = auto)
}

type WhitelistConfig struct {
	Countries        []string `yaml:"countries"`
	GeositeCountries []string `yaml:"geosite_countries,omitempty"`
	GeositeURL       string   `yaml:"geosite_url,omitempty"`
	BypassDomains    []string `yaml:"bypass_domains,omitempty"`
	CustomFile       string   `yaml:"custom_file,omitempty"`
	UpdateInterval   string   `yaml:"update_interval"`
}

type IsolationConfig struct {
	Enabled bool `yaml:"enabled"`
}

type HealthCheckConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Interval string `yaml:"interval"`
	URL      string `yaml:"url"`
}

type DHCPConfig struct {
	Enabled    bool     `yaml:"enabled"`
	RangeStart string   `yaml:"range_start"`
	RangeEnd   string   `yaml:"range_end"`
	Gateway    string   `yaml:"gateway"`
	DNS        []string `yaml:"dns"`
	LeaseTime  string   `yaml:"lease_time"`
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
	return cfg, nil
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
		cfg.Whitelist.BypassDomains = []string{
			"cloudflare.com",
			"ip-api.com",
			"ipinfo.io",
			"api.myip.com",
		}
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
