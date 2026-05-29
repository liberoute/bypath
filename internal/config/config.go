package config

import (
	"fmt"
	"os"

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
	APIToken  string `yaml:"api_token,omitempty"`
	HTTPProxy int    `yaml:"http_proxy_port,omitempty"` // Separate HTTP proxy port (0 = disabled, mixed inbound handles both)
}

type GatewayConfig struct {
	Enabled     bool     `yaml:"enabled"`
	Interface   string   `yaml:"interface"`
	DNSUpstream []string `yaml:"dns_upstream"`
}

type EnginesConfig struct {
	Directory       string `yaml:"directory"`
	PreferSystem    bool   `yaml:"prefer_system"`
	PreferredEngine string `yaml:"preferred,omitempty"` // "sing-box" or "xray" (empty = auto)
}

type WhitelistConfig struct {
	Countries      []string `yaml:"countries"`
	CustomFile     string   `yaml:"custom_file,omitempty"`
	UpdateInterval string   `yaml:"update_interval"`
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
	Name string      `yaml:"name"`
	Hops []HopConfig `yaml:"hops"`
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
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	applyDefaults(cfg)
	return cfg, nil
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
	if cfg.Engines.Directory == "" {
		cfg.Engines.Directory = "./engines"
	}
	if cfg.Profiles.Directory == "" {
		cfg.Profiles.Directory = "./data/profiles"
	}
	if cfg.Profiles.ActiveGroup == "" {
		cfg.Profiles.ActiveGroup = "default"
	}
	if len(cfg.Gateway.DNSUpstream) == 0 {
		cfg.Gateway.DNSUpstream = []string{"1.1.1.1", "8.8.8.8"}
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
