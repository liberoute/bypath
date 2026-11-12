package config

import (
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path"
	"strings"

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
	Update      UpdateConfig      `yaml:"update,omitempty"`
	Tests       TestsConfig       `yaml:"tests,omitempty"`
}

// TestsConfig carries the host capability flags and limits for relay/latency
// and speed testing. It is deliberately not writable from the authenticated
// panel: isolation_verified is a lab-certified property of the host, not a
// user preference.
type TestsConfig struct {
	// IsolationVerified is set only after spike S0.1 has been replicated on
	// this host class. While false, isolated results are Inconclusive.
	IsolationVerified bool `yaml:"isolation_verified"`
	// Parallel bounds concurrent isolated instances (default 2, hard cap 3).
	Parallel int `yaml:"parallel,omitempty"`
	// SpeedPerLinkMB caps one throughput measurement (default 10, hard max 100).
	SpeedPerLinkMB int `yaml:"speed_per_link_mb,omitempty"`
	// SpeedPerBatchMB caps a whole batch (default 40, hard max 300).
	SpeedPerBatchMB int `yaml:"speed_per_batch_mb,omitempty"`
	// MonthlyBudgetMB refuses a run whose worst case exceeds what is left of
	// the monthly allowance. Zero means no monthly cap.
	MonthlyBudgetMB int `yaml:"monthly_budget_mb,omitempty"`
}

// UpdateConfig points at a release feed that publishes the same JSON shape as
// the upstream GitHub releases API (tag_name, body, assets[].digest). Left
// empty, self-update stays disabled instead of offering another project's
// release line.
type UpdateConfig struct {
	URL string `yaml:"url,omitempty"`
}

type ServerConfig struct {
	Listen    string    `yaml:"listen"`
	APIPort   int       `yaml:"api_port"`
	DNSPort   int       `yaml:"dns_port"`
	SOCKSPort int       `yaml:"socks_port"`
	APIToken  string    `yaml:"api_token,omitempty"`
	Web       WebConfig `yaml:"web,omitempty"`
	// SOCKSListen is the bind address of the local SOCKS/mixed proxy.
	// Loopback by default: the proxy has no authentication, so a LAN bind is an
	// explicit opt-in (socks_allow_lan) and must be paired with a firewall rule.
	SOCKSListen   string `yaml:"socks_listen,omitempty"`
	SOCKSAllowLAN bool   `yaml:"socks_allow_lan,omitempty"`
	// SOCKSAllowCIDRs is the explicit source allowlist for a LAN proxy bind.
	// It exists for hosts that own more than one private network: the derived
	// single-CIDR path would otherwise have to guess which one is trusted.
	SOCKSAllowCIDRs []string `yaml:"socks_trusted_cidrs,omitempty"`
	// SOCKSUsername/SOCKSPassword are parsed for compatibility but rejected by
	// validation: the engine's own probe, DNS and subscription clients reach the
	// listener without credentials, and an authenticated LAN listener would be
	// silently unusable (or, for SSH links, silently unauthenticated).
	SOCKSUsername string `yaml:"socks_username,omitempty"`
	SOCKSPassword string `yaml:"socks_password,omitempty"`
	// SSHHostKey selects host-key verification for SSH links: "accept-new"
	// (default, pins the key on first use), "strict" (rejects unknown hosts),
	// or "off" (explicitly unverified).
	SSHHostKey string `yaml:"ssh_host_key,omitempty"`
}

// WebConfig controls the browser management panel. It is disabled by default
// and binds to loopback; serving it on a LAN address requires allow_lan, so
// exposing the panel is always a deliberate choice.
type WebConfig struct {
	Enabled        bool     `yaml:"enabled"`
	Listen         string   `yaml:"listen,omitempty"`
	Port           int      `yaml:"port,omitempty"`
	AllowLAN       bool     `yaml:"allow_lan,omitempty"`
	AllowedOrigins []string `yaml:"allowed_origins,omitempty"` // e.g. https://bypath.example.net
	// Socket optionally serves the same panel on a Unix-domain socket. The
	// gateway runs inside a network namespace whose loopback a host reverse
	// proxy cannot reach; a socket in the shared filesystem lets that proxy
	// terminate TLS without publishing a plain-HTTP listener on the LAN.
	Socket string `yaml:"socket,omitempty"`
}

type GatewayConfig struct {
	Enabled     bool            `yaml:"enabled"`
	Interface   string          `yaml:"interface"`
	DNSUpstream []string        `yaml:"dns_upstream"`
	NativeTUN   bool            `yaml:"native_tun"`
	LocalDNS    []LocalDNSEntry `yaml:"local_dns,omitempty"`
	// DNSMode selects the DNS leak policy. "strict" (default) resolves through
	// the tunnel and rejects a query instead of falling back to direct DNS;
	// "local" explicitly permits direct upstream queries.
	DNSMode string `yaml:"dns_mode,omitempty"`
}

// LocalDNSEntry routes specific domain suffixes to a local DNS server (e.g. home DNS for .home TLD).
type LocalDNSEntry struct {
	Server  string   `yaml:"server"`            // IP of the local DNS server (e.g. "192.0.2.53")
	Domains []string `yaml:"domains,omitempty"` // domain suffixes without leading dot (e.g. ["home", "lan"])
}

type FallbackConfig struct {
	Enabled bool   `yaml:"enabled"`
	Timeout string `yaml:"timeout"` // per-engine startup timeout, e.g. "10s"
	// EndpointTimeout bounds one link attempt, including engine readiness and
	// connectivity probes, before the next group link is tried.
	EndpointTimeout string `yaml:"endpoint_timeout,omitempty"`
	// TotalTimeout bounds the entire startup fallback chain across links so an
	// unreachable group cannot hold the gateway in CONNECTING indefinitely.
	TotalTimeout string   `yaml:"total_timeout,omitempty"`
	Order        []string `yaml:"order"` // e.g. ["sing-box", "xray"]
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
	// even if their resolved IP falls within a whitelisted country (e.g. geoip:cc).
	// These rules are evaluated before any geoip/geosite direct rules.
	ForceProxyDomains []string `yaml:"force_proxy_domains,omitempty"`
	UpdateInterval    string   `yaml:"update_interval"`
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
	ExternalOutbounds map[string]string `yaml:"external_outbounds,omitempty"` // name → URL e.g. "office-proxy": "socks5://proxy.example:1080"
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
	SNI     string `yaml:"sni,omitempty"`  // fake SNI to present (e.g. "example.com")
	Mode    string `yaml:"mode,omitempty"` // "replace" or "fragment"
}

// Load reads and parses the YAML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, err
	}
	if err := cfg.NormalizeAndValidate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Parse unmarshals a configuration document and applies the same defaults as
// Load, without touching the filesystem. Validation is deliberately separate so
// a caller merging host-local fields (backup restore) can validate the merged
// document instead of rejecting a portable one.
func Parse(data []byte) (*Config, error) {
	cfg := &Config{}
	// Set defaults that need to be true before unmarshaling
	// (YAML will override if explicitly set to false)
	cfg.Gateway.NativeTUN = true

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	applyDefaults(cfg)
	return cfg, nil
}

// NormalizeAndValidate applies the checks Load performs on a parsed document.
func (cfg *Config) NormalizeAndValidate() error {
	normalizeLocalDNS(cfg)
	if err := ValidateServer(cfg.Server); err != nil {
		return err
	}
	validateBypassDomains(cfg)
	if err := validateCountryCodes(cfg); err != nil {
		return err
	}
	if err := validateRouting(cfg); err != nil {
		return err
	}
	if err := validateUpdateURL(cfg.Update.URL); err != nil {
		return err
	}
	warnLegacyRouting(cfg)
	return nil
}

// validateUpdateURL keeps the release feed on TLS: the digest that authorizes
// replacing the binary is served by the same feed, so plaintext transport would
// make tampering with both trivial.
func validateUpdateURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("update.url: invalid release feed URL %q", raw)
	}
	if strings.EqualFold(u.Scheme, "https") {
		return nil
	}
	if strings.EqualFold(u.Scheme, "http") && isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("update.url: release feed must use https (got %q)", u.Scheme)
}

// Denial outbound spellings. A deny rule must drop the traffic: it may never
// fall through to a proxy or, worse, to a direct egress.
var denyOutbounds = map[string]bool{"deny": true, "block": true, "reject": true}

// IsDenyOutbound reports whether an outbound name means "drop this traffic".
func IsDenyOutbound(outbound string) bool {
	return denyOutbounds[strings.ToLower(strings.TrimSpace(outbound))]
}

// validateRouting rejects rule documents the generators would silently ignore
// or mis-handle. The routing table decides which traffic leaves the tunnel, so
// an unrecognized matcher or outbound is a configuration error, not a warning:
// skipping a direct country rule turns it into proxy traffic (safe), but
// skipping a force-proxy rule could send traffic direct (a leak).
func validateRouting(cfg *Config) error {
	if err := validateExternalOutbounds(cfg.Routing.ExternalOutbounds); err != nil {
		return err
	}
	if len(cfg.Routing.Rules) == 0 {
		return nil
	}
	defaults := 0
	for i, rule := range cfg.Routing.Rules {
		match := strings.TrimSpace(rule.Match)
		outbound := strings.TrimSpace(rule.Outbound)
		if match == "" {
			return fmt.Errorf("routing.rules[%d]: match is empty", i)
		}
		if outbound == "" {
			return fmt.Errorf("routing.rules[%d]: outbound is empty", i)
		}
		if !knownOutbound(outbound, cfg.Routing.ExternalOutbounds) {
			return fmt.Errorf("routing.rules[%d]: outbound %q is not direct, proxy, a deny spelling, or an external_outbounds name", i, outbound)
		}
		if match == "default" {
			defaults++
			if defaults > 1 {
				return fmt.Errorf("routing.rules[%d]: duplicate default rule", i)
			}
			continue
		}
		typ, val, ok := strings.Cut(match, ":")
		if !ok || val == "" {
			return fmt.Errorf("routing.rules[%d]: match %q must be \"default\" or <type>:<value>", i, match)
		}
		switch typ {
		case "geoip", "geosite":
			if !validGeoName(val) {
				return fmt.Errorf("routing.rules[%d]: %q is not a valid country code or geosite tag", i, val)
			}
		case "domain", "domain_suffix":
			if err := validDomainMatcher(typ, val); err != nil {
				return fmt.Errorf("routing.rules[%d]: %w", i, err)
			}
		case "ip_cidr":
			if _, _, err := net.ParseCIDR(val); err != nil {
				return fmt.Errorf("routing.rules[%d]: ip_cidr %q is not a CIDR", i, val)
			}
		default:
			return fmt.Errorf("routing.rules[%d]: unsupported matcher type %q (want geoip, geosite, domain, domain_suffix, ip_cidr or default)", i, typ)
		}
	}
	return nil
}

func knownOutbound(outbound string, external map[string]string) bool {
	switch strings.ToLower(strings.TrimSpace(outbound)) {
	case "direct", "proxy", "deny", "block", "reject":
		return true
	}
	_, ok := external[outbound]
	return ok
}

func validDomainMatcher(typ, val string) error {
	if strings.ContainsAny(val, " \t\r\n\x00") {
		return fmt.Errorf("%s matcher %q contains whitespace or NUL", typ, val)
	}
	if typ == "domain" && strings.HasPrefix(val, ".") {
		return fmt.Errorf("domain matcher %q must not start with a dot; use domain_suffix", val)
	}
	return nil
}

// validateExternalOutbounds enforces the URL shape the generators understand so
// a typo cannot silently drop an outbound the routing table references.
func validateExternalOutbounds(m map[string]string) error {
	for name, raw := range m {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("routing.external_outbounds: empty name")
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "direct", "proxy", "block", "deny", "reject":
			return fmt.Errorf("routing.external_outbounds: %q collides with a built-in outbound", name)
		}
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("routing.external_outbounds[%q]: invalid URL: %v", name, err)
		}
		switch u.Scheme {
		case "socks5", "socks5h", "socks4", "socks", "http", "https":
		default:
			return fmt.Errorf("routing.external_outbounds[%q]: unsupported scheme %q", name, u.Scheme)
		}
		host, portStr, err := net.SplitHostPort(u.Host)
		if err != nil || host == "" {
			return fmt.Errorf("routing.external_outbounds[%q]: URL must contain host:port", name)
		}
		port, err := net.LookupPort("tcp", portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("routing.external_outbounds[%q]: invalid port %q", name, portStr)
		}
	}
	return nil
}

// normalizeLocalDNS trims suffixes once so the resolve rule and the direct
// route rule generated from them match the same strings.
func normalizeLocalDNS(cfg *Config) {
	entries := cfg.Gateway.LocalDNS
	out := entries[:0]
	for _, entry := range entries {
		entry.Server = strings.TrimSpace(entry.Server)
		domains := entry.Domains[:0]
		for _, d := range entry.Domains {
			if d = strings.TrimSpace(d); d != "" {
				domains = append(domains, d)
			}
		}
		entry.Domains = domains
		if entry.Server == "" || len(entry.Domains) == 0 {
			continue
		}
		out = append(out, entry)
	}
	cfg.Gateway.LocalDNS = out
}

// validGeoName reports whether a value can be embedded in a rule-set file
// name. Country codes and geosite tags are single path components; separators,
// volume syntax and parent-directory names are refused because the value is
// joined into a path under the geo directory and the daemon runs as root.
func validGeoName(v string) bool {
	if v == "" || len(v) > 64 || v == "." || v == ".." || strings.HasPrefix(v, ".") {
		return false
	}
	return !strings.ContainsAny(v, `/\:`+"\x00")
}

// validateCountryCodes makes every value used to build a
// geoip-<code>.srs/geosite-<code>.srs path a single safe component. A backup
// can set these fields; without this check it could choose an arbitrary path.
func validateCountryCodes(cfg *Config) error {
	check := func(field string, values []string) error {
		for _, v := range values {
			if !validGeoName(v) {
				return fmt.Errorf("%s: %q is not a valid country code or geosite tag", field, v)
			}
		}
		return nil
	}
	if err := check("whitelist.countries", cfg.Whitelist.Countries); err != nil {
		return err
	}
	if err := check("whitelist.geosite_countries", cfg.Whitelist.GeositeCountries); err != nil {
		return err
	}
	for i, rule := range cfg.Routing.Rules {
		for _, prefix := range []string{"geoip:", "geosite:"} {
			if strings.HasPrefix(rule.Match, prefix) {
				value := strings.TrimPrefix(rule.Match, prefix)
				if !validGeoName(value) {
					return fmt.Errorf("routing.rules[%d].match: %q is not a valid country code or geosite tag", i, value)
				}
			}
		}
	}
	return nil
}

// warnLegacyRouting prints a deprecation notice when whitelist-style config is
// used, and an explicit notice when a routing.rules block silently overrides it:
// in that case the whitelist fields have no effect, which is easy to miss.
func warnLegacyRouting(cfg *Config) {
	legacy := len(cfg.Whitelist.Countries) > 0 || len(cfg.Whitelist.BypassDomains) > 0 ||
		len(cfg.Whitelist.ForceProxyDomains) > 0 || len(cfg.Whitelist.GeositeCountries) > 0
	if !legacy {
		return
	}
	if len(cfg.Routing.Rules) > 0 {
		log.Println("⚠️  [config] whitelist.* is ignored because routing.rules is present — move countries/bypass/force_proxy rules into routing.rules")
		return
	}
	log.Println("⚠️  [config] whitelist is deprecated — migrate to routing.rules for per-outbound control")
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
		// The management API is privileged and holds the tunnel stack; it is
		// reachable from the LAN only when the operator sets listen explicitly.
		cfg.Server.Listen = "127.0.0.1"
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
	if cfg.Server.SOCKSListen == "" {
		cfg.Server.SOCKSListen = "127.0.0.1"
	}
	for i, raw := range cfg.Server.SOCKSAllowCIDRs {
		cfg.Server.SOCKSAllowCIDRs[i] = strings.TrimSpace(raw)
	}
	if cfg.Server.SSHHostKey == "" {
		cfg.Server.SSHHostKey = SSHHostKeyAcceptNew
	}
	if cfg.Server.Web.Listen == "" {
		cfg.Server.Web.Listen = "127.0.0.1"
	}
	if cfg.Server.Web.Port == 0 {
		cfg.Server.Web.Port = cfg.Server.APIPort + 1
	}
	if cfg.Engines.Directory == "" {
		cfg.Engines.Directory = paths.Get().EngineDir
	}
	if !cfg.Engines.Fallback.Enabled && len(cfg.Engines.Fallback.Order) == 0 {
		cfg.Engines.Fallback.Enabled = true
		cfg.Engines.Fallback.Timeout = "10s"
		cfg.Engines.Fallback.Order = []string{"sing-box", "xray"}
	}
	if cfg.Engines.Fallback.EndpointTimeout == "" {
		cfg.Engines.Fallback.EndpointTimeout = "90s"
	}
	if cfg.Engines.Fallback.TotalTimeout == "" {
		cfg.Engines.Fallback.TotalTimeout = "5m"
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
		// No default source: a rule-set endpoint is an operator choice, and the
		// shipped routing policy does not need one. `geo update` explains what to
		// set when a geosite rule is configured without it.
	}
	if cfg.Whitelist.UpdateInterval == "" {
		cfg.Whitelist.UpdateInterval = "24h"
	}
	if cfg.HealthCheck.Interval == "" {
		cfg.HealthCheck.Interval = "60s"
	}
	if cfg.HealthCheck.URL == "" {
		// Neutral HTTPS liveness endpoint; no IP-echo or provider API.
		cfg.HealthCheck.URL = "https://cp.cloudflare.com"
	}
}

// SSH host-key verification policies accepted by server.ssh_host_key.
const (
	SSHHostKeyAcceptNew = "accept-new"
	SSHHostKeyStrict    = "strict"
	SSHHostKeyOff       = "off"
)

// ValidateServer enforces the management-plane exposure policy. The SOCKS
// proxy carries no authentication, so a non-loopback bind requires the explicit
// socks_allow_lan opt-in and must be firewalled. A listener address must be an
// IP literal: a hostname would make the bind depend on resolver state at
// startup, and the proxy's own clients always reach it through 127.0.0.1.
func ValidateServer(s ServerConfig) error {
	if err := ValidateProxyPort(s); err != nil {
		return err
	}
	if s.Listen != "" && !IsLoopbackHost(s.Listen) && strings.TrimSpace(s.APIToken) == "" {
		return fmt.Errorf("non-loopback management API requires server.api_token")
	}
	listen := strings.TrimSpace(s.SOCKSListen)
	if listen == "" {
		listen = "127.0.0.1"
	}
	ip := net.ParseIP(strings.Trim(listen, "[]"))
	if ip == nil {
		return fmt.Errorf("server.socks_listen %q must be an IP address such as 127.0.0.1", listen)
	}
	if ip.To4() == nil {
		return fmt.Errorf("server.socks_listen must be IPv4; IPv6 LAN guarding is not supported")
	}
	for _, raw := range s.SOCKSAllowCIDRs {
		if _, _, err := parseTrustedCIDR(raw); err != nil {
			return fmt.Errorf("server.socks_trusted_cidrs entry %q %v", strings.TrimSpace(raw), err)
		}
	}
	if !ip.Equal(net.IPv4(127, 0, 0, 1)) {
		if !s.SOCKSAllowLAN {
			return fmt.Errorf("server.socks_listen requires explicit socks_allow_lan")
		}
		if !ip.IsUnspecified() {
			if !ip.IsPrivate() {
				return fmt.Errorf("server.socks_listen must be a trusted private IPv4 interface address")
			}
			ifaces, err := net.Interfaces()
			if err != nil {
				return err
			}
			owned := false
			for _, iface := range ifaces {
				addrs, _ := iface.Addrs()
				for _, addr := range addrs {
					local, _, _ := net.ParseCIDR(addr.String())
					if local != nil && local.Equal(ip) {
						owned = true
					}
				}
			}
			if !owned {
				return fmt.Errorf("server.socks_listen must belong to a local interface")
			}
		}
	}
	if s.SOCKSUsername != "" || s.SOCKSPassword != "" {
		return fmt.Errorf("server.socks_username/server.socks_password are not supported: the gateway's own probe, DNS and subscription clients connect without credentials; leave the proxy on loopback or firewall a LAN listener")
	}
	switch s.SSHHostKey {
	case "", SSHHostKeyAcceptNew, SSHHostKeyStrict, SSHHostKeyOff:
	default:
		return fmt.Errorf("server.ssh_host_key %q must be one of accept-new, strict, off", s.SSHHostKey)
	}
	return nil
}

// SOCKSListenAddress returns the effective bind address for the local proxy,
// normalized so a bracketed IPv6 wildcard reaches ssh -D and sing-box in the
// form they expect.
func (s ServerConfig) SOCKSListenAddress() string {
	if listen := strings.TrimSpace(s.SOCKSListen); listen != "" {
		if ip := net.ParseIP(strings.Trim(listen, "[]")); ip != nil {
			return ip.String()
		}
		return listen
	}
	return "127.0.0.1"
}

// SOCKSRequiresAuth reports whether the generated proxy listener must demand
// a username and password.
func (s ServerConfig) SOCKSRequiresAuth() bool {
	return s.SOCKSUsername != "" && s.SOCKSPassword != ""
}

// ValidateWeb enforces the panel exposure policy. A non-loopback bind is only
// accepted when allow_lan is set, and reverse-proxy origins must be absolute
// http(s) URLs.
func ValidateWeb(w WebConfig) error {
	if w.Port < 1 || w.Port > 65535 {
		return fmt.Errorf("web.port %d is out of range", w.Port)
	}
	listen := strings.TrimSpace(w.Listen)
	if listen == "" {
		listen = "127.0.0.1"
	}
	if !isLoopbackHost(listen) && !w.AllowLAN {
		return fmt.Errorf("web.listen %q is not loopback; set server.web.allow_lan: true to expose the panel on the LAN", listen)
	}
	for _, origin := range w.AllowedOrigins {
		u, err := url.Parse(strings.TrimSpace(origin))
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("web.allowed_origins entry %q is not an absolute http(s) origin", origin)
		}
		if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("web.allowed_origins entry %q must not contain a path, query or fragment", origin)
		}
	}
	if sock := strings.TrimSpace(w.Socket); sock != "" {
		// Unix socket paths use forward slashes on every platform bypath
		// supports; path (not filepath) keeps validation identical in tests.
		if !path.IsAbs(sock) {
			return fmt.Errorf("web.socket %q must be an absolute path", sock)
		}
		if path.Clean(sock) != sock {
			return fmt.Errorf("web.socket %q must be a clean path", sock)
		}
		if info, err := os.Stat(sock); err == nil && info.IsDir() {
			return fmt.Errorf("web.socket %q is a directory", sock)
		}
	}
	return nil
}

// IsLoopbackHost reports whether a bind address stays on this machine.
func IsLoopbackHost(host string) bool { return isLoopbackHost(host) }

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
