package tunnel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
)

// ConfigGenerator creates engine-specific configuration files from a Link.
type ConfigGenerator struct {
	tempDir            string
	WhitelistCountries []string // country codes (e.g. "ir") to route direct via geoip
	GeositeCountries   []string // country codes (e.g. "ir") to route direct via geosite (domain-based)
	BypassDomains      []string // domains to route direct (bypass tunnel)
	ForceProxyDomains  []string // domains to always route through tunnel (override geoip/geosite direct rules)
	DNSUpstream        []string // upstream DNS servers to use in tunnel config
	SOCKSPort          int      // SOCKS5/mixed listen port (default: 2801)
	SNISpoof           string   // fake SNI to replace real one (empty = disabled)
	GatewayMode        bool     // when true, generate TUN inbound + DNS server config
	DNSPort            int      // DNS listen port for gateway mode (default: 53)
}

// NewConfigGenerator creates a new config generator.
func NewConfigGenerator(tempDir string) *ConfigGenerator {
	os.MkdirAll(tempDir, 0755)
	return &ConfigGenerator{tempDir: tempDir}
}

// Generate creates a config file for the given engine and link.
func (cg *ConfigGenerator) Generate(eng *engine.Engine, link *profile.Link) (string, error) {
	switch eng.Name {
	case "sing-box":
		return cg.generateSingBox(link)
	case "xray":
		return cg.generateXray(link)
	case "wireguard-go":
		return cg.generateWireGuard(link)
	case "openvpn":
		return cg.generateOpenVPN(link)
	default:
		return "", fmt.Errorf("unsupported engine: %s", eng.Name)
	}
}

// GenerateChainConfig creates a sing-box config with detour-linked outbounds for a multi-hop chain.
// Each link becomes an outbound with a unique tag (chain-<name>-hop-<i>), and each outbound's
// detour field points to the next hop. The last hop has no detour (it connects directly).
// Returns the path to the generated JSON config file.
func (cg *ConfigGenerator) GenerateChainConfig(chainName string, links []*profile.Link) (string, error) {
	if len(links) == 0 {
		return "", fmt.Errorf("chain %q: no links provided", chainName)
	}

	// Task 2.2: Generate outbounds with unique tags and detour linkage
	outbounds := cg.buildChainOutbounds(chainName, links)

	// Task 2.3: Generate single mixed inbound routing to first hop's tag
	// Use port 10800 for chain inbound to avoid conflict with main gateway (2801)
	chainPort := 10800
	inbounds := []map[string]interface{}{
		{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      "0.0.0.0",
			"listen_port": chainPort,
		},
	}

	// Route: direct all inbound traffic to the last hop's outbound (exit node)
	lastHopTag := fmt.Sprintf("chain-%s-hop-%d", chainName, len(links)-1)
	route := map[string]interface{}{
		"final":                   lastHopTag,
		"auto_detect_interface":   true,
		"default_domain_resolver": "dns-direct",
	}

	// DNS: simple direct DNS for chain resolution (sing-box 1.12+ format)
	dns := map[string]interface{}{
		"servers": []map[string]interface{}{
			{
				"tag":         "dns-direct",
				"type":        "udp",
				"server":      "1.1.1.1",
				"server_port": 53,
			},
		},
		"final": "dns-direct",
	}

	cfg := map[string]interface{}{
		"log": map[string]interface{}{
			"level": "info",
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     route,
		"dns":       dns,
	}

	return cg.writeJSON(fmt.Sprintf("chain-%s", sanitizeName(chainName)), cfg)
}

// buildChainOutbounds generates the outbound slice for a multi-hop chain.
// In sing-box, "detour" means "connect through this outbound as transport".
// For a chain: client → hop0 → hop1 → ... → hopN → internet
// The inbound routes to the LAST hop (exit node), and each hop's detour
// points to the PREVIOUS hop (its transport). The first hop has no detour
// (it connects directly to its server).
func (cg *ConfigGenerator) buildChainOutbounds(chainName string, links []*profile.Link) []map[string]interface{} {
	outbounds := make([]map[string]interface{}, 0, len(links)+1)

	for i, link := range links {
		outbound := cg.BuildSingboxOutbound(link)

		// Assign unique tag: chain-<chainName>-hop-<index>
		tag := fmt.Sprintf("chain-%s-hop-%d", chainName, i)
		outbound["tag"] = tag

		// Add detour to previous hop (except for the first hop which connects directly)
		if i > 0 {
			prevTag := fmt.Sprintf("chain-%s-hop-%d", chainName, i-1)
			outbound["detour"] = prevTag

			// Remove flow field when using detour — xtls-rprx-vision requires direct TCP
			// and is incompatible with sing-box's detour mechanism
			delete(outbound, "flow")
		}

		outbounds = append(outbounds, outbound)
	}

	// Append the direct outbound (needed for route rules)
	outbounds = append(outbounds, map[string]interface{}{
		"type": "direct",
		"tag":  "direct",
	})

	return outbounds
}

// BuildSingboxOutbound builds a single sing-box outbound map for a link.
// This extracts the protocol-specific outbound generation logic so it can be
// reused by both singboxOutbounds (single-hop) and buildChainOutbounds (multi-hop).
// The returned map does NOT include "tag" or "detour" — callers set those.
func (cg *ConfigGenerator) BuildSingboxOutbound(link *profile.Link) map[string]interface{} {
	// Fix comma-separated SNI/Host — take first entry
	sni := link.SNI
	host := link.Host
	if strings.Contains(sni, ",") {
		sni = strings.TrimSpace(strings.Split(sni, ",")[0])
	}
	if strings.Contains(host, ",") {
		host = strings.TrimSpace(strings.Split(host, ",")[0])
	}
	// Apply SNI spoof if configured
	if cg.SNISpoof != "" && sni != "" {
		sni = cg.SNISpoof
	}

	var outbound map[string]interface{}

	switch link.Protocol {
	case "vmess":
		outbound = map[string]interface{}{
			"type":        "vmess",
			"server":      link.Address,
			"server_port": link.Port,
			"uuid":        link.UUID,
			"alter_id":    link.AlterId,
			"security":    link.Security,
		}
		if link.Network != "" && link.Network != "tcp" {
			transport := map[string]interface{}{"type": link.Network}
			if link.Path != "" {
				transport["path"] = link.Path
			}
			if host != "" {
				transport["headers"] = map[string]interface{}{
					"Host": host,
				}
			}
			outbound["transport"] = transport
		}
		if link.TLS {
			tls := map[string]interface{}{"enabled": true}
			if sni != "" {
				tls["server_name"] = sni
			}
			outbound["tls"] = tls
		}

	case "vless":
		outbound = map[string]interface{}{
			"type":        "vless",
			"server":      link.Address,
			"server_port": link.Port,
			"uuid":        link.UUID,
		}
		if link.Flow != "" {
			outbound["flow"] = link.Flow
		}
		if link.Network != "" && link.Network != "tcp" {
			transport := map[string]interface{}{"type": link.Network}
			if link.Path != "" {
				transport["path"] = link.Path
			}
			if host != "" {
				transport["headers"] = map[string]interface{}{
					"Host": host,
				}
			}
			outbound["transport"] = transport
		}
		if link.Security == "reality" {
			tls := map[string]interface{}{"enabled": true}
			if sni != "" {
				tls["server_name"] = sni
			}
			reality := map[string]interface{}{"enabled": true}
			if link.RealityPublicKey != "" {
				reality["public_key"] = link.RealityPublicKey
			}
			if link.RealityShortID != "" {
				reality["short_id"] = link.RealityShortID
			}
			tls["reality"] = reality
			if link.Fingerprint != "" {
				tls["utls"] = map[string]interface{}{
					"enabled":     true,
					"fingerprint": link.Fingerprint,
				}
			}
			outbound["tls"] = tls
		} else if link.TLS {
			tls := map[string]interface{}{"enabled": true, "insecure": true}
			if sni != "" {
				tls["server_name"] = sni
			}
			if link.Fingerprint != "" {
				tls["utls"] = map[string]interface{}{
					"enabled":     true,
					"fingerprint": link.Fingerprint,
				}
			}
			outbound["tls"] = tls
		}

	case "trojan":
		outbound = map[string]interface{}{
			"type":        "trojan",
			"server":      link.Address,
			"server_port": link.Port,
			"password":    link.UUID,
		}
		tls := map[string]interface{}{"enabled": true}
		if sni != "" {
			tls["server_name"] = sni
		}
		outbound["tls"] = tls
		if link.Network != "" && link.Network != "tcp" {
			transport := map[string]interface{}{"type": link.Network}
			if link.Path != "" {
				transport["path"] = link.Path
			}
			outbound["transport"] = transport
		}

	case "shadowsocks":
		outbound = map[string]interface{}{
			"type":        "shadowsocks",
			"server":      link.Address,
			"server_port": link.Port,
			"method":      link.Security,
			"password":    link.UUID,
		}

	case "wireguard":
		outbound = map[string]interface{}{
			"type":           "wireguard",
			"server":         link.Address,
			"server_port":    link.Port,
			"private_key":    link.PrivateKey,
			"peer_public_key": link.PublicKey,
			"local_address":  []string{"10.0.0.2/32"},
		}

	case "socks5":
		outbound = map[string]interface{}{
			"type":        "socks",
			"server":      link.Address,
			"server_port": link.Port,
			"version":     "5",
		}
		if link.UUID != "" {
			outbound["username"] = link.UUID
			outbound["password"] = link.Security
		}

	case "http":
		outbound = map[string]interface{}{
			"type":        "http",
			"server":      link.Address,
			"server_port": link.Port,
		}
		if link.UUID != "" {
			outbound["username"] = link.UUID
			outbound["password"] = link.Security
		}
		if link.TLS {
			outbound["tls"] = map[string]interface{}{"enabled": true}
		}

	case "ssh":
		// SSH tunnels run as a local SOCKS5 proxy (ssh -D). In chain/detour
		// scenarios, reference the SSH hop via its local listen port.
		port := link.ListenPort
		if port == 0 {
			port = 10800 // default chain port
		}
		outbound = map[string]interface{}{
			"type":        "socks",
			"server":      "127.0.0.1",
			"server_port": port,
			"version":     "5",
		}

	default:
		outbound = map[string]interface{}{
			"type": "direct",
		}
	}

	return outbound
}

// --- sing-box config generation ---

// singboxDNS generates the DNS section for the sing-box config.
//
// In gateway mode (GatewayMode=true), it produces full split DNS with:
//   - dns-tunnel: resolves through proxy (detour: "proxy")
//   - dns-direct: resolves directly (detour: "direct")
//   - DNS rules: geosite rule_sets point to dns-direct
//   - final: "dns-tunnel" (unmatched domains resolve through tunnel)
//   - independent_cache: true
//   - listen: "0.0.0.0" and listen_port: cg.DNSPort
//
// In proxy mode with GeositeCountries configured, it produces split DNS without listen.
// When GeositeCountries is empty, it falls back to simple DNS (direct only, no split).
func (cg *ConfigGenerator) singboxDNS() map[string]interface{} {
	// Determine which countries to use for geosite DNS rules.
	// Prefer GeositeCountries; fall back to WhitelistCountries if empty.
	geositeCountries := cg.GeositeCountries
	if len(geositeCountries) == 0 {
		geositeCountries = cg.WhitelistCountries
	}

	if !cg.GatewayMode && len(geositeCountries) == 0 {
		// Fallback: simple DNS, direct only (current behavior for proxy-only mode)
		return map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"tag":         "dns-direct",
					"type":        "udp",
					"server":      "1.1.1.1",
					"server_port": 53,
				},
			},
			"final": "dns-direct",
		}
	}

	// Split DNS: tunnel + direct (sing-box 1.12+ format)
	servers := []map[string]interface{}{
		{
			"tag":         "dns-tunnel",
			"type":        "udp",
			"server":      "1.1.1.1",
			"server_port": 53,
			"detour":      "proxy",
		},
		{
			"tag":         "dns-direct",
			"type":        "udp",
			"server":      "1.1.1.1",
			"server_port": 53,
		},
	}

	dns := map[string]interface{}{
		"servers": servers,
		"final":   "dns-tunnel",
	}

	// DNS rules: geosite rule_sets → dns-direct
	// IMPORTANT: only add DNS rules for geosite files that are actually defined
	// in the route rule_set section. In legacy mode (GatewayMode=false),
	// GeositeCountries is empty so we use WhitelistCountries, but we must only
	// reference tags that will have corresponding rule_set definitions in route.
	// Route only defines geosite rule_sets when GeositeCountries is non-empty,
	// so we must be consistent here.
	if len(cg.GeositeCountries) > 0 {
		var ruleSetTags []string
		for _, country := range cg.GeositeCountries {
			geositePath := filepath.Join(paths.Get().GeoDir, fmt.Sprintf("geosite-%s.srs", country))
			if _, err := os.Stat(geositePath); err == nil {
				ruleSetTags = append(ruleSetTags, fmt.Sprintf("geosite-%s", country))
			}
		}
		if len(ruleSetTags) > 0 {
			dns["rules"] = []map[string]interface{}{
				{
					"rule_set": ruleSetTags,
					"server":   "dns-direct",
				},
			}
		}
	}

	// In gateway mode, DNS listen is handled via a separate inbound
	// (sing-box 1.12+ removed dns.listen/listen_port fields)

	return dns
}

// singboxBypassDomainRule returns a sing-box route rule that matches bypass domains
// using domain_suffix and routes them to the "direct" outbound.
func (cg *ConfigGenerator) singboxBypassDomainRule() map[string]interface{} {
	return map[string]interface{}{
		"domain_suffix": cg.BypassDomains,
		"action":        "route",
		"outbound":      "direct",
	}
}

// singboxGeositeRuleSets returns rule_set definitions for geosite files.
// Each entry is a local binary rule set pointing to GeoDir/geosite-{country}.srs.
// Only includes entries where the file actually exists.
func (cg *ConfigGenerator) singboxGeositeRuleSets() []map[string]interface{} {
	var ruleSets []map[string]interface{}
	for _, country := range cg.GeositeCountries {
		geositePath := filepath.Join(paths.Get().GeoDir, fmt.Sprintf("geosite-%s.srs", country))
		if _, err := os.Stat(geositePath); err == nil {
			ruleSets = append(ruleSets, map[string]interface{}{
				"type":   "local",
				"tag":    fmt.Sprintf("geosite-%s", country),
				"format": "binary",
				"path":   geositePath,
			})
		}
	}
	return ruleSets
}

// singboxRoute builds the route section with geoip-based whitelist rules.
// Traffic destined for whitelisted countries goes direct; everything else goes through proxy.
func (cg *ConfigGenerator) singboxRoute(link *profile.Link) map[string]interface{} {
	var rules []map[string]interface{}

	// Rule: sniff to detect domain from TLS/HTTP
	rules = append(rules, map[string]interface{}{
		"action":  "sniff",
		"timeout": "300ms",
	})

	// Rule: force proxy domains — always tunnel these, even if IP is in a whitelisted country.
	// Must come before bypass_domains and geoip/geosite direct rules.
	if len(cg.ForceProxyDomains) > 0 {
		rules = append(rules, map[string]interface{}{
			"domain_suffix": cg.ForceProxyDomains,
			"action":        "route",
			"outbound":      "proxy",
		})
	}

	// Rule: domain bypass (VPN detection endpoints → direct)
	if len(cg.BypassDomains) > 0 {
		rules = append(rules, cg.singboxBypassDomainRule())
	}

	// Rule: private/LAN IPs → direct
	rules = append(rules, map[string]interface{}{
		"ip_is_private": true,
		"action":        "route",
		"outbound":      "direct",
	})

	// Rule: geosite domain whitelist → direct (must come before geoip)
	// Only include if geosite files actually exist
	if len(cg.GeositeCountries) > 0 {
		var geositeRuleSetTags []string
		for _, country := range cg.GeositeCountries {
			geositePath := filepath.Join(paths.Get().GeoDir, fmt.Sprintf("geosite-%s.srs", country))
			if _, err := os.Stat(geositePath); err == nil {
				geositeRuleSetTags = append(geositeRuleSetTags, fmt.Sprintf("geosite-%s", country))
			}
		}
		if len(geositeRuleSetTags) > 0 {
			rules = append(rules, map[string]interface{}{
				"rule_set": geositeRuleSetTags,
				"action":   "route",
				"outbound": "direct",
			})
		}
	}

	// Rule: whitelisted countries → direct (using local geoip rule_set)
	if len(cg.WhitelistCountries) > 0 {
		var ruleSetTags []string
		for _, country := range cg.WhitelistCountries {
			ruleSetTags = append(ruleSetTags, fmt.Sprintf("geoip-%s", country))
		}
		rules = append(rules, map[string]interface{}{
			"rule_set": ruleSetTags,
			"action":   "route",
			"outbound": "direct",
		})
	}

	// Build rule_set definitions (local .srs files)
	var ruleSets []map[string]interface{}

	// Geosite rule_set definitions (domain-based whitelist)
	if len(cg.GeositeCountries) > 0 {
		ruleSets = append(ruleSets, cg.singboxGeositeRuleSets()...)
	}

	// Geoip rule_set definitions (IP-based whitelist)
	for _, country := range cg.WhitelistCountries {
		ruleSets = append(ruleSets, map[string]interface{}{
			"type":   "local",
			"tag":    fmt.Sprintf("geoip-%s", country),
			"format": "binary",
			"path":   filepath.Join(paths.Get().GeoDir, fmt.Sprintf("geoip-%s.srs", country)),
		})
	}

	route := map[string]interface{}{
		"rules":                  rules,
		"final":                  "proxy",
		"default_domain_resolver": "dns-tunnel",
	}

	// Only include rule_set key when there are definitions
	if len(ruleSets) > 0 {
		route["rule_set"] = ruleSets
	}

	return route
}

// generateSingBox generates the full sing-box config.
//
// In gateway mode (GatewayMode=true), it uses TUN + Mixed inbounds, always includes
// route and DNS sections, and ensures geosite rule_sets are present alongside geoip ones.
// In proxy-only mode (GatewayMode=false), it uses only Mixed inbound and includes
// route/DNS only when whitelist countries or bypass domains are configured.
func (cg *ConfigGenerator) generateSingBox(link *profile.Link) (string, error) {
	// In gateway mode, ensure GeositeCountries is populated from WhitelistCountries
	// so that geosite rule_sets are included alongside geoip ones for domain-based routing.
	if cg.GatewayMode && len(cg.GeositeCountries) == 0 && len(cg.WhitelistCountries) > 0 {
		cg.GeositeCountries = cg.WhitelistCountries
	}

	// Select inbounds based on mode
	var inbounds []map[string]interface{}
	if cg.GatewayMode {
		inbounds = cg.singboxInboundsGateway(link)
	} else {
		inbounds = cg.singboxInbounds(link)
	}

	cfg := map[string]interface{}{
		"log": map[string]interface{}{
			"level": "info",
		},
		"inbounds":  inbounds,
		"outbounds": cg.singboxOutbounds(link),
	}

	// Route and DNS sections:
	// - Gateway mode: always include (needed for TUN routing and DNS serving)
	// - Proxy mode: include only when whitelist/bypass/geosite is configured
	if cg.GatewayMode || len(cg.WhitelistCountries) > 0 || len(cg.BypassDomains) > 0 || len(cg.GeositeCountries) > 0 {
		cfg["route"] = cg.singboxRoute(link)
		cfg["dns"] = cg.singboxDNS()
	}

	return cg.writeJSON("singbox", cfg)
}

// singboxInboundsGateway returns inbounds for gateway mode: a TUN inbound for
// transparent traffic capture, a DNS inbound for LAN DNS resolution,
// plus the standard Mixed inbound for local SOCKS5/HTTP proxy.
func (cg *ConfigGenerator) singboxInboundsGateway(link *profile.Link) []map[string]interface{} {
	tunInbound := map[string]interface{}{
		"type":       "tun",
		"tag":        "tun-in",
		"address":    []string{"10.0.0.1/30"},
		"auto_route": true,
		"stack":      "system",
	}

	// DNS inbound for LAN clients (sing-box 1.12+ requires separate inbound)
	dnsPort := cg.DNSPort
	if dnsPort == 0 {
		dnsPort = 53
	}
	dnsInbound := map[string]interface{}{
		"type":        "direct",
		"tag":         "dns-in",
		"listen":      "0.0.0.0",
		"listen_port": dnsPort,
		"network":     "udp",
		"override_address": "1.1.1.1",
		"override_port":    53,
	}

	// Combine TUN + DNS + Mixed inbounds
	inbounds := []map[string]interface{}{tunInbound, dnsInbound}
	inbounds = append(inbounds, cg.singboxInbounds(link)...)
	return inbounds
}

func (cg *ConfigGenerator) singboxInbounds(link *profile.Link) []map[string]interface{} {
	listenPort := link.ListenPort
	if listenPort == 0 {
		listenPort = cg.SOCKSPort
		if listenPort == 0 {
			listenPort = 2801
		}
	}

	inbounds := []map[string]interface{}{
		{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      "0.0.0.0",
			"listen_port": listenPort,
		},
	}

	return inbounds
}

func (cg *ConfigGenerator) singboxOutbounds(link *profile.Link) []map[string]interface{} {
	outbound := cg.BuildSingboxOutbound(link)
	if outbound == nil {
		outbound = map[string]interface{}{"type": "direct"}
	}
	outbound["tag"] = "proxy"

	if link.ChainProxy != "" {
		outbound["detour"] = "chain-out"
		return []map[string]interface{}{
			outbound,
			{
				"type":        "socks",
				"tag":         "chain-out",
				"server":      "127.0.0.1",
				"server_port": extractPort(link.ChainProxy),
			},
			{"type": "direct", "tag": "direct"},
		}
	}

	return []map[string]interface{}{
		outbound,
		{"type": "direct", "tag": "direct"},
	}
}

// --- xray config generation ---

// xrayDNSConfig builds the xray DNS section.
//
// Problem: Iranian ISPs poison DNS for censored sites (youtube.com → 10.x.x.x).
// That fake IP is in the private range, so xray routes it DIRECT → hits the
// censorship server → SSL_ERROR_SYSCALL.
//
// Fix: route DNS through the proxy outbound (proxyTag) so that youtube.com
// resolves to a real IP at the exit node, not the local poisoned one.
//
// Bootstrap exception: the proxy server itself (link.Address, link.SNI, link.Host)
// must resolve via localhost — otherwise xray can't connect to the proxy at all,
// creating a circular dependency.
func (cg *ConfigGenerator) xrayDNSConfig(link *profile.Link) map[string]interface{} {
	// Collect hostnames that must resolve locally (proxy server bootstrapping)
	bootstrapDomains := []string{}
	seen := map[string]bool{}
	for _, h := range []string{link.Address, link.SNI, link.Host} {
		h = strings.TrimSpace(h)
		if h != "" && !seen[h] {
			bootstrapDomains = append(bootstrapDomains, "full:"+h)
			seen[h] = true
		}
	}
	// bypass_domains also resolve locally (they go direct, no need for remote DNS)
	for _, d := range cg.BypassDomains {
		d = strings.TrimSpace(d)
		if d != "" && !seen[d] {
			bootstrapDomains = append(bootstrapDomains, "domain:"+d)
			seen[d] = true
		}
	}

	servers := []interface{}{}

	// First: proxy-server & direct domains → use local resolver (no proxyTag)
	if len(bootstrapDomains) > 0 {
		servers = append(servers, map[string]interface{}{
			"address": "localhost",
			"domains": bootstrapDomains,
		})
	}

	// Then: everything else → 1.1.1.1 via proxy, so censored domains get real IPs
	servers = append(servers, map[string]interface{}{
		"address":  "1.1.1.1",
		"proxyTag": "proxy",
	})

	// Fallback
	servers = append(servers, "localhost")

	return map[string]interface{}{
		"servers":       servers,
		"queryStrategy": "UseIPv4",
	}
}

func (cg *ConfigGenerator) generateXray(link *profile.Link) (string, error) {
	listenPort := link.ListenPort
	if listenPort == 0 {
		listenPort = cg.SOCKSPort
		if listenPort == 0 {
			listenPort = 2801
		}
	}

	cfg := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"dns": map[string]interface{}{
			"servers":       []interface{}{"localhost"},
			"queryStrategy": "UseIPv4",
		},
		"inbounds": []map[string]interface{}{
			{
				"port":     listenPort,
				"listen":   "0.0.0.0",
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  true,
				},
				"sniffing": map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls"},
					"routeOnly":    true,
				},
			},
		},
		"outbounds": cg.xrayOutbounds(link),
	}

	// Add routing rules for whitelist countries (geoip-based direct routing)
	if len(cg.WhitelistCountries) > 0 || len(cg.BypassDomains) > 0 || len(cg.ForceProxyDomains) > 0 {
		var rules []map[string]interface{}

		// Private/LAN IPs → direct (use explicit RFC1918 ranges; geoip:private is not
		// guaranteed to exist in all geoip.dat builds used by xray)
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"ip":          []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128"},
			"outboundTag": "direct",
		})

		// Force proxy domains → proxy (must come before geoip direct rules).
		// These domains always go through the tunnel even if their IP is in a
		// whitelisted country (e.g. Iranian sites that are ISP-blocked).
		if len(cg.ForceProxyDomains) > 0 {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"domain":      cg.ForceProxyDomains,
				"outboundTag": "proxy",
			})
		}

		// Bypass domains → direct
		if len(cg.BypassDomains) > 0 {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"domain":      cg.BypassDomains,
				"outboundTag": "direct",
			})
		}

		// Whitelisted countries → direct.
		//
		// Strategy: AsIs (no local DNS resolution for routing).
		//
		// WHY AsIs: Iranian ISPs poison DNS for blocked sites (youtube.com → 10.x.x.x).
		// With IPIfNonMatch, xray resolves youtube.com locally → gets 10.x.x.x →
		// private IP rule routes it DIRECT → hits ISP censorship server.
		// With AsIs, domains are never resolved locally; the VLESS outbound sends the
		// original domain to the CDN server which resolves it at the exit node → real IP.
		//
		// To compensate for losing geoip-based domain routing, add geosite rules:
		// - geosite:<country>: domain-based direct routing (AsIs-compatible)
		// - geoip:<country>: IP-based direct routing (still works for bare-IP traffic)
		// IP-based whitelist: still works with AsIs for bare-IP connections.
		// Domain traffic (e.g. youtube.com) bypasses this entirely with AsIs,
		// which is the point — ISP-poisoned IPs never get routed direct.
		for _, country := range cg.WhitelistCountries {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"ip":          []string{fmt.Sprintf("geoip:%s", country)},
				"outboundTag": "direct",
			})
		}

		cfg["routing"] = map[string]interface{}{
			"domainStrategy": "AsIs",
			"rules":          rules,
		}
	}

	return cg.writeJSON("xray", cfg)
}

func (cg *ConfigGenerator) xrayOutbounds(link *profile.Link) []map[string]interface{} {
	var outbound map[string]interface{}

	switch link.Protocol {
	case "vmess":
		vnext := map[string]interface{}{
			"address": link.Address,
			"port":    link.Port,
			"users": []map[string]interface{}{
				{
					"id":       link.UUID,
					"alterId":  link.AlterId,
					"security": link.Security,
				},
			},
		}
		settings := map[string]interface{}{
			"vnext": []map[string]interface{}{vnext},
		}
		outbound = map[string]interface{}{
			"protocol": "vmess",
			"settings": settings,
		}
		// Stream settings
		stream := map[string]interface{}{"network": link.Network}
		if link.Network == "ws" {
			ws := map[string]interface{}{"path": link.Path}
			if link.Host != "" {
				// xray 25.x: Host moved to top-level field (headers.Host is deprecated)
				ws["host"] = link.Host
			}
			stream["wsSettings"] = ws
		}
		if link.TLS {
			stream["security"] = "tls"
			stream["tlsSettings"] = map[string]interface{}{
				"serverName":    link.SNI,
				"allowInsecure": link.Insecure,
			}
		}
		outbound["streamSettings"] = stream

	case "vless":
		vnext := map[string]interface{}{
			"address": link.Address,
			"port":    link.Port,
			"users": []map[string]interface{}{
				{
					"id":         link.UUID,
					"encryption": "none",
					"flow":       link.Flow,
				},
			},
		}
		outbound = map[string]interface{}{
			"protocol": "vless",
			"settings": map[string]interface{}{
				"vnext": []map[string]interface{}{vnext},
			},
		}
		stream := map[string]interface{}{"network": link.Network}
		if link.Network == "ws" {
			ws := map[string]interface{}{"path": link.Path}
			if link.Host != "" {
				ws["host"] = link.Host
			}
			stream["wsSettings"] = ws
		}
		if link.Security == "reality" {
			stream["security"] = "reality"
			realitySettings := map[string]interface{}{
				"serverName": link.SNI,
				"publicKey":  link.RealityPublicKey,
				"shortId":    link.RealityShortID,
			}
			if link.Fingerprint != "" {
				realitySettings["fingerprint"] = link.Fingerprint
			}
			stream["realitySettings"] = realitySettings
		} else if link.TLS {
			stream["security"] = "tls"
			tlsSettings := map[string]interface{}{
				"serverName":   link.SNI,
				"allowInsecure": link.Insecure,
			}
			if link.Fingerprint != "" {
				tlsSettings["fingerprint"] = link.Fingerprint
			}
			stream["tlsSettings"] = tlsSettings
		}
		outbound["streamSettings"] = stream

	default:
		// Handle socks5 and http protocols for xray
		if link.Protocol == "socks5" || link.Protocol == "socks" {
			outbound = map[string]interface{}{
				"protocol": "socks",
				"settings": map[string]interface{}{
					"servers": []map[string]interface{}{
						{
							"address": link.Address,
							"port":    link.Port,
						},
					},
				},
			}
		} else if link.Protocol == "http" {
			outbound = map[string]interface{}{
				"protocol": "http",
				"settings": map[string]interface{}{
					"servers": []map[string]interface{}{
						{
							"address": link.Address,
							"port":    link.Port,
						},
					},
				},
			}
		} else {
			outbound = map[string]interface{}{
				"protocol": "freedom",
				"settings": map[string]interface{}{},
			}
		}
	}

	outbound["tag"] = "proxy"

	return []map[string]interface{}{
		outbound,
		{"protocol": "freedom", "tag": "direct", "settings": map[string]interface{}{}},
	}
}

// --- WireGuard config generation ---

func (cg *ConfigGenerator) generateWireGuard(link *profile.Link) (string, error) {
	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = %s
Endpoint = %s:%d
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`, link.PrivateKey, link.PublicKey, link.Address, link.Port)

	filename := filepath.Join(cg.tempDir, fmt.Sprintf("wg-%s.conf", sanitizeName(link.Remark)))
	if err := os.WriteFile(filename, []byte(conf), 0600); err != nil {
		return "", err
	}
	return filename, nil
}

// --- OpenVPN config generation ---

func (cg *ConfigGenerator) generateOpenVPN(link *profile.Link) (string, error) {
	// OpenVPN configs are typically provided as-is (not generated from URI)
	// If the RawURI contains a path to an .ovpn file, use that
	// Otherwise generate a minimal config
	conf := fmt.Sprintf(`client
dev tun
proto udp
remote %s %d
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-256-GCM
auth SHA256
verb 3
`, link.Address, link.Port)

	filename := filepath.Join(cg.tempDir, fmt.Sprintf("ovpn-%s.conf", sanitizeName(link.Remark)))
	if err := os.WriteFile(filename, []byte(conf), 0600); err != nil {
		return "", err
	}
	return filename, nil
}

// --- Helpers ---

func (cg *ConfigGenerator) writeJSON(prefix string, data interface{}) (string, error) {
	content, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling config: %w", err)
	}

	filename := filepath.Join(cg.tempDir, fmt.Sprintf("%s-config.json", prefix))
	if err := os.WriteFile(filename, content, 0644); err != nil {
		return "", fmt.Errorf("writing config file: %w", err)
	}

	return filename, nil
}

func sanitizeName(name string) string {
	result := ""
	for _, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' {
			result += string(ch)
		}
	}
	if result == "" {
		return "unnamed"
	}
	return result
}

func extractPort(addr string) int {
	// Extract port from "host:port" string
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			port := 0
			for _, ch := range addr[i+1:] {
				if ch >= '0' && ch <= '9' {
					port = port*10 + int(ch-'0')
				}
			}
			return port
		}
	}
	return 0
}
