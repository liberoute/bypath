package tunnel

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
)

// RoutingRule maps a traffic matcher to a named outbound.
// Match: "geoip:<cc>" | "geosite:<tag>" | "domain:<exact>" | "domain_suffix:<suffix>" | "ip_cidr:<cidr>" | "default"
// Outbound: "direct" | "proxy" | any name in ConfigGenerator.ExternalOutbounds
type RoutingRule struct {
	Match    string
	Outbound string
}

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
	// New rule-based routing (overrides whitelist fields when non-empty)
	RoutingRules      []RoutingRule     // ordered routing rules; last rule with match="default" sets final outbound
	ExternalOutbounds map[string]string // name → proxy URL (e.g. "lray-proxy" → "socks5://172.20.100.12:8088")
	// PinnedHosts maps hostnames to resolved IPs (populated from /etc/hosts pins).
	// When set, the outbound server address is replaced with the IP so that
	// sing-box's internal DNS resolver doesn't need to resolve the hostname itself —
	// avoiding bootstrap loops and ISP DNS interception for the proxy server.
	PinnedHosts map[string]string // hostname → IP (e.g. "dl8.okarimi.ir" → "104.16.6.70")
}

// proxyDNSServer returns the DoH server to use for DNS queries routed through the
// tunnel proxy. Cloudflare IPs (1.1.1.1, 1.0.0.1) are avoided because CDN-fronted
// VLESS proxies run on Cloudflare — connecting to 1.1.1.1:443 through them causes
// the CDN to rate-limit or self-intercept the request (503/429).
// Selection order: first non-Cloudflare entry in DNSUpstream → last entry → "8.8.8.8".
func (cg *ConfigGenerator) proxyDNSServer() string {
	cloudflare := map[string]bool{"1.1.1.1": true, "1.0.0.1": true}
	for _, u := range cg.DNSUpstream {
		if !cloudflare[u] {
			return u
		}
	}
	if len(cg.DNSUpstream) > 0 {
		return cg.DNSUpstream[len(cg.DNSUpstream)-1]
	}
	return "8.8.8.8"
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

	// Use pinned IP instead of hostname when available.
	// sing-box's internal DNS resolver doesn't read /etc/hosts, so using the
	// hostname would require a live DNS query — which may fail if ISP intercepts
	// DNS or if the query races with the tunnel bootstrap. Using the pre-resolved
	// IP avoids the lookup entirely; TLS SNI and WS Host headers remain correct.
	serverAddr := link.Address
	if ip, ok := cg.PinnedHosts[link.Address]; ok && ip != "" {
		serverAddr = ip
	}

	var outbound map[string]interface{}

	switch link.Protocol {
	case "vmess":
		outbound = map[string]interface{}{
			"type":        "vmess",
			"server":      serverAddr,
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
			"server":      serverAddr,
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
			"server":      serverAddr,
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
			"server":      serverAddr,
			"server_port": link.Port,
			"method":      link.Security,
			"password":    link.UUID,
		}

	case "wireguard":
		outbound = map[string]interface{}{
			"type":            "wireguard",
			"server":          serverAddr,
			"server_port":     link.Port,
			"private_key":     link.PrivateKey,
			"peer_public_key": link.PublicKey,
			"local_address":   []string{"10.0.0.2/32"},
		}

	case "socks5":
		outbound = map[string]interface{}{
			"type":        "socks",
			"server":      serverAddr,
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
			"server":      serverAddr,
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
func (cg *ConfigGenerator) singboxDNS(link *profile.Link) map[string]interface{} {
	// Determine which countries to use for geosite DNS rules.
	// Prefer GeositeCountries; fall back to WhitelistCountries if empty.
	geositeCountries := cg.GeositeCountries
	if len(geositeCountries) == 0 {
		geositeCountries = cg.WhitelistCountries
	}

	if !cg.GatewayMode && len(geositeCountries) == 0 && len(cg.RoutingRules) == 0 {
		// Fallback: simple DNS, direct only (proxy-only mode with no routing rules)
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
	// Loop prevention is handled by DNS rules: domains that go DIRECT also resolve
	// via dns-direct (see rule generation below), so dns-tunnel is never needed
	// when setting up a direct connection, avoiding the proxy bootstrap loop.
	servers := []map[string]interface{}{
		{
			// DoH (HTTPS) so the query goes over TCP through the VLESS/WebSocket tunnel.
			// Plain UDP DNS doesn't survive TCP-only transports (VLESS-WS, Trojan-WS, etc.)
			// and would silently fail or be intercepted/poisoned by the ISP.
			// proxyDNSServer() avoids Cloudflare IPs — see its doc for why.
			"tag":    "dns-tunnel",
			"type":   "https",
			"server": cg.proxyDNSServer(),
			"detour": "proxy",
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

	// Build DNS rules in order: proxy server domains first, then geosite rule_sets.
	var dnsRules []map[string]interface{}

	// Proxy server domains must resolve via dns-direct to prevent a DNS loop:
	// sing-box would otherwise try to resolve the VLESS server domain through
	// the tunnel, which in turn requires the tunnel to be up — a circular dependency.
	if link != nil {
		seen := map[string]bool{}
		var proxyDomains []string
		for _, candidate := range []string{link.Address, link.SNI, link.Host} {
			if candidate == "" || seen[candidate] {
				continue
			}
			seen[candidate] = true
			if net.ParseIP(candidate) == nil { // skip bare IPs
				proxyDomains = append(proxyDomains, candidate)
			}
		}
		if len(proxyDomains) > 0 {
			dnsRules = append(dnsRules, map[string]interface{}{
				"domain": proxyDomains,
				"server": "dns-direct",
			})
		}
	}

	// When using new routing rules: derive DNS rules from routing rules.
	// Any domain routed to "direct" must also resolve via dns-direct to avoid
	// the loop: dns-tunnel→proxy→resolve dl8→dns-direct→1.1.1.1→proxy→...
	if len(cg.RoutingRules) > 0 {
		for _, rule := range cg.RoutingRules {
			if rule.Outbound != "direct" || rule.Match == "default" {
				continue
			}
			parts := strings.SplitN(rule.Match, ":", 2)
			if len(parts) != 2 {
				continue
			}
			typ, val := parts[0], parts[1]
			switch typ {
			case "geosite":
				p := filepath.Join(paths.Get().GeoDir, fmt.Sprintf("geosite-%s.srs", val))
				if _, err := os.Stat(p); err == nil {
					dnsRules = append(dnsRules, map[string]interface{}{
						"rule_set": []string{fmt.Sprintf("geosite-%s", val)},
						"server":   "dns-direct",
					})
				}
			case "geoip":
				dnsRules = append(dnsRules, map[string]interface{}{
					"rule_set": []string{fmt.Sprintf("geoip-%s", val)},
					"server":   "dns-direct",
				})
			case "domain_suffix":
				dnsRules = append(dnsRules, map[string]interface{}{
					"domain_suffix": []string{val},
					"server":        "dns-direct",
				})
			case "domain":
				dnsRules = append(dnsRules, map[string]interface{}{
					"domain": []string{val},
					"server": "dns-direct",
				})
			}
		}
	} else if len(cg.GeositeCountries) > 0 {
		// Legacy whitelist mode: geosite rule_sets → dns-direct
		// IMPORTANT: only add DNS rules for geosite files that are actually defined
		// in the route rule_set section. In legacy mode (GatewayMode=false),
		// GeositeCountries is empty so we use WhitelistCountries, but we must only
		// reference tags that will have corresponding rule_set definitions in route.
		// Route only defines geosite rule_sets when GeositeCountries is non-empty,
		// so we must be consistent here.
		var ruleSetTags []string
		for _, country := range cg.GeositeCountries {
			geositePath := filepath.Join(paths.Get().GeoDir, fmt.Sprintf("geosite-%s.srs", country))
			if _, err := os.Stat(geositePath); err == nil {
				ruleSetTags = append(ruleSetTags, fmt.Sprintf("geosite-%s", country))
			}
		}
		if len(ruleSetTags) > 0 {
			dnsRules = append(dnsRules, map[string]interface{}{
				"rule_set": ruleSetTags,
				"server":   "dns-direct",
			})
		}
	}

	if len(dnsRules) > 0 {
		dns["rules"] = dnsRules
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

// singboxRouteFromRules builds the sing-box route section from RoutingRules.
// Private IPs always go direct. Rules are evaluated in order; "default" sets the final outbound.
func (cg *ConfigGenerator) singboxRouteFromRules() map[string]interface{} {
	var rules []map[string]interface{}
	seenRuleSets := map[string]bool{}
	var ruleSets []map[string]interface{}
	finalOutbound := "proxy"

	rules = append(rules, map[string]interface{}{
		"action":  "sniff",
		"timeout": "300ms",
	})
	// resolve action: translate domain names to IPs so that IP-based rules (geoip, ip_cidr)
	// can match. Uses dns-tunnel (DoH via proxy) to bypass ISP DNS poisoning — blocked sites
	// return bogon/private IPs from local DNS, which would incorrectly match ip_is_private.
	// Proxy server domains are pinned to IPs in /etc/hosts so no bootstrap loop occurs.
	rules = append(rules, map[string]interface{}{
		"action": "resolve",
		"server": "dns-tunnel",
	})
	rules = append(rules, map[string]interface{}{
		"ip_is_private": true,
		"action":        "route",
		"outbound":      "direct",
	})

	for _, rule := range cg.RoutingRules {
		if rule.Match == "default" {
			finalOutbound = rule.Outbound
			continue
		}
		sbRule := cg.singboxRuleFromMatcher(rule.Match, rule.Outbound)
		if sbRule == nil {
			log.Printf("⚠️  routing rule: unsupported matcher %q, skipping", rule.Match)
			continue
		}
		rules = append(rules, sbRule)
		if rs := cg.ruleSetForMatcher(rule.Match); rs != nil {
			tag := rs["tag"].(string)
			if !seenRuleSets[tag] {
				seenRuleSets[tag] = true
				ruleSets = append(ruleSets, rs)
			}
		}
	}

	route := map[string]interface{}{
		"rules":                   rules,
		"final":                   finalOutbound,
		"default_domain_resolver": "dns-direct",
	}
	if cg.GatewayMode {
		route["auto_detect_interface"] = true
	}
	if len(ruleSets) > 0 {
		route["rule_set"] = ruleSets
	}
	return route
}

// singboxRuleFromMatcher converts a match string + outbound to a sing-box rule map.
func (cg *ConfigGenerator) singboxRuleFromMatcher(match, outbound string) map[string]interface{} {
	parts := strings.SplitN(match, ":", 2)
	if len(parts) != 2 {
		return nil
	}
	typ, val := parts[0], parts[1]
	rule := map[string]interface{}{"action": "route", "outbound": outbound}
	switch typ {
	case "geoip":
		// Only add rule if the .srs file actually exists — referencing a missing
		// rule_set crashes sing-box at startup.
		if cg.ruleSetForMatcher(match) == nil {
			return nil
		}
		rule["rule_set"] = []string{fmt.Sprintf("geoip-%s", val)}
	case "geosite":
		if cg.ruleSetForMatcher(match) == nil {
			return nil
		}
		rule["rule_set"] = []string{fmt.Sprintf("geosite-%s", val)}
	case "domain":
		rule["domain"] = []string{val}
	case "domain_suffix":
		rule["domain_suffix"] = []string{val}
	case "ip_cidr":
		rule["ip_cidr"] = []string{val}
	default:
		return nil
	}
	return rule
}

// ruleSetForMatcher returns the sing-box rule_set definition for a geoip/geosite matcher,
// or nil if the matcher doesn't need one (or the file doesn't exist for geosite).
func (cg *ConfigGenerator) ruleSetForMatcher(match string) map[string]interface{} {
	parts := strings.SplitN(match, ":", 2)
	if len(parts) != 2 {
		return nil
	}
	typ, val := parts[0], parts[1]
	switch typ {
	case "geoip":
		p := filepath.Join(paths.Get().GeoDir, fmt.Sprintf("geoip-%s.srs", val))
		if _, err := os.Stat(p); err != nil {
			log.Printf("⚠️  geoip-%s.srs not found — run 'bypath geo update' or wait for auto-download", val)
			return nil
		}
		return map[string]interface{}{
			"type":   "local",
			"tag":    fmt.Sprintf("geoip-%s", val),
			"format": "binary",
			"path":   p,
		}
	case "geosite":
		p := filepath.Join(paths.Get().GeoDir, fmt.Sprintf("geosite-%s.srs", val))
		if _, err := os.Stat(p); err != nil {
			return nil
		}
		return map[string]interface{}{
			"type":   "local",
			"tag":    fmt.Sprintf("geosite-%s", val),
			"format": "binary",
			"path":   p,
		}
	}
	return nil
}

// singboxExternalOutbounds returns sing-box outbound entries for each ExternalOutbound URL.
func (cg *ConfigGenerator) singboxExternalOutbounds() []map[string]interface{} {
	names := make([]string, 0, len(cg.ExternalOutbounds))
	for name := range cg.ExternalOutbounds {
		names = append(names, name)
	}
	sort.Strings(names)

	var result []map[string]interface{}
	for _, name := range names {
		ob := parseSingboxExternalOutbound(name, cg.ExternalOutbounds[name])
		if ob != nil {
			result = append(result, ob)
		}
	}
	return result
}

func parseSingboxExternalOutbound(tag, rawURL string) map[string]interface{} {
	u, err := url.Parse(rawURL)
	if err != nil {
		log.Printf("⚠️  external_outbounds %q: invalid URL: %v", tag, err)
		return nil
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		log.Printf("⚠️  external_outbounds %q: invalid host:port: %v", tag, err)
		return nil
	}
	port, _ := strconv.Atoi(portStr)

	ob := map[string]interface{}{
		"tag":         tag,
		"server":      host,
		"server_port": port,
	}
	if u.User != nil {
		ob["username"] = u.User.Username()
		if pwd, ok := u.User.Password(); ok {
			ob["password"] = pwd
		}
	}
	switch u.Scheme {
	case "socks5", "socks5h":
		ob["type"] = "socks"
		ob["version"] = "5"
	case "socks4":
		ob["type"] = "socks"
		ob["version"] = "4"
	case "http":
		ob["type"] = "http"
	case "https":
		ob["type"] = "http"
		ob["tls"] = map[string]interface{}{"enabled": true}
	default:
		log.Printf("⚠️  external_outbounds %q: unsupported scheme %q", tag, u.Scheme)
		return nil
	}
	return ob
}

// singboxRoute builds the route section with geoip-based whitelist rules.
// Traffic destined for whitelisted countries goes direct; everything else goes through proxy.
func (cg *ConfigGenerator) singboxRoute(link *profile.Link) map[string]interface{} {
	if len(cg.RoutingRules) > 0 {
		return cg.singboxRouteFromRules()
	}
	var rules []map[string]interface{}

	// Rule: sniff to detect domain from TLS/HTTP
	rules = append(rules, map[string]interface{}{
		"action":  "sniff",
		"timeout": "300ms",
	})
	// resolve: translate domain names to IPs before IP-based rules (geoip, ip_cidr).
	// Must use dns-direct — UDP DNS via a WebSocket/TCP proxy doesn't work.
	rules = append(rules, map[string]interface{}{
		"action": "resolve",
		"server": "dns-direct",
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
		"rules":                   rules,
		"final":                   "proxy",
		"default_domain_resolver": "dns-direct",
	}

	// In TUN (gateway) mode, bind outbound connections to the physical interface
	// so that sing-box's own traffic (VLESS, DNS) bypasses the TUN and doesn't loop.
	if cg.GatewayMode {
		route["auto_detect_interface"] = true
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
	// - Proxy mode: include when whitelist/bypass/geosite is configured OR routing rules are set
	if cg.GatewayMode || len(cg.RoutingRules) > 0 || len(cg.WhitelistCountries) > 0 || len(cg.BypassDomains) > 0 || len(cg.GeositeCountries) > 0 {
		cfg["route"] = cg.singboxRoute(link)
		cfg["dns"] = cg.singboxDNS(link)
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

	var outbounds []map[string]interface{}
	if link.ChainProxy != "" {
		outbound["detour"] = "chain-out"
		outbounds = []map[string]interface{}{
			outbound,
			{
				"type":        "socks",
				"tag":         "chain-out",
				"server":      "127.0.0.1",
				"server_port": extractPort(link.ChainProxy),
			},
			{"type": "direct", "tag": "direct"},
		}
	} else {
		outbounds = []map[string]interface{}{
			outbound,
			{"type": "direct", "tag": "direct"},
		}
	}
	outbounds = append(outbounds, cg.singboxExternalOutbounds()...)
	return outbounds
}

// --- xray config generation ---

// xrayDNSConfig builds the xray DNS section.
//
// Problem: Iranian ISPs poison UDP DNS for censored sites (youtube.com → 10.x.x.x fake IP).
// And VLESS over WebSocket is TCP-only — sending plain UDP DNS queries with proxyTag sends
// UDP through the TCP tunnel, which either gets dropped or the server doesn't support it.
//
// Fix: use DoH (DNS over HTTPS) with proxyTag so the DNS query travels as HTTPS/TCP through
// the VLESS proxy. The exit node resolves the domain unblocked and returns a real IP.
//
// Bootstrap exception: the proxy server itself (link.Address, link.SNI, link.Host) is already
// pinned in /etc/hosts by bypath before xray starts. Bypass domains also use direct DoH
// (they route direct so no circular dependency). For these, direct DoH to 1.1.1.1 is used
// since they are either IPs themselves or non-censored hostnames.
func (cg *ConfigGenerator) xrayDNSConfig(link *profile.Link) map[string]interface{} {
	upstream := "1.1.1.1"
	if len(cg.DNSUpstream) > 0 {
		upstream = cg.DNSUpstream[0]
	}
	// DoH URL: if upstream is an IP, build a DoH URL; if it's already a URL, use as-is.
	upstreamDoH := upstream
	if net.ParseIP(upstream) != nil {
		upstreamDoH = "https://" + upstream + "/dns-query"
	}

	// For proxy DoH (goes through the CDN-fronted VLESS outbound), avoid Cloudflare IPs.
	// proxyDNSServer() selects a non-Cloudflare server from DNSUpstream. See its doc.
	proxyUpstream := cg.proxyDNSServer()
	proxyUpstreamDoH := proxyUpstream
	if net.ParseIP(proxyUpstream) != nil {
		proxyUpstreamDoH = "https://" + proxyUpstream + "/dns-query"
	}

	// Collect hostnames that must resolve without going through the proxy.
	// Proxy-server domains are already in /etc/hosts (pinned by bypath), so direct DNS
	// here is just a belt-and-suspenders fallback. Bypass domains go direct anyway.
	bootstrapDomains := []string{}
	seen := map[string]bool{}
	for _, h := range []string{link.Address, link.SNI, link.Host} {
		h = strings.TrimSpace(h)
		if h != "" && !seen[h] {
			bootstrapDomains = append(bootstrapDomains, "full:"+h)
			seen[h] = true
		}
	}
	for _, d := range cg.BypassDomains {
		d = strings.TrimSpace(d)
		if d != "" && !seen[d] {
			bootstrapDomains = append(bootstrapDomains, "domain:"+d)
			seen[d] = true
		}
	}

	servers := []interface{}{}

	// Bootstrap domains → direct DoH (no proxy).
	if len(bootstrapDomains) > 0 {
		servers = append(servers, map[string]interface{}{
			"address": upstreamDoH,
			"domains": bootstrapDomains,
		})
	}

	// Everything else → DoH via proxy (TCP through VLESS — works with WS transport).
	// This ensures ISP-poisoned domains get real IPs from the uncensored exit node.
	servers = append(servers, map[string]interface{}{
		"address":  proxyUpstreamDoH,
		"proxyTag": "proxy",
	})

	// Fallback: direct DoH (may be blocked by ISP for foreign domains, but better than nothing).
	servers = append(servers, upstreamDoH)

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
		"dns": cg.xrayDNSConfig(link),
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

	// Append external outbounds (referenced by routing rules or used manually)
	if len(cg.ExternalOutbounds) > 0 {
		existing := cfg["outbounds"].([]map[string]interface{})
		cfg["outbounds"] = append(existing, cg.xrayExternalOutbounds()...)
	}

	// Add routing: prefer new rule-based system, fall back to legacy whitelist config.
	if len(cg.RoutingRules) > 0 {
		cfg["routing"] = cg.xrayRouteFromRules()
	} else if len(cg.WhitelistCountries) > 0 || len(cg.BypassDomains) > 0 || len(cg.ForceProxyDomains) > 0 {
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
		// Strategy: UseIPv4 — xray resolves all domains via its own DNS config (not system
		// DNS) and uses the resolved IP for both routing decisions AND outbound connections.
		//
		// WHY UseIPv4 (not IPIfNonMatch or AsIs):
		// With AsIs/IPIfNonMatch, xray's direct outbound connects using the original hostname,
		// which requires a system-level DNS resolution. In gateway mode, bypath sets
		// resolv.conf to 127.0.0.1, which may have no server → hostname resolution fails →
		// direct outbound fails with SSL_ERROR_SYSCALL.
		// With UseIPv4, xray resolves via its own DNS config (1.1.1.1 direct for bootstrap
		// domains, 1.1.1.1 via proxy for general), gets a real IP, uses that IP to both
		// route (geoip:ir → direct) and connect. No system DNS dependency. ✓
		//
		// The old concern (ISP poisoning: youtube.com → 10.x.x.x → private rule → direct)
		// is now mitigated: dns2socks routes DNS through the tunnel so resolutions are
		// uncensored. Blocked sites get real IPs → not private → go through proxy. ✓
		//
		// In gateway mode (tun2socks sends IPs), domainStrategy is irrelevant because
		// tun2socks never sends hostnames — only destination IPs are forwarded.
		// Use geoip for country routing (geosite:ir doesn't exist in standard geosite.dat builds).
		for _, country := range cg.WhitelistCountries {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"ip":          []string{fmt.Sprintf("geoip:%s", country)},
				"outboundTag": "direct",
			})
		}

		cfg["routing"] = map[string]interface{}{
			// IPIfNonMatch: if no domain rule matches, resolve domain to IP and check IP rules.
			// UseIPv4 caused xray 25.x to skip DNS resolution in routing entirely (debug showed
			// "default route" with no DNS attempt logged). IPIfNonMatch triggers the DNS-then-IP
			// fallback we need for geoip:ir matching.
			// The freedom direct outbound still has domainStrategy:UseIPv4 so it uses xray DNS
			// (not broken system DNS) for the actual TCP dial.
			"domainStrategy": "IPIfNonMatch",
			"rules":          rules,
		}
	}

	return cg.writeJSON("xray", cfg)
}

// xrayGeositeAvailable returns true when a geosite.dat that xray can load exists.
// xray looks for geosite.dat in: its own binary's directory, then standard system paths.
func xrayGeositeAvailable() bool {
	candidates := []string{
		filepath.Join(paths.Get().EngineDir, "geosite.dat"),
		"/usr/local/share/xray/geosite.dat",
		"/usr/share/xray/geosite.dat",
		"/etc/bypath/geo/geosite.dat",
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && info.Size() > 1000 {
			return true
		}
	}
	return false
}

// xrayRouteFromRules builds the xray routing section from RoutingRules.
// Private IPs always go direct. A "default" rule becomes a TCP+UDP catch-all at the end.
func (cg *ConfigGenerator) xrayRouteFromRules() map[string]interface{} {
	var rules []map[string]interface{}
	finalOutbound := "proxy"

	rules = append(rules, map[string]interface{}{
		"type":        "field",
		"ip":          []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "fc00::/7", "::1/128"},
		"outboundTag": "direct",
	})

	for _, rule := range cg.RoutingRules {
		if rule.Match == "default" {
			finalOutbound = rule.Outbound
			continue
		}
		xrayRule := cg.xrayRuleFromMatcher(rule.Match, rule.Outbound)
		if xrayRule == nil {
			log.Printf("⚠️  routing rule: unsupported matcher %q for xray, skipping", rule.Match)
			continue
		}
		rules = append(rules, xrayRule)
	}

	// Explicit catch-all so unmatched traffic routes to the correct final outbound.
	rules = append(rules, map[string]interface{}{
		"type":        "field",
		"network":     "tcp,udp",
		"outboundTag": finalOutbound,
	})

	return map[string]interface{}{
		"domainStrategy": "IPIfNonMatch",
		"rules":          rules,
	}
}

// xrayRuleFromMatcher converts a match string + outbound to an xray routing rule.
func (cg *ConfigGenerator) xrayRuleFromMatcher(match, outbound string) map[string]interface{} {
	parts := strings.SplitN(match, ":", 2)
	if len(parts) != 2 {
		return nil
	}
	typ, val := parts[0], parts[1]
	rule := map[string]interface{}{"type": "field", "outboundTag": outbound}
	switch typ {
	case "geoip":
		rule["ip"] = []string{fmt.Sprintf("geoip:%s", val)}
	case "geosite":
		if !xrayGeositeAvailable() {
			log.Printf("⚠️  routing rule geosite:%s: geosite.dat not found, skipping", val)
			return nil
		}
		rule["domain"] = []string{fmt.Sprintf("geosite:%s", val)}
	case "domain":
		rule["domain"] = []string{fmt.Sprintf("full:%s", val)}
	case "domain_suffix":
		rule["domain"] = []string{fmt.Sprintf("domain:%s", val)}
	case "ip_cidr":
		rule["ip"] = []string{val}
	default:
		return nil
	}
	return rule
}

// xrayExternalOutbounds returns xray outbound entries for each ExternalOutbound URL.
func (cg *ConfigGenerator) xrayExternalOutbounds() []map[string]interface{} {
	names := make([]string, 0, len(cg.ExternalOutbounds))
	for name := range cg.ExternalOutbounds {
		names = append(names, name)
	}
	sort.Strings(names)

	var result []map[string]interface{}
	for _, name := range names {
		ob := parseXrayExternalOutbound(name, cg.ExternalOutbounds[name])
		if ob != nil {
			result = append(result, ob)
		}
	}
	return result
}

func parseXrayExternalOutbound(tag, rawURL string) map[string]interface{} {
	u, err := url.Parse(rawURL)
	if err != nil {
		log.Printf("⚠️  external_outbounds %q: invalid URL: %v", tag, err)
		return nil
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		log.Printf("⚠️  external_outbounds %q: invalid host:port: %v", tag, err)
		return nil
	}
	port, _ := strconv.Atoi(portStr)

	server := map[string]interface{}{"address": host, "port": port}
	if u.User != nil {
		user := u.User.Username()
		pwd, _ := u.User.Password()
		server["users"] = []map[string]interface{}{{"user": user, "pass": pwd}}
	}

	var protocol string
	switch u.Scheme {
	case "socks5", "socks5h", "socks4", "socks":
		protocol = "socks"
	case "http", "https":
		protocol = "http"
	default:
		log.Printf("⚠️  external_outbounds %q: unsupported scheme %q", tag, u.Scheme)
		return nil
	}

	return map[string]interface{}{
		"tag":      tag,
		"protocol": protocol,
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{server},
		},
	}
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
		// UseIPv4: resolve hostname via xray's own DNS before dialing, so the direct
		// outbound never needs system DNS (which bypath sets to 127.0.0.1 in gateway mode).
		{"protocol": "freedom", "tag": "direct", "settings": map[string]interface{}{"domainStrategy": "UseIPv4"}},
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
