package tunnel

import (
	"encoding/json"
	"errors"
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
	"github.com/liberoute/bypath/internal/geo"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/securefile"
)

// RoutingRule maps a traffic matcher to a named outbound.
// Match: "geoip:<cc>" | "geosite:<tag>" | "domain:<exact>" | "domain_suffix:<suffix>" | "ip_cidr:<cidr>" | "default"
// Outbound: "direct" | "proxy" | any name in ConfigGenerator.ExternalOutbounds
type RoutingRule struct {
	Match    string
	Outbound string
}

// LocalDNSRule routes domain suffixes to a specific local DNS server (e.g. home DNS for .home).
type LocalDNSRule struct {
	Server  string   // IP of the local DNS server
	Domains []string // domain suffixes without leading dot (e.g. ["home", "lan"])
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
	// SOCKSListen is the bind address for generated SOCKS/mixed inbounds.
	// Empty means loopback; a LAN address is only reachable when the operator
	// opted in through server.socks_allow_lan.
	SOCKSListen   string // e.g. "127.0.0.1" (default) or "0.0.0.0"
	SOCKSUsername string // optional SOCKS5 user; emitted with SOCKSPassword
	SOCKSPassword string
	SSHHostKey    string // SSH host-key policy, reused by the bench command
	SNISpoof      string // fake SNI to replace real one (empty = disabled)
	GatewayMode   bool   // when true, generate TUN inbound + DNS server config
	DNSPort       int    // DNS listen port for gateway mode (default: 53)
	// New rule-based routing (overrides whitelist fields when non-empty)
	RoutingRules      []RoutingRule     // ordered routing rules; last rule with match="default" sets final outbound
	ExternalOutbounds map[string]string // name → proxy URL (e.g. "office-proxy" → "socks5://10.20.30.10:8088")
	// PinnedHosts maps hostnames to resolved IPs (populated from /etc/hosts pins).
	// When set, the outbound server address is replaced with the IP so that
	// sing-box's internal DNS resolver doesn't need to resolve the hostname itself —
	// avoiding bootstrap loops and ISP DNS interception for the proxy server.
	PinnedHosts map[string]string // hostname → IP (e.g. "cdn.example.net" → "192.0.2.70")
	// ProfileDir resolves artifact references recorded by an earlier install
	// (e.g. "data/profiles/ovpn/x.ovpn") that no longer match the daemon's
	// working directory. Empty keeps legacy behaviour for portable runs.
	ProfileDir string
	// LocalDNSRules routes specific domain suffixes to a local DNS server (e.g. .home → 192.0.2.53).
	// Traffic to these domains is also routed direct (not through the tunnel).
	LocalDNSRules []LocalDNSRule

	// genDir is the current per-generation directory. Every Generate call gets
	// its own 0700 directory so configs and extracted secrets from different
	// attempts never overwrite or delete each other.
	genDir  string
	genDirs []string
}

// socksListenAddr is the bind address for generated SOCKS/mixed inbounds.
// Loopback is the default so an unconfigured proxy is never reachable from the
// LAN; server.socks_allow_lan is the explicit override.
func (cg *ConfigGenerator) socksListenAddr() string {
	if listen := strings.TrimSpace(cg.SOCKSListen); listen != "" {
		return listen
	}
	return "127.0.0.1"
}

// sockAuth returns the credentials to embed in a socks/mixed inbound, or nil
// when the listener is unauthenticated.
func (cg *ConfigGenerator) sockAuth() (string, string, bool) {
	if cg.SOCKSUsername == "" || cg.SOCKSPassword == "" {
		return "", "", false
	}
	return cg.SOCKSUsername, cg.SOCKSPassword, true
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
	if err := ValidateEngineSupport(eng, link); err != nil {
		return "", err
	}
	if _, err := cg.beginGeneration(); err != nil {
		return "", err
	}
	switch eng.Name {
	case "sing-box":
		if link.Protocol == "openvpn" {
			return cg.generateSingBoxOpenVPN(link)
		}
		return cg.generateSingBox(link)
	case "xray":
		return cg.generateXray(link)
	case "wireguard-go":
		return cg.generateWireGuard(link)
	case "openvpn":
		return "", fmt.Errorf("native OpenVPN engine is not supported; OpenVPN profiles run through sing-box 1.14+")
	default:
		return "", fmt.Errorf("unsupported engine: %s", eng.Name)
	}
}

// ValidateEngineSupport rejects combinations where the selected engine would
// silently drop security-relevant profile parameters.
func ValidateEngineSupport(eng *engine.Engine, link *profile.Link) error {
	if eng == nil || link == nil {
		return fmt.Errorf("missing engine or link")
	}
	if err := validateProtocolMapping(eng.Name, link); err != nil {
		return err
	}
	if link.EncryptedVLESS() {
		if eng.Name != "xray" {
			return fmt.Errorf("VLESS Encryption requires the xray engine; %s would silently discard it", eng.Name)
		}
		if err := eng.RequireVersion(minXrayVLESSEncryption); err != nil {
			return fmt.Errorf("VLESS Encryption unsupported: %w", err)
		}
	}
	if link.Protocol == "openvpn" {
		if eng.Name != "sing-box" {
			return fmt.Errorf("OpenVPN profiles require the sing-box engine (1.14+)")
		}
		if link.OVPNPath == "" {
			return fmt.Errorf("OpenVPN profile has no .ovpn file reference")
		}
		if err := eng.RequireVersion(minSingBoxOpenVPN); err != nil {
			return fmt.Errorf("OpenVPN endpoint unsupported: %w", err)
		}
	}
	return nil
}

// Minimum engine releases for features whose absence would silently change the
// security properties of a profile.
const (
	// First release family validated to accept VLESS Encryption values; older
	// builds reject the user field or strip it down to "none".
	minXrayVLESSEncryption = "26.3.27"
	// openvpn-client endpoint support.
	minSingBoxOpenVPN = "1.14.0"
)

// GenerateChainConfig creates a sing-box config with detour-linked outbounds for a multi-hop chain.
// Each link becomes an outbound with a unique tag (chain-<name>-hop-<i>), and each outbound's
// detour field points to the next hop. The last hop has no detour (it connects directly).
// Returns the path to the generated JSON config file.
func (cg *ConfigGenerator) GenerateChainConfig(chainName string, links []*profile.Link) (string, error) {
	if len(links) == 0 {
		return "", fmt.Errorf("chain %q: no links provided", chainName)
	}

	for _, link := range links {
		if err := ValidateEngineSupport(&engine.Engine{Name: "sing-box"}, link); err != nil {
			return "", err
		}
		if link.Flow != "" {
			return "", fmt.Errorf("chain detours cannot preserve VLESS flow")
		}
	}
	// Task 2.2: Generate outbounds with unique tags and detour linkage
	outbounds := cg.buildChainOutbounds(chainName, links)

	// Task 2.3: Generate single mixed inbound routing to first hop's tag
	// Use port 10800 for chain inbound to avoid conflict with main gateway (2801)
	chainPort := 10800
	chainInbound := map[string]interface{}{
		"type":        "mixed",
		"tag":         "mixed-in",
		"listen":      cg.socksListenAddr(),
		"listen_port": chainPort,
	}
	if user, pass, ok := cg.sockAuth(); ok {
		chainInbound["users"] = []map[string]interface{}{{"username": user, "password": pass}}
	}
	inbounds := []map[string]interface{}{chainInbound}

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
			outbound["transport"] = singboxTransport(link, host)
		}
		if link.TLS {
			tls := map[string]interface{}{"enabled": true}
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
			outbound["transport"] = singboxTransport(link, host)
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
			tls := map[string]interface{}{"enabled": true, "insecure": link.Insecure}
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
			outbound["transport"] = singboxTransport(link, host)
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
		// Generate rejects this configuration. Low-level callers also fail closed.
		outbound = map[string]interface{}{"type": "block"}
	}
	if link.TLS || link.Protocol == "trojan" {
		tls := singboxTLS(link, sni)
		if previous, ok := outbound["tls"].(map[string]interface{}); ok {
			if reality, ok := previous["reality"]; ok {
				tls["reality"] = reality
			}
		}
		outbound["tls"] = tls
	}

	return outbound
}

// singboxTransport builds a sing-box V2Ray transport object for the link.
// xhttp/splithttp is passed through when the engine supports it; path/host/mode/extra preserved.
func singboxTransport(link *profile.Link, host string) map[string]interface{} {
	netType := link.Network
	if netType == "splithttp" {
		netType = "xhttp"
	}
	if netType == "h2" || netType == "http2" {
		netType = "http"
	}
	if netType == "grpc" {
		return map[string]interface{}{"type": "grpc", "service_name": grpcService(link)}
	}
	transport := map[string]interface{}{"type": netType}
	if netType == "ws" && link.WSMaxEarlyData > 0 {
		transport["max_early_data"] = link.WSMaxEarlyData
		transport["early_data_header_name"] = link.WSEarlyDataHeader
	}
	if link.Path != "" {
		transport["path"] = link.Path
	}
	if host != "" {
		// xhttp uses top-level host; ws/http use headers.Host
		if netType == "xhttp" {
			transport["host"] = host
		} else if netType == "http" {
			transport["host"] = strings.Split(host, ",")
		} else {
			transport["headers"] = map[string]interface{}{"Host": host}
		}
	}
	if netType == "xhttp" {
		if link.TransportMode != "" {
			transport["mode"] = link.TransportMode
		}
		if extra := parseExtraJSON(link.ExtraJSON); len(extra) > 0 {
			transport["extra"] = extra
		}
	}
	return transport
}

// parseExtraJSON decodes the URI extra= payload into a map for engine configs.
func parseExtraJSON(raw string) map[string]interface{} {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil
	}
	return m
}

// xrayStreamNetwork applies network-specific streamSettings (ws, xhttp/splithttp, grpc, h2).
func xrayStreamNetwork(stream map[string]interface{}, link *profile.Link) {
	netType := link.Network
	if netType == "" {
		netType = "tcp"
	}
	// Canonical name for Xray 24.12+: xhttp (splithttp still accepted as alias on some builds)
	if netType == "splithttp" {
		netType = "xhttp"
	}
	if netType == "h2" || netType == "http2" {
		netType = "http"
	}
	stream["network"] = netType

	switch netType {
	case "ws":
		ws := map[string]interface{}{}
		if link.Path != "" {
			ws["path"] = link.Path
		}
		if link.Host != "" {
			// xray 25.x: Host is top-level (headers.Host deprecated)
			ws["host"] = link.Host
		}
		if link.WSMaxEarlyData > 0 {
			ws["maxEarlyData"] = link.WSMaxEarlyData
			ws["earlyDataHeaderName"] = link.WSEarlyDataHeader
		}
		stream["wsSettings"] = ws
	case "xhttp":
		xh := map[string]interface{}{}
		if link.Path != "" {
			xh["path"] = link.Path
		}
		if link.Host != "" {
			xh["host"] = link.Host
		}
		if link.TransportMode != "" {
			xh["mode"] = link.TransportMode
		}
		if extra := parseExtraJSON(link.ExtraJSON); len(extra) > 0 {
			xh["extra"] = extra
		}
		stream["xhttpSettings"] = xh
	case "grpc":
		gs := map[string]interface{}{}
		gs["serviceName"] = grpcService(link)
		gs["multiMode"] = link.GRPCMultiMode
		if link.Host != "" {
			gs["authority"] = link.Host
		}
		stream["grpcSettings"] = gs
	case "h2", "http":
		h2 := map[string]interface{}{}
		if link.Path != "" {
			h2["path"] = link.Path
		}
		if link.Host != "" {
			h2["host"] = []string{link.Host}
		}
		stream["httpSettings"] = h2
	}
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

	// OpenVPN always keeps DNS inside the tunnel (except the endpoint hostname),
	// so the plain direct-DNS fallback would leak queries.
	if !cg.GatewayMode && len(geositeCountries) == 0 && len(cg.RoutingRules) == 0 && len(cg.LocalDNSRules) == 0 &&
		(link == nil || link.Protocol != "openvpn") {
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
				// A DNS rule may only reference a rule_set that the route section
				// actually defines; an invalid asset is dropped from both.
				if tag := geoRuleSetTag("geosite", val); tag != "" {
					dnsRules = append(dnsRules, map[string]interface{}{
						"rule_set": []string{tag},
						"server":   "dns-direct",
					})
				}
			case "geoip":
				if tag := geoRuleSetTag("geoip", val); tag != "" {
					dnsRules = append(dnsRules, map[string]interface{}{
						"rule_set": []string{tag},
						"server":   "dns-direct",
					})
				}
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
		// Legacy whitelist mode: geosite rule_sets → dns-direct.
		// Only reference tags the route section will define: legacy route builds
		// geosite rule_sets from GeositeCountries alone. Falling back to
		// WhitelistCountries here referenced tags that were never defined, which
		// makes sing-box reject the entire config.
		var ruleSetTags []string
		for _, country := range cg.GeositeCountries {
			if tag := geoRuleSetTag("geosite", country); tag != "" {
				ruleSetTags = append(ruleSetTags, tag)
			}
		}
		if len(ruleSetTags) > 0 {
			dnsRules = append(dnsRules, map[string]interface{}{
				"rule_set": ruleSetTags,
				"server":   "dns-direct",
			})
		}
	}

	// Local DNS rules: route specific domain suffixes to a local DNS server (e.g. .home → 192.0.2.53).
	// These rules are inserted BEFORE other direct rules so .home doesn't fall through to dns-tunnel.
	// Local DNS servers use plain UDP — they're on the LAN, no need for encrypted DNS.
	localDNSRules := make([]map[string]interface{}, 0, len(cg.LocalDNSRules))
	for i, rule := range cg.LocalDNSRules {
		if rule.Server == "" || len(rule.Domains) == 0 {
			continue
		}
		tag := localDNSTag(i)
		servers = append(servers, map[string]interface{}{
			"tag":         tag,
			"type":        "udp",
			"server":      rule.Server,
			"server_port": 53,
		})
		localDNSRules = append(localDNSRules, map[string]interface{}{
			"domain_suffix": rule.Domains,
			"server":        tag,
		})
	}
	// Local DNS rules come first so private TLDs are resolved before the catch-all tunnel rule.
	if len(localDNSRules) > 0 {
		dnsRules = append(localDNSRules, dnsRules...)
	}

	// The map snapshotted the slice before the dns-local-N servers were appended.
	dns["servers"] = servers

	if len(dnsRules) > 0 {
		dns["rules"] = dnsRules
	}

	// In gateway mode, DNS listen is handled via a separate inbound
	// (sing-box 1.12+ removed dns.listen/listen_port fields)

	return dns
}

func localDNSTag(i int) string { return fmt.Sprintf("dns-local-%d", i) }

// localDNSResolveRules pins connection-time resolution of each local_dns suffix
// to its declared server. The route catch-all resolve runs before the DNS rules
// are consulted, so without these the suffix would still be sent to the tunnel
// resolver even though its server entry exists.
func (cg *ConfigGenerator) localDNSResolveRules() []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(cg.LocalDNSRules))
	for i, rule := range cg.LocalDNSRules {
		if rule.Server == "" || len(rule.Domains) == 0 {
			continue
		}
		out = append(out, map[string]interface{}{
			"domain_suffix": rule.Domains,
			"action":        "resolve",
			"server":        localDNSTag(i),
		})
	}
	return out
}

// localDNSSuffixes flattens every usable local_dns domain, in declaration order.
func (cg *ConfigGenerator) localDNSSuffixes() []string {
	var out []string
	seen := map[string]bool{}
	for _, rule := range cg.LocalDNSRules {
		if rule.Server == "" {
			continue
		}
		for _, d := range rule.Domains {
			d = strings.TrimSpace(d)
			if d == "" || seen[d] {
				continue
			}
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// tunnelResolveRule resolves the destinations the local resolvers did not.
// A resolve action re-resolves an already-resolved destination, so this
// catch-all has to exclude the local suffixes: otherwise the home answer is
// replaced by the tunnel resolver's, and the connection fails outright when
// that resolver is unreachable.
func (cg *ConfigGenerator) tunnelResolveRule(server string) map[string]interface{} {
	rule := map[string]interface{}{
		"action": "resolve",
		"server": server,
	}
	if suffixes := cg.localDNSSuffixes(); len(suffixes) > 0 {
		rule["invert"] = true
		rule["domain_suffix"] = suffixes
	}
	return rule
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

// geoRuleSetTag returns the rule_set tag for a local .srs asset, or "" when the
// asset is missing, truncated or not a binary rule set. Validity — not bare
// existence — decides, because sing-box refuses the whole config when a
// referenced rule_set cannot be loaded. Dropping a DIRECT rule lets the traffic
// fall through to the proxy, so an unusable asset narrows direct routing
// instead of leaking it.
func geoRuleSetTag(kind, name string) string {
	p := filepath.Join(paths.Get().GeoDir, fmt.Sprintf("%s-%s.srs", kind, name))
	if !geo.ValidSRSFile(p) {
		return ""
	}
	return fmt.Sprintf("%s-%s", kind, name)
}

// geoRuleSetDefinition builds the local binary rule_set entry for a tag that
// geoRuleSetTag has already validated.
func geoRuleSetDefinition(tag string) map[string]interface{} {
	return map[string]interface{}{
		"type":   "local",
		"tag":    tag,
		"format": "binary",
		"path":   filepath.Join(paths.Get().GeoDir, tag+".srs"),
	}
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
	rules = append(rules, cg.localDNSResolveRules()...)
	// resolve action: translate domain names to IPs so that IP-based rules (geoip, ip_cidr)
	// can match. Uses dns-tunnel (DoH via proxy) to bypass ISP DNS poisoning — blocked sites
	// return bogon/private IPs from local DNS, which would incorrectly match ip_is_private.
	// Proxy server domains are pinned to IPs in /etc/hosts so no bootstrap loop occurs.
	rules = append(rules, cg.tunnelResolveRule("dns-tunnel"))
	rules = append(rules, map[string]interface{}{
		"ip_is_private": true,
		"action":        "route",
		"outbound":      "direct",
	})

	// Local DNS domains (e.g. .home, .lan) → direct before applying user routing rules.
	for _, rule := range cg.LocalDNSRules {
		if len(rule.Domains) == 0 {
			continue
		}
		rules = append(rules, map[string]interface{}{
			"domain_suffix": rule.Domains,
			"action":        "route",
			"outbound":      "direct",
		})
	}

	finalDeny := false
	for _, rule := range cg.RoutingRules {
		if rule.Match == "default" {
			if isDenyOutbound(rule.Outbound) {
				finalDeny = true
				continue
			}
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
	if finalDeny {
		// sing-box's route.final must name an outbound tag, so a denied default
		// is expressed as a matcher-less reject rule. It is appended after every
		// user rule and still leaves "proxy" as a defined final, which the
		// reject rule always preempts.
		finalOutbound = "proxy"
		rules = append(rules, map[string]interface{}{"action": "reject"})
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
	rule := map[string]interface{}{}
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
	if isDenyOutbound(outbound) {
		rule["action"] = "reject"
		return rule
	}
	rule["action"] = "route"
	rule["outbound"] = outbound
	return rule
}

// isDenyOutbound treats every documented denial spelling as a drop. A deny rule
// must never be emitted as a route to a named outbound: an unknown tag would
// make sing-box refuse the config, and silently rewriting it to direct would be
// a leak.
func isDenyOutbound(outbound string) bool {
	switch strings.ToLower(strings.TrimSpace(outbound)) {
	case "deny", "block", "reject":
		return true
	}
	return false
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
	case "geoip", "geosite":
		tag := geoRuleSetTag(typ, val)
		if tag == "" {
			log.Printf("⚠️  %s-%s.srs is missing or not a binary rule set — %s:%s stays proxied; run 'bypath geo update' or wait for auto-download", typ, val, typ, val)
			return nil
		}
		return geoRuleSetDefinition(tag)
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
	rules = append(rules, cg.localDNSResolveRules()...)
	// resolve: translate domain names to IPs before IP-based rules (geoip, ip_cidr).
	// Must use dns-direct — UDP DNS via a WebSocket/TCP proxy doesn't work.
	rules = append(rules, cg.tunnelResolveRule("dns-direct"))

	// Rule: force proxy domains — always tunnel these, even if IP is in a whitelisted country.
	// Must come before bypass_domains and geoip/geosite direct rules.
	if len(cg.ForceProxyDomains) > 0 {
		rules = append(rules, map[string]interface{}{
			"domain_suffix": cg.ForceProxyDomains,
			"action":        "route",
			"outbound":      "proxy",
		})
	}

	// Rule: local DNS domains (e.g. .home, .lan) → direct (they live on the LAN, not the internet).
	for _, rule := range cg.LocalDNSRules {
		if len(rule.Domains) == 0 {
			continue
		}
		rules = append(rules, map[string]interface{}{
			"domain_suffix": rule.Domains,
			"action":        "route",
			"outbound":      "direct",
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

	// Geo rule sets decide DIRECT egress, so one validated list feeds both the
	// rules and their definitions: an asset that is absent, truncated or not
	// binary is dropped from both, because sing-box rejects a config that
	// references a rule_set it cannot load. The dropped rule's traffic falls
	// through to the proxy — a narrower DIRECT route, never a leak.
	var geositeTags []string
	for _, country := range cg.GeositeCountries {
		tag := geoRuleSetTag("geosite", country)
		if tag == "" {
			log.Printf("⚠️  geosite-%s.srs is missing or not a binary rule set — geosite:%s stays proxied; run 'bypath geo update' or wait for auto-download", country, country)
			continue
		}
		geositeTags = append(geositeTags, tag)
	}

	var geoipTags []string
	for _, country := range cg.WhitelistCountries {
		tag := geoRuleSetTag("geoip", country)
		if tag == "" {
			log.Printf("⚠️  geoip-%s.srs is missing or not a binary rule set — geoip:%s stays proxied; run 'bypath geo update' or wait for auto-download", country, country)
			continue
		}
		geoipTags = append(geoipTags, tag)
	}

	// Rule: geosite domain whitelist → direct (must come before geoip)
	if len(geositeTags) > 0 {
		rules = append(rules, map[string]interface{}{
			"rule_set": geositeTags,
			"action":   "route",
			"outbound": "direct",
		})
	}

	// Rule: whitelisted countries → direct (using local geoip rule_set)
	if len(geoipTags) > 0 {
		rules = append(rules, map[string]interface{}{
			"rule_set": geoipTags,
			"action":   "route",
			"outbound": "direct",
		})
	}

	// Build rule_set definitions (local .srs files) — exactly the validated tags.
	var ruleSets []map[string]interface{}
	for _, tag := range append(append([]string{}, geositeTags...), geoipTags...) {
		ruleSets = append(ruleSets, geoRuleSetDefinition(tag))
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
	if cg.GatewayMode || len(cg.RoutingRules) > 0 || len(cg.WhitelistCountries) > 0 || len(cg.BypassDomains) > 0 || len(cg.GeositeCountries) > 0 || len(cg.LocalDNSRules) > 0 {
		cfg["route"] = cg.singboxRoute(link)
		cfg["dns"] = cg.singboxDNS(link)
	}

	return cg.writeJSON("singbox", cfg)
}

// singboxInboundsGateway returns inbounds for gateway mode: a TUN inbound for
// transparent traffic capture plus the standard Mixed inbound for local
// SOCKS5/HTTP proxy. DNS is served by bypath's own resolver on port 53 for
// every engine, so sing-box must not bind it.
func (cg *ConfigGenerator) singboxInboundsGateway(link *profile.Link) []map[string]interface{} {
	tunInbound := map[string]interface{}{
		"type":       "tun",
		"tag":        "tun-in",
		"address":    []string{"10.0.0.1/30"},
		"auto_route": true,
		"stack":      "system",
		// bypath reserves these values before the engine starts and records
		// ownership first, so native routing has a deterministic, recoverable
		// footprint. The engine's own defaults are not used.
		"iproute2_table_index": NativeRouteTable,
		"iproute2_rule_index":  NativeRuleIndex,
	}

	// Combine TUN + Mixed inbounds
	inbounds := []map[string]interface{}{tunInbound}
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

	inbound := map[string]interface{}{
		"type":        "mixed",
		"tag":         "mixed-in",
		"listen":      cg.socksListenAddr(),
		"listen_port": listenPort,
	}
	if user, pass, ok := cg.sockAuth(); ok {
		inbound["users"] = []map[string]interface{}{{"username": user, "password": pass}}
	}
	inbounds := []map[string]interface{}{inbound}
	// A specific LAN bind does not cover loopback; daemon DNS/probes/subs
	// deliberately stay on 127.0.0.1 and must not depend on LAN routing.
	if cg.socksListenAddr() != "127.0.0.1" && cg.socksListenAddr() != "0.0.0.0" {
		local := make(map[string]interface{}, len(inbound))
		for key, value := range inbound {
			local[key] = value
		}
		local["listen"], local["tag"] = "127.0.0.1", "mixed-local"
		inbounds = append(inbounds, local)
	}
	return inbounds
}

func (cg *ConfigGenerator) singboxOutbounds(link *profile.Link) []map[string]interface{} {
	// OpenVPN profiles define their tunnel as an endpoint tagged "proxy"; adding
	// an outbound with the same tag would be a duplicate.
	if link.Protocol == "openvpn" {
		outbounds := []map[string]interface{}{{"type": "direct", "tag": "direct"}}
		return append(outbounds, cg.singboxExternalOutbounds()...)
	}

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
// Problem: some networks poison UDP DNS for blocked sites (returning fake IPs in
// private ranges).
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

	// Local DNS rules: route private TLDs (e.g. .home, .lan) to the home DNS server.
	// Must come first so these domains don't fall through to the proxy DNS.
	for _, rule := range cg.LocalDNSRules {
		if rule.Server == "" || len(rule.Domains) == 0 {
			continue
		}
		domains := make([]string, len(rule.Domains))
		for j, d := range rule.Domains {
			domains[j] = "domain:" + d
		}
		servers = append(servers, map[string]interface{}{
			"address": rule.Server,
			"domains": domains,
		})
	}

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

	socksSettings := map[string]interface{}{
		"auth": "noauth",
		"udp":  true,
	}
	if user, pass, ok := cg.sockAuth(); ok {
		socksSettings["auth"] = "password"
		socksSettings["accounts"] = []map[string]interface{}{{"user": user, "pass": pass}}
	}

	cfg := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"dns": cg.xrayDNSConfig(link),
		"inbounds": []map[string]interface{}{
			{
				"port":     listenPort,
				"listen":   cg.socksListenAddr(),
				"protocol": "socks",
				"settings": socksSettings,
				"sniffing": map[string]interface{}{
					"enabled":      true,
					"destOverride": []string{"http", "tls"},
					"routeOnly":    true,
				},
			},
		},
		"outbounds": cg.xrayOutbounds(link),
	}

	if cg.socksListenAddr() != "127.0.0.1" && cg.socksListenAddr() != "0.0.0.0" {
		inbounds := cfg["inbounds"].([]map[string]interface{})
		local := make(map[string]interface{}, len(inbounds[0]))
		for key, value := range inbounds[0] {
			local[key] = value
		}
		local["listen"], local["tag"] = "127.0.0.1", "socks-local"
		cfg["inbounds"] = append(inbounds, local)
	}

	// Append external outbounds (referenced by routing rules or used manually)
	if len(cg.ExternalOutbounds) > 0 {
		existing := cfg["outbounds"].([]map[string]interface{})
		cfg["outbounds"] = append(existing, cg.xrayExternalOutbounds()...)
	}

	// Add routing: prefer new rule-based system, fall back to legacy whitelist config.
	// Both shapes come from one plan so the panel's explanation matches the
	// engine config that is actually generated.
	if len(cg.RoutingRules) > 0 || len(cg.WhitelistCountries) > 0 || len(cg.BypassDomains) > 0 || len(cg.ForceProxyDomains) > 0 {
		cfg["routing"] = cg.xrayRoutingSection()
	}

	return cg.writeJSON("xray", cfg)
}

// xrayGeoAssetPath returns the .dat file xray would load for name, searching
// bypath's provisioning directories first and then xray's standard locations.
func xrayGeoAssetPath(name string) string {
	for _, dir := range []string{paths.Get().EngineDir, paths.Get().GeoDir} {
		if p := geo.FindXrayAsset(dir, name); p != "" {
			return p
		}
	}
	return ""
}

// xrayGeoipAvailable reports whether geoip.dat exists AND contains the country.
// xray aborts instance startup when a rule references a missing category, so a
// bare "file exists" check is not enough: the file must also carry the code.
func xrayGeoipAvailable(country string) bool {
	p := xrayGeoAssetPath("geoip.dat")
	if p == "" {
		return false
	}
	return geo.HasXrayCategory(p, strings.ToUpper(country))
}

// xrayGeositeTag resolves the tag spelling used by the installed geosite.dat.
// A rule written as geosite:cc must work against both v2fly's "CATEGORY-XX" and
// a bare country code entry, and xray only accepts the exact tag present in the file.
func xrayGeositeTag(tag string) (string, bool) {
	p := xrayGeoAssetPath("geosite.dat")
	if p == "" {
		return "", false
	}
	return geo.FindXrayCategory(p, tag)
}

// XrayAssetDir returns the directory that contains xray's geo databases, or ""
// when none is installed. The embedded engine sets xray.location.asset to it so
// xray finds the files bypath provisioned instead of only its executable dir.
func XrayAssetDir() string {
	return geo.FindXrayAssetDir(paths.Get().EngineDir, paths.Get().GeoDir)
}

// xrayRuleFromMatcher converts a match string + outbound to an xray routing
// rule. It is the single-rule form of the plan used by the generator and by
// callers that need to show what one rule compiles to.
func (cg *ConfigGenerator) xrayRuleFromMatcher(match, outbound string) map[string]interface{} {
	entry := cg.planFromRule(-1, RoutingRule{Match: match, Outbound: outbound})
	if entry.Kind == "default" {
		return nil
	}
	if entry.Skip != "" {
		log.Printf("⚠️  routing rule %s: %s; skipping (traffic keeps the default outbound)", planEntryLabel(entry), entry.Skip)
		return nil
	}
	return planEntryToXray(entry)
}

// xrayBlockOutboundTag is the blackhole outbound that implements deny rules.
const xrayBlockOutboundTag = "block"

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

	// Prefer pinned IP when available (same reason as sing-box: DNS bootstrap).
	serverAddr := link.Address
	if ip, ok := cg.PinnedHosts[link.Address]; ok && ip != "" {
		serverAddr = ip
	}

	switch link.Protocol {
	case "vmess":
		vnext := map[string]interface{}{
			"address": serverAddr,
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
		stream := map[string]interface{}{}
		xrayStreamNetwork(stream, link)
		if link.TLS {
			stream["security"] = "tls"
			tlsSettings := map[string]interface{}{
				"serverName":    link.SNI,
				"allowInsecure": link.Insecure,
			}
			if link.Fingerprint != "" {
				tlsSettings["fingerprint"] = link.Fingerprint
			}
			stream["tlsSettings"] = tlsSettings
		}
		outbound["streamSettings"] = stream

	case "vless":
		// Preserve VLESS Encryption verbatim. Xray requires every user to carry
		// an explicit value; only fall back to "none" when the URI had none.
		encryption := link.Encryption
		if encryption == "" {
			encryption = "none"
		}
		vnext := map[string]interface{}{
			"address": serverAddr,
			"port":    link.Port,
			"users": []map[string]interface{}{
				{
					"id":         link.UUID,
					"encryption": encryption,
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
		stream := map[string]interface{}{}
		xrayStreamNetwork(stream, link)
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
				"serverName":    link.SNI,
				"allowInsecure": link.Insecure,
			}
			if link.Fingerprint != "" {
				tlsSettings["fingerprint"] = link.Fingerprint
			}
			stream["tlsSettings"] = tlsSettings
		}
		outbound["streamSettings"] = stream

	case "trojan", "shadowsocks":
		server := map[string]interface{}{"address": serverAddr, "port": link.Port, "password": link.UUID}
		if link.Protocol == "shadowsocks" {
			server["method"] = link.Security
		}
		outbound = map[string]interface{}{"protocol": link.Protocol, "settings": map[string]interface{}{"servers": []map[string]interface{}{server}}}
		stream := map[string]interface{}{}
		xrayStreamNetwork(stream, link)
		outbound["streamSettings"] = stream
	default:
		// Handle socks5 and http protocols for xray
		if link.Protocol == "socks5" || link.Protocol == "socks" {
			outbound = map[string]interface{}{
				"protocol": "socks",
				"settings": map[string]interface{}{
					"servers": []map[string]interface{}{
						{
							"address": serverAddr,
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
							"address": serverAddr,
							"port":    link.Port,
						},
					},
				},
			}
		} else {
			outbound = map[string]interface{}{
				"protocol": "blackhole",
				"settings": map[string]interface{}{},
			}
		}
	}

	if link.Protocol == "socks5" || link.Protocol == "socks" || link.Protocol == "http" {
		if link.UUID != "" {
			servers := outbound["settings"].(map[string]interface{})["servers"].([]map[string]interface{})
			servers[0]["users"] = []map[string]interface{}{{"user": link.UUID, "pass": link.Security}}
		}
	}
	if link.TLS || link.Protocol == "trojan" {
		stream, ok := outbound["streamSettings"].(map[string]interface{})
		if !ok {
			stream = map[string]interface{}{"network": "tcp"}
			outbound["streamSettings"] = stream
		}
		if link.Security != "reality" {
			stream["security"] = "tls"
			stream["tlsSettings"] = xrayTLS(link)
		} else if settings, ok := stream["realitySettings"].(map[string]interface{}); ok && link.RealitySpiderX != "" {
			settings["spiderX"] = link.RealitySpiderX
		}
	}
	outbound["tag"] = "proxy"

	return []map[string]interface{}{
		outbound,
		// UseIPv4: resolve hostname via xray's own DNS before dialing, so the direct
		// outbound never needs system DNS (which bypath sets to 127.0.0.1 in gateway mode).
		{"protocol": "freedom", "tag": "direct", "settings": map[string]interface{}{"domainStrategy": "UseIPv4"}},
		// Deny rules route here. The tag is always defined so a deny rule can never
		// degrade into an unknown-tag startup failure or a silent direct egress.
		{"protocol": "blackhole", "tag": xrayBlockOutboundTag},
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

	dir, err := cg.currentGenDir()
	if err != nil {
		return "", err
	}
	filename := filepath.Join(dir, fmt.Sprintf("wg-%s.conf", sanitizeName(link.Remark)))
	if err := securefile.WriteFile(filename, []byte(conf)); err != nil {
		return "", err
	}
	return filename, nil
}

// --- Helpers ---

// beginGeneration allocates a fresh per-run directory. Directories are created
// under tempDir with a "gen-" prefix so Discard/Cleanup can recognise exactly
// what this generator owns and refuse to delete anything else.
func (cg *ConfigGenerator) beginGeneration() (string, error) {
	if err := securefile.MkdirAll(cg.tempDir); err != nil {
		return "", fmt.Errorf("creating runtime directory: %w", err)
	}
	dir, err := os.MkdirTemp(cg.tempDir, "gen-")
	if err != nil {
		return "", fmt.Errorf("creating generation directory: %w", err)
	}
	if err := securefile.RestrictDir(dir); err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("securing generation directory: %w", err)
	}
	cg.genDir = dir
	cg.genDirs = append(cg.genDirs, dir)
	return dir, nil
}

func (cg *ConfigGenerator) currentGenDir() (string, error) {
	if cg.genDir != "" {
		return cg.genDir, nil
	}
	return cg.beginGeneration()
}

// ownsDir reports whether dir is a generation directory under tempDir.
func (cg *ConfigGenerator) ownsDir(dir string) bool {
	absTemp, err := filepath.Abs(cg.tempDir)
	if err != nil {
		return false
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(absTemp, absDir)
	if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return strings.HasPrefix(filepath.Base(absDir), "gen-")
}

// DiscardGeneration removes the most recent generation directory after a
// failed attempt. It never touches directories outside tempDir/gen-*.
func (cg *ConfigGenerator) DiscardGeneration() {
	if cg.genDir == "" {
		return
	}
	if cg.ownsDir(cg.genDir) {
		os.RemoveAll(cg.genDir)
	}
	cg.genDir = ""
}

// DiscardConfig removes the generation directory containing configFile.
func (cg *ConfigGenerator) DiscardConfig(configFile string) {
	if configFile == "" {
		return
	}
	dir := filepath.Dir(configFile)
	if cg.ownsDir(dir) {
		os.RemoveAll(dir)
	}
}

// Cleanup removes every generation directory this generator created.
func (cg *ConfigGenerator) Cleanup() {
	for _, dir := range cg.genDirs {
		if cg.ownsDir(dir) {
			os.RemoveAll(dir)
		}
	}
	cg.genDirs = nil
	cg.genDir = ""
}

// RemoveGenerationDir removes the generation directory that holds configFile.
// It is used by lifecycle code that no longer has the generator instance.
func RemoveGenerationDir(tempDir, configFile string) {
	if configFile == "" {
		return
	}
	dir := filepath.Dir(configFile)
	absTemp, err := filepath.Abs(tempDir)
	if err != nil {
		return
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return
	}
	rel, err := filepath.Rel(absTemp, absDir)
	if err != nil || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return
	}
	if strings.HasPrefix(filepath.Base(absDir), "gen-") {
		os.RemoveAll(absDir)
	}
}

// RemoveStaleGenerations removes leftover generation directories from earlier
// bypath runs. Only direct children of tempDir whose names start with "gen-"
// are considered; the directory holding keep (the active config, if any) and
// every unrelated entry are left untouched. It returns the number removed.
//
// This is called only after the previous engine has been stopped and reaped, so
// a gen-* directory at that point is provably not in use.
func RemoveStaleGenerations(tempDir, keep string) (int, error) {
	absTemp, err := filepath.Abs(tempDir)
	if err != nil {
		return 0, err
	}
	keepAbs := ""
	if keep != "" {
		if dir := filepath.Dir(keep); dir != "" {
			keepAbs, _ = filepath.Abs(dir)
		}
	}
	entries, err := os.ReadDir(absTemp)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	var errs []error
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "gen-") {
			continue
		}
		path := filepath.Join(absTemp, entry.Name())
		if keepAbs != "" && path == keepAbs {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			errs = append(errs, fmt.Errorf("removing stale generation %s: %w", path, err))
			continue
		}
		removed++
	}
	return removed, errors.Join(errs...)
}

func (cg *ConfigGenerator) writeJSON(prefix string, data interface{}) (string, error) {
	content, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling config: %w", err)
	}

	dir, err := cg.currentGenDir()
	if err != nil {
		return "", err
	}
	filename := filepath.Join(dir, fmt.Sprintf("%s-config.json", prefix))
	// Configs carry UUIDs, REALITY keys and VLESS encryption credentials.
	if err := securefile.WriteFile(filename, content); err != nil {
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
