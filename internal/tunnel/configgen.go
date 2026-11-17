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
	// CountrySplit is an opt-in split for one country: its geoip and geosite
	// categories go DIRECT while every unmatched destination keeps the default
	// outbound. It is emitted after the explicit rules so a user exception can
	// override it, and before the catch-all. Empty disables the split.
	CountrySplit string
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
	// GeoDir and EngineDir override the directories the geo gates inspect. Empty
	// keeps paths.Get(); the app passes its own resolved paths so the plan it
	// shows and the assets it provisions cannot refer to different directories.
	GeoDir    string
	EngineDir string

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
	if eng.Name == "sing-box" || eng.Name == "xray" {
		if err := cg.ValidatePlanForEngine(eng.Name); err != nil {
			return "", err
		}
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
	// Policy rules may name an external outbound, exactly as in a single tunnel.
	outbounds = append(outbounds, cg.singboxExternalOutbounds()...)

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

	// The exit hop plays the role of the "proxy" outbound, so the same plan
	// builder decides DIRECT/PROXY/deny/split for a chain as for a tunnel.
	lastHopTag := fmt.Sprintf("chain-%s-hop-%d", chainName, len(links)-1)
	route := cg.singboxRouteFor(nil, lastHopTag)
	route["auto_detect_interface"] = true

	// DNS follows the same policy: tunneled names resolve over the chain's DoH
	// path (detour = exit hop) instead of a plaintext query, and every hop's
	// server domain resolves directly so the chain can bootstrap.
	dns := cg.singboxDNSFor(lastHopTag, true, links...)

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
	path := link.Path
	earlyData := link.WSMaxEarlyData
	if netType == "ws" {
		// Older profiles persist the request path with its "?ed=NNN" hint.
		// sing-box forwards that path verbatim and the server rejects the
		// upgrade, so translate the hint into the explicit fields.
		if cleaned, ed := profile.SplitWSPathEarlyData(path); ed > 0 {
			path = cleaned
			if earlyData == 0 {
				earlyData = ed
			}
		}
		if earlyData > 0 {
			transport["max_early_data"] = earlyData
			transport["early_data_header_name"] = earlyDataHeader(link.WSEarlyDataHeader)
		}
	}
	if path != "" {
		transport["path"] = path
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

func earlyDataHeader(header string) string {
	if header == "" {
		return profile.EarlyDataHeaderDefault
	}
	return header
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
		path := link.Path
		earlyData := link.WSMaxEarlyData
		if cleaned, ed := profile.SplitWSPathEarlyData(path); ed > 0 {
			path = cleaned
			if earlyData == 0 {
				earlyData = ed
			}
		}
		if path != "" {
			ws["path"] = path
		}
		if link.Host != "" {
			// xray 25.x: Host is top-level (headers.Host deprecated)
			ws["host"] = link.Host
		}
		if earlyData > 0 {
			ws["maxEarlyData"] = earlyData
			ws["earlyDataHeaderName"] = earlyDataHeader(link.WSEarlyDataHeader)
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
	return cg.singboxDNSFor("proxy", false, link)
}

// singboxDNSFor builds the DNS section for a tunnel or a chain. proxyTag is the
// outbound that carries tunneled traffic (the last hop for a chain). Every
// link's server domain resolves via dns-direct, so a chain cannot deadlock on
// resolving the server it needs to reach the resolver. forceSplit skips the
// direct-only fallback because a chain route always contains the dns-tunnel
// resolve and must define that server.
func (cg *ConfigGenerator) singboxDNSFor(proxyTag string, forceSplit bool, links ...*profile.Link) map[string]interface{} {
	// Determine which countries to use for geosite DNS rules.
	// Prefer GeositeCountries; fall back to WhitelistCountries if empty.
	geositeCountries := cg.GeositeCountries
	if len(geositeCountries) == 0 {
		geositeCountries = cg.WhitelistCountries
	}

	openvpn := false
	for _, link := range links {
		if link != nil && link.Protocol == "openvpn" {
			openvpn = true
		}
	}

	// OpenVPN always keeps DNS inside the tunnel (except the endpoint hostname),
	// so the plain direct-DNS fallback would leak queries. A split or a bypass
	// list needs the split resolver too: the route section references dns-tunnel
	// for every name it can proxy, and the simple fallback defines no such
	// server.
	if !forceSplit && !cg.GatewayMode && len(geositeCountries) == 0 && len(cg.RoutingRules) == 0 && len(cg.LocalDNSRules) == 0 &&
		cg.CountrySplit == "" && len(cg.BypassDomains) == 0 && !openvpn {
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
			"detour": proxyTag,
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
		// A name no rule matches takes the plan's default class, so a DIRECT
		// default resolves domestically too.
		"final": dnsServerForClass(cg.defaultNameClass()),
	}

	// Build DNS rules in order: proxy server domains first, then geosite rule_sets.
	var dnsRules []map[string]interface{}

	// Proxy server domains must resolve via dns-direct to prevent a DNS loop:
	// sing-box would otherwise try to resolve the VLESS server domain through
	// the tunnel, which in turn requires the tunnel to be up — a circular dependency.
	seen := map[string]bool{}
	var proxyDomains []string
	for _, link := range links {
		if link == nil {
			continue
		}
		for _, candidate := range []string{link.Address, link.SNI, link.Host} {
			if candidate == "" || seen[candidate] {
				continue
			}
			seen[candidate] = true
			if net.ParseIP(candidate) == nil { // skip bare IPs
				proxyDomains = append(proxyDomains, candidate)
			}
		}
	}
	if len(proxyDomains) > 0 {
		dnsRules = append(dnsRules, map[string]interface{}{
			"domain": proxyDomains,
			"server": "dns-direct",
		})
	}

	// DNS rules follow plan order so the first route rule that can match a name
	// also decides the server that answers it. A proxy exception above a DIRECT
	// class therefore keeps its name off the direct resolver.
	for _, class := range cg.orderedDomainClasses() {
		rule := make(map[string]interface{}, len(class.condition)+1)
		for key, value := range class.condition {
			rule[key] = value
		}
		rule["server"] = dnsServerForClass(class.class)
		dnsRules = append(dnsRules, rule)
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

// domainRouteClass is one domain-shaped plan entry with the class its outbound
// implies. Resolve steps and DNS rules both walk these in plan order, so the
// first route rule that can match a name also decides which resolver answers it.
type domainRouteClass struct {
	condition map[string]interface{}
	class     NameClass
}

// orderedDomainClasses lists the domain-shaped plan entries in the order the
// route section evaluates them. Address-only entries (private, geoip, ip_cidr)
// are omitted because a name cannot be tested against them, and local_dns
// entries are omitted because they already have their own resolve rule and
// server tag.
func (cg *ConfigGenerator) orderedDomainClasses() []domainRouteClass {
	var out []domainRouteClass
	seen := map[string]bool{}
	for _, entry := range cg.SingboxRoutingPlan() {
		if entry.Skip != "" || entry.Scope == "local-dns" || entry.Kind == "default" {
			continue
		}
		condition := domainCondition(entry)
		if condition == nil {
			continue
		}
		// A later entry with the same condition can never match: first-match
		// wins, so the earlier class already claimed the name.
		key := conditionKey(condition)
		if seen[key] {
			continue
		}
		seen[key] = true
		next := domainRouteClass{condition: condition, class: nameClassForOutbound(entry.Outbound)}
		// Consecutive geo categories of one class can share a single step; the
		// merge keeps the config compact without changing first-match order.
		if n := len(out); n > 0 && out[n-1].class == next.class && mergeRuleSets(&out[n-1], next) {
			continue
		}
		out = append(out, next)
	}
	return out
}

// mergeRuleSets folds a geo class into the previous one when both match only a
// rule_set list. It reports whether the merge happened.
func mergeRuleSets(into *domainRouteClass, next domainRouteClass) bool {
	if len(into.condition) != 1 || len(next.condition) != 1 {
		return false
	}
	current, ok := into.condition["rule_set"].([]string)
	if !ok {
		return false
	}
	added, ok := next.condition["rule_set"].([]string)
	if !ok {
		return false
	}
	merged := append(append([]string(nil), current...), added...)
	seen := map[string]bool{}
	unique := merged[:0]
	for _, tag := range merged {
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		unique = append(unique, tag)
	}
	into.condition["rule_set"] = unique
	return true
}

func conditionKey(condition map[string]interface{}) string {
	var parts []string
	for _, key := range []string{"rule_set", "domain", "domain_suffix"} {
		if values, ok := condition[key].([]string); ok {
			parts = append(parts, key+"="+strings.Join(values, ","))
		}
	}
	return strings.Join(parts, "&")
}

func domainCondition(entry PlanEntry) map[string]interface{} {
	switch entry.Kind {
	case "domain":
		return map[string]interface{}{"domain": []string{entry.Value}}
	case "domain_suffix":
		return map[string]interface{}{"domain_suffix": []string{entry.Value}}
	case "domain_suffix_list":
		if len(entry.Domains) == 0 {
			return nil
		}
		return map[string]interface{}{"domain_suffix": append([]string(nil), entry.Domains...)}
	case "geosite":
		tag := entry.Resolved
		if tag == "" {
			tag = "geosite-" + entry.Value
		}
		return map[string]interface{}{"rule_set": []string{tag}}
	}
	return nil
}

// defaultNameClass is the class the plan gives a name no entry matches.
func (cg *ConfigGenerator) defaultNameClass() NameClass {
	for _, entry := range cg.SingboxRoutingPlan() {
		if entry.Kind == "default" {
			return nameClassForOutbound(entry.Outbound)
		}
	}
	return NameClassProxy
}

// dnsServerForClass names the resolver a class owns. A blocked destination is
// never dialed; it is resolved like proxied traffic so the name is not disclosed
// to the direct resolver.
func dnsServerForClass(class NameClass) string {
	if class == NameClassDirect {
		return "dns-direct"
	}
	return "dns-tunnel"
}

// domainResolveRules pins connection-time resolution of every domain class to
// the resolver that class owns. The steps follow plan order and each one
// excludes the classes above it, because sing-box applies every matching resolve
// action: without the exclusion a later class would overwrite an earlier
// decision, and a name its first route rule sends to the proxy would be queried
// on the direct resolver in plaintext.
func (cg *ConfigGenerator) domainResolveRules() []map[string]interface{} {
	classes := cg.orderedDomainClasses()
	var earlier []map[string]interface{}
	if suffixes := cg.localDNSSuffixes(); len(suffixes) > 0 {
		earlier = append(earlier, map[string]interface{}{"domain_suffix": suffixes})
	}
	rules := make([]map[string]interface{}, 0, len(classes)+1)
	for _, class := range classes {
		if coveredByEarlier(class.condition, earlier) {
			// A local_dns suffix, or an earlier identical class, already claims
			// this name; a resolve step here would never match.
			continue
		}
		if class.class == NameClassBlock {
			// A blocked destination is never dialed, so resolving it would only
			// disclose the name. It still claims the name for later classes.
			earlier = append(earlier, class.condition)
			continue
		}
		step := excludeEarlier(class.condition, earlier)
		step["action"] = "resolve"
		step["server"] = dnsServerForClass(class.class)
		rules = append(rules, step)
		earlier = append(earlier, class.condition)
	}
	fallback := excludeEarlier(map[string]interface{}{}, earlier)
	fallback["action"] = "resolve"
	fallback["server"] = dnsServerForClass(cg.defaultNameClass())
	return append(rules, fallback)
}

// coveredByEarlier reports whether every value of a single-value condition was
// already claimed by an earlier condition on the same field. Such a class can
// never match under first-match-wins.
func coveredByEarlier(condition map[string]interface{}, earlier []map[string]interface{}) bool {
	if len(condition) != 1 {
		return false
	}
	for _, key := range []string{"domain_suffix", "domain", "rule_set"} {
		values, ok := condition[key].([]string)
		if !ok || len(values) == 0 {
			continue
		}
		for _, prior := range earlier {
			priorValues, ok := prior[key].([]string)
			if !ok {
				continue
			}
			all := true
			for _, value := range values {
				found := false
				for _, priorValue := range priorValues {
					if priorValue == value {
						found = true
						break
					}
				}
				if !found {
					all = false
					break
				}
			}
			if all {
				return true
			}
		}
	}
	return false
}

// excludeEarlier returns a rule matching base unless an earlier class already
// matched. sing-box ANDs the conditions of one rule, so the exclusion becomes
// AND(base, NOT(OR(earlier))).
func excludeEarlier(base map[string]interface{}, earlier []map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(base)+4)
	for key, value := range base {
		out[key] = value
	}
	if len(earlier) == 0 {
		return out
	}
	var notEarlier map[string]interface{}
	if len(earlier) == 1 {
		notEarlier = map[string]interface{}{"invert": true}
		for key, value := range earlier[0] {
			notEarlier[key] = value
		}
	} else {
		notEarlier = map[string]interface{}{
			"type":   "logical",
			"mode":   "or",
			"invert": true,
			"rules":  earlier,
		}
	}
	if len(out) == 0 {
		return notEarlier
	}
	return map[string]interface{}{
		"type":  "logical",
		"mode":  "and",
		"rules": []map[string]interface{}{out, notEarlier},
	}
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
// asset cannot be loaded by sing-box's own reader (missing, truncated, HTML,
// unsupported version). Validity — not bare existence — decides, because
// sing-box refuses the whole config when a referenced rule_set cannot be
// loaded. Dropping a DIRECT rule lets the traffic fall through to the proxy, so
// an unusable asset narrows direct routing instead of leaking it.
func (cg *ConfigGenerator) geoRuleSetTag(kind, name string) string {
	p := filepath.Join(cg.geoDir(), fmt.Sprintf("%s-%s.srs", kind, name))
	if !geo.ValidSRSFile(p) {
		return ""
	}
	return fmt.Sprintf("%s-%s", kind, name)
}

// geoRuleSetDefinition builds the local binary rule_set entry for a tag that
// geoRuleSetTag has already validated.
func (cg *ConfigGenerator) geoRuleSetDefinition(tag string) map[string]interface{} {
	return map[string]interface{}{
		"type":   "local",
		"tag":    tag,
		"format": "binary",
		"path":   filepath.Join(cg.geoDir(), tag+".srs"),
	}
}

// geoDir is the directory holding per-country .srs rule sets.
func (cg *ConfigGenerator) geoDir() string {
	if cg.GeoDir != "" {
		return cg.GeoDir
	}
	return paths.Get().GeoDir
}

// engineDir is the directory holding the engine binary and its xray .dat assets.
func (cg *ConfigGenerator) engineDir() string {
	if cg.EngineDir != "" {
		return cg.EngineDir
	}
	return paths.Get().EngineDir
}

// tunnelTag resolves the policy name "proxy" to the outbound tag that carries
// tunneled traffic: "proxy" itself for a single tunnel, the exit hop for a
// chain. Every other name is already an engine tag.
func tunnelTag(name, proxyTag string) string {
	if name == "proxy" {
		return proxyTag
	}
	return name
}

// singboxRouteFromRules builds the sing-box route section from RoutingRules.
// Private IPs always go direct. Rules are evaluated in order; "default" sets the final outbound.
func (cg *ConfigGenerator) singboxRouteFromRules() map[string]interface{} {
	return cg.singboxRouteFromRulesFor("proxy")
}

// singboxRouteFromRulesFor renders the rules path with proxyTag standing in for
// the policy name "proxy". A single tunnel uses the literal outbound tag; a
// chain uses its exit hop, so one policy drives both shapes identically.
func (cg *ConfigGenerator) singboxRouteFromRulesFor(proxyTag string) map[string]interface{} {
	var rules []map[string]interface{}
	seenRuleSets := map[string]bool{}
	var ruleSets []map[string]interface{}
	finalOutbound := proxyTag

	rules = append(rules, map[string]interface{}{
		"action":  "sniff",
		"timeout": "300ms",
	})
	rules = append(rules, cg.localDNSResolveRules()...)
	// Resolve every domain class with the resolver it owns, in plan order. A
	// DIRECT name keeps the direct answer; every other name resolves through the
	// tunnel's DoH, which survives TCP-only transports (dns-direct is plaintext
	// UDP) and returns the uncensored answer for ISP-poisoned names.
	rules = append(rules, cg.domainResolveRules()...)
	rules = append(rules, map[string]interface{}{
		"ip_is_private": true,
		"action":        "route",
		"outbound":      "direct",
	})
	// Startup health probes are forced through the tunnel here so no operator or
	// country DIRECT rule can make them verify the direct path instead.
	rules = append(rules, singboxProbeRule(proxyTag))

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
			finalOutbound = tunnelTag(rule.Outbound, proxyTag)
			continue
		}
		sbRule := cg.singboxRuleFromMatcher(rule.Match, tunnelTag(rule.Outbound, proxyTag))
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

	// Opt-in country split. These rules follow the explicit user rules so an
	// operator exception still wins, and they are omitted (not faked) when the
	// rule set is unusable: that traffic then stays on the default outbound
	// instead of being sent direct on incomplete data.
	for _, matcher := range cg.countrySplitMatchers() {
		sbRule := cg.singboxRuleFromMatcher(matcher, "direct")
		if sbRule == nil {
			continue
		}
		rules = append(rules, sbRule)
		if rs := cg.ruleSetForMatcher(matcher); rs != nil {
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
		finalOutbound = proxyTag
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

// singboxProbeRule routes the startup health-probe hosts through the tunnel.
// It is emitted before operator and country DIRECT rules on purpose.
func singboxProbeRule(outbound string) map[string]interface{} {
	return map[string]interface{}{
		"domain_suffix": append([]string(nil), StartupProbeDomains...),
		"action":        "route",
		"outbound":      outbound,
	}
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
		tag := cg.geoRuleSetTag(typ, val)
		if tag == "" {
			log.Printf("⚠️  %s-%s.srs is missing or not a binary rule set — %s:%s stays proxied; run 'bypath geo update' or wait for auto-download", typ, val, typ, val)
			return nil
		}
		return cg.geoRuleSetDefinition(tag)
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
	return cg.singboxRouteFor(link, "proxy")
}

// singboxRouteFor is singboxRoute with proxyTag in place of the policy name
// "proxy": the literal outbound for a tunnel, the exit hop for a chain.
func (cg *ConfigGenerator) singboxRouteFor(link *profile.Link, proxyTag string) map[string]interface{} {
	if len(cg.RoutingRules) > 0 {
		return cg.singboxRouteFromRulesFor(proxyTag)
	}
	var rules []map[string]interface{}

	// Rule: sniff to detect domain from TLS/HTTP
	rules = append(rules, map[string]interface{}{
		"action":  "sniff",
		"timeout": "300ms",
	})
	rules = append(rules, cg.localDNSResolveRules()...)
	// Resolve each name with the resolver its plan class owns. A proxy domain
	// listed above a bypass rule therefore keeps its query on the tunnel.
	rules = append(rules, cg.domainResolveRules()...)

	// Rule: startup health probes — always tunnel these, so the startup HTTPS
	// check verifies the tunnel even when a bypass or country list says DIRECT.
	rules = append(rules, singboxProbeRule(proxyTag))

	// Rule: force proxy domains — always tunnel these, even if IP is in a whitelisted country.
	// Must come before bypass_domains and geoip/geosite direct rules.
	if len(cg.ForceProxyDomains) > 0 {
		rules = append(rules, map[string]interface{}{
			"domain_suffix": cg.ForceProxyDomains,
			"action":        "route",
			"outbound":      proxyTag,
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
		tag := cg.geoRuleSetTag("geosite", country)
		if tag == "" {
			log.Printf("⚠️  geosite-%s.srs is missing or not loadable — geosite:%s stays proxied; run 'bypath geo update' or wait for auto-download", country, country)
			continue
		}
		geositeTags = append(geositeTags, tag)
	}

	var geoipTags []string
	for _, country := range cg.WhitelistCountries {
		tag := cg.geoRuleSetTag("geoip", country)
		if tag == "" {
			log.Printf("⚠️  geoip-%s.srs is missing or not loadable — geoip:%s stays proxied; run 'bypath geo update' or wait for auto-download", country, country)
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
	seenTags := map[string]bool{}
	for _, tag := range append(append([]string{}, geositeTags...), geoipTags...) {
		ruleSets = append(ruleSets, cg.geoRuleSetDefinition(tag))
		seenTags[tag] = true
	}

	// Opt-in country split on the legacy field path. It follows the whitelist
	// lists and keeps the same fail-closed rule: an unusable asset drops the
	// DIRECT rule, so that traffic falls through to the proxy.
	for _, matcher := range cg.countrySplitMatchers() {
		sbRule := cg.singboxRuleFromMatcher(matcher, "direct")
		if sbRule == nil {
			continue
		}
		kind, value, _ := strings.Cut(matcher, ":")
		tag := cg.geoRuleSetTag(kind, value)
		if seenTags[tag] {
			continue
		}
		seenTags[tag] = true
		rules = append(rules, sbRule)
		ruleSets = append(ruleSets, cg.geoRuleSetDefinition(tag))
	}

	route := map[string]interface{}{
		"rules":                   rules,
		"final":                   proxyTag,
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
	if cg.GatewayMode || len(cg.RoutingRules) > 0 || cg.CountrySplit != "" || len(cg.WhitelistCountries) > 0 || len(cg.BypassDomains) > 0 || len(cg.GeositeCountries) > 0 || len(cg.LocalDNSRules) > 0 {
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
// xray has no per-server "send this resolver through the tunnel" switch: every
// https resolver is dialed through the router, so an entry that is merely
// labelled direct is still dispatched to outbounds[0] (the proxy). The section
// therefore defines exactly one resolver path, a DoH endpoint that the router
// sends to the proxy (xrayTunnelResolverRule pins it), plus name-scoped servers
// for the names that must not take that path:
//
//   - local_dns suffixes → their declared home DNS server;
//   - the proxy server's own names → a direct DoH bootstrap. They are already
//     pinned in /etc/hosts by bypath, so this entry is belt and suspenders.
//
// disableFallback keeps the scoped servers out of the fallback chain, and
// skipFallback keeps them out of it even if a future caller drops that flag.
// Without both, xray asks every non-matching server for every name, and a
// local_dns server receives every proxied name in plaintext (R2-03).
//
// There is deliberately no direct-class resolver: a "direct" entry would still
// be dispatched through the proxy. country_split is refused for xray in
// generateXray rather than pretending the split resolves locally here.
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

	// Names that must resolve without going through the proxy. Proxy-server names
	// are already in /etc/hosts (pinned by bypath), so direct DoH here is a
	// belt-and-suspenders fallback.
	bootstrapDomains := []string{}
	seen := map[string]bool{}
	for _, h := range []string{link.Address, link.SNI, link.Host} {
		h = strings.TrimSpace(h)
		if h != "" && !seen[h] {
			bootstrapDomains = append(bootstrapDomains, "full:"+h)
			seen[h] = true
		}
	}

	// The tunnel resolver is listed first: when no scoped server matches and
	// disableFallback suppressed the fallback chain, xray uses the first client.
	servers := []interface{}{
		map[string]interface{}{
			"address":      proxyUpstreamDoH,
			"skipFallback": true,
		},
	}

	// Local DNS rules: route private TLDs (e.g. .home, .lan) to the home DNS server.
	for _, rule := range cg.LocalDNSRules {
		if rule.Server == "" || len(rule.Domains) == 0 {
			continue
		}
		domains := make([]string, len(rule.Domains))
		for j, d := range rule.Domains {
			domains[j] = "domain:" + d
		}
		servers = append(servers, map[string]interface{}{
			"address":      rule.Server,
			"domains":      domains,
			"skipFallback": true,
		})
	}

	// Bootstrap domains → direct DoH (no proxy).
	if len(bootstrapDomains) > 0 {
		servers = append(servers, map[string]interface{}{
			"address":      upstreamDoH,
			"domains":      bootstrapDomains,
			"skipFallback": true,
		})
	}

	return map[string]interface{}{
		"servers":         servers,
		"queryStrategy":   "UseIPv4",
		"disableFallback": true,
	}
}

// tunnelResolverEndpoint returns the host part of the DoH endpoint that the
// router must send to the proxy, and whether it is an IP literal. A URL
// hostname is returned too: the pin still applies once xray has resolved it.
func (cg *ConfigGenerator) tunnelResolverEndpoint() (host string, isIP bool) {
	proxyUpstream := cg.proxyDNSServer()
	if strings.HasPrefix(proxyUpstream, "http://") || strings.HasPrefix(proxyUpstream, "https://") {
		if u, err := url.Parse(proxyUpstream); err == nil {
			host = u.Hostname()
		}
	} else if h, _, err := net.SplitHostPort(proxyUpstream); err == nil {
		host = h
	} else {
		host = proxyUpstream
	}
	host = strings.TrimSpace(host)
	return host, net.ParseIP(host) != nil
}

// xraySplitRefusal explains why the country split is not generated for xray.
// xray's DNS module is independent of its router: a resolver entry cannot be
// scoped to the proxy, so every DIRECT name would still be disclosed to the
// tunnel resolver, and a local DNS server would see every proxied name.
const xraySplitRefusal = "routing.country_split is implemented for sing-box only: xray cannot route a DNS resolver through the tunnel, so the split would either leak domestic lookups to the proxy or proxied lookups to the local resolver; unset routing.country_split or select sing-box"

func (cg *ConfigGenerator) generateXray(link *profile.Link) (string, error) {
	// Refusing here keeps the panel from reporting a direct path the engine
	// cannot honour.
	if cg.CountrySplit != "" {
		return "", errors.New(xraySplitRefusal)
	}
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
	if len(cg.RoutingRules) > 0 || cg.CountrySplit != "" || len(cg.WhitelistCountries) > 0 || len(cg.BypassDomains) > 0 || len(cg.ForceProxyDomains) > 0 {
		cfg["routing"] = cg.xrayRoutingSection()
	}

	return cg.writeJSON("xray", cfg)
}

// xrayGeoAssetPath returns the .dat file xray would load for name, searching
// bypath's provisioning directories first and then xray's standard locations.
func (cg *ConfigGenerator) xrayGeoAssetPath(name string) string {
	for _, dir := range []string{cg.engineDir(), cg.geoDir()} {
		if p := geo.FindXrayAsset(dir, name); p != "" {
			return p
		}
	}
	return ""
}

// xrayGeoipAvailable reports whether geoip.dat exists AND contains the country.
// xray aborts instance startup when a rule references a missing category, so a
// bare "file exists" check is not enough: the file must also carry the code.
func (cg *ConfigGenerator) xrayGeoipAvailable(country string) bool {
	p := cg.xrayGeoAssetPath("geoip.dat")
	if p == "" {
		return false
	}
	return geo.HasXrayCategory(p, strings.ToUpper(country))
}

// xrayGeositeTag resolves the tag spelling used by the installed geosite.dat.
// A rule written as geosite:cc must work against both v2fly's "CATEGORY-XX" and
// a bare country code entry, and xray only accepts the exact tag present in the file.
func (cg *ConfigGenerator) xrayGeositeTag(tag string) (string, bool) {
	p := cg.xrayGeoAssetPath("geosite.dat")
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
	entry := cg.planFromRule(-1, RoutingRule{Match: match, Outbound: outbound}, cg.xrayGeoGate)
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
