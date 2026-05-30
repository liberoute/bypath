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
	SOCKSPort          int      // SOCKS5/mixed listen port (default: 2801)
	SNISpoof           string   // fake SNI to replace real one (empty = disabled)
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

// --- sing-box config generation ---

// singboxRoute builds the route section with geoip-based whitelist rules.
// Traffic destined for whitelisted countries goes direct; everything else goes through proxy.
func (cg *ConfigGenerator) singboxRoute(link *profile.Link) map[string]interface{} {
	var rules []map[string]interface{}

	// Rule: sniff to detect domain from TLS/HTTP
	rules = append(rules, map[string]interface{}{
		"action":  "sniff",
		"timeout": "300ms",
	})

	// Rule: resolve destination IP using direct DNS (for geoip matching)
	rules = append(rules, map[string]interface{}{
		"action": "resolve",
		"server": "dns-direct",
	})

	// Rule: private/LAN IPs → direct
	rules = append(rules, map[string]interface{}{
		"ip_is_private": true,
		"action":        "route",
		"outbound":      "direct",
	})

	// Rule: whitelisted countries → direct (using local geoip rule_set)
	var ruleSetTags []string
	for _, country := range cg.WhitelistCountries {
		ruleSetTags = append(ruleSetTags, fmt.Sprintf("geoip-%s", country))
	}
	rules = append(rules, map[string]interface{}{
		"rule_set": ruleSetTags,
		"action":   "route",
		"outbound": "direct",
	})

	// Build rule_set definitions (local .srs files)
	var ruleSets []map[string]interface{}
	for _, country := range cg.WhitelistCountries {
		ruleSets = append(ruleSets, map[string]interface{}{
			"type":   "local",
			"tag":    fmt.Sprintf("geoip-%s", country),
			"format": "binary",
			"path":   filepath.Join(paths.Get().GeoDir, fmt.Sprintf("geoip-%s.srs", country)),
		})
	}

	route := map[string]interface{}{
		"rules":    rules,
		"rule_set": ruleSets,
		"final":    "proxy",
	}

	return route
}

// generateSingBox generates the full sing-box config.
func (cg *ConfigGenerator) generateSingBox(link *profile.Link) (string, error) {
	cfg := map[string]interface{}{
		"log": map[string]interface{}{
			"level": "info",
		},
		"inbounds":  cg.singboxInbounds(link),
		"outbounds": cg.singboxOutbounds(link),
	}

	// Route section: geoip whitelist for bypassing tunnel on IR traffic.
	if len(cg.WhitelistCountries) > 0 {
		cfg["route"] = cg.singboxRoute(link)
		// DNS for route matching: resolve directly (no tunnel)
		cfg["dns"] = map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"tag":     "dns-direct",
					"address": "udp://1.1.1.1",
				},
			},
			"final": "dns-direct",
		}
	}

	return cg.writeJSON("singbox", cfg)
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
	var outbound map[string]interface{}

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

	switch link.Protocol {
	case "vmess":
		outbound = map[string]interface{}{
			"type":       "vmess",
			"tag":        "proxy",
			"server":     link.Address,
			"server_port": link.Port,
			"uuid":       link.UUID,
			"alter_id":   link.AlterId,
			"security":   link.Security,
		}
		// Transport
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
		// TLS
		if link.TLS {
			tls := map[string]interface{}{"enabled": true}
			if sni != "" {
				tls["server_name"] = sni
			}
			outbound["tls"] = tls
		}

	case "vless":
		outbound = map[string]interface{}{
			"type":       "vless",
			"tag":        "proxy",
			"server":     link.Address,
			"server_port": link.Port,
			"uuid":       link.UUID,
		}
		if link.Flow != "" {
			outbound["flow"] = link.Flow
		}
		// Transport
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
		// TLS
		if link.TLS {
			tls := map[string]interface{}{"enabled": true, "insecure": true}
			if sni != "" {
				tls["server_name"] = sni
			}
			outbound["tls"] = tls
		}

	case "trojan":
		outbound = map[string]interface{}{
			"type":       "trojan",
			"tag":        "proxy",
			"server":     link.Address,
			"server_port": link.Port,
			"password":   link.UUID,
		}
		// TLS (always enabled for trojan)
		tls := map[string]interface{}{"enabled": true}
		if sni != "" {
			tls["server_name"] = sni
		}
		outbound["tls"] = tls
		// Transport
		if link.Network != "" && link.Network != "tcp" {
			transport := map[string]interface{}{"type": link.Network}
			if link.Path != "" {
				transport["path"] = link.Path
			}
			outbound["transport"] = transport
		}

	case "shadowsocks":
		outbound = map[string]interface{}{
			"type":       "shadowsocks",
			"tag":        "proxy",
			"server":     link.Address,
			"server_port": link.Port,
			"method":     link.Security,
			"password":   link.UUID,
		}

	case "wireguard":
		outbound = map[string]interface{}{
			"type":        "wireguard",
			"tag":         "proxy",
			"server":      link.Address,
			"server_port": link.Port,
			"private_key": link.PrivateKey,
			"peer_public_key": link.PublicKey,
			"local_address": []string{"10.0.0.2/32"},
		}

	case "socks5":
		outbound = map[string]interface{}{
			"type":       "socks",
			"tag":        "proxy",
			"server":     link.Address,
			"server_port": link.Port,
			"version":    "5",
		}
		if link.UUID != "" {
			outbound["username"] = link.UUID
			outbound["password"] = link.Security
		}

	case "http":
		outbound = map[string]interface{}{
			"type":       "http",
			"tag":        "proxy",
			"server":     link.Address,
			"server_port": link.Port,
		}
		if link.UUID != "" {
			outbound["username"] = link.UUID
			outbound["password"] = link.Security
		}
		if link.TLS {
			outbound["tls"] = map[string]interface{}{"enabled": true}
		}

	default:
		outbound = map[string]interface{}{
			"type": "direct",
			"tag":  "proxy",
		}
	}

	// If this hop is chained, add detour through previous hop's SOCKS
	if link.ChainProxy != "" {
		outbound["detour"] = "chain-out"
		// Add a SOCKS outbound for the chain
		return []map[string]interface{}{
			outbound,
			{
				"type":       "socks",
				"tag":        "chain-out",
				"server":     "127.0.0.1",
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
		"inbounds": []map[string]interface{}{
			{
				"port":     listenPort,
				"listen":   "0.0.0.0",
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  true,
				},
			},
		},
		"outbounds": cg.xrayOutbounds(link),
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
			stream["wsSettings"] = map[string]interface{}{
				"path": link.Path,
				"headers": map[string]interface{}{
					"Host": link.Host,
				},
			}
		}
		if link.TLS {
			stream["security"] = "tls"
			stream["tlsSettings"] = map[string]interface{}{
				"serverName": link.SNI,
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
		if link.TLS {
			stream["security"] = "tls"
			stream["tlsSettings"] = map[string]interface{}{
				"serverName": link.SNI,
			}
		}
		outbound["streamSettings"] = stream

	default:
		outbound = map[string]interface{}{
			"protocol": "freedom",
			"settings": map[string]interface{}{},
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
