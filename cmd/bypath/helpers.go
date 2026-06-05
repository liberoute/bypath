package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/liberoute/bypath/internal/paths"
)

func detectEngine(protocol, forceEngine string) string {
	if forceEngine != "" {
		return forceEngine
	}

	switch protocol {
	case "vmess", "vless", "trojan", "shadowsocks", "hysteria2", "tuic":
		return "sing-box (auto)"
	case "wireguard":
		return "wireguard-go (auto)"
	case "openvpn":
		return "openvpn (auto)"
	case "ssh":
		return "ssh (native)"
	default:
		return "sing-box (fallback)"
	}
}

func detectEngineFromFile(path, forceEngine string) string {
	if forceEngine != "" {
		return forceEngine
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown (can't read file)"
	}

	content := string(data)

	if strings.Contains(content, `"inbounds"`) && strings.Contains(content, `"outbounds"`) {
		if strings.Contains(content, `"type"`) && strings.Contains(content, `"tag"`) {
			return "sing-box (detected)"
		}
	}

	if strings.Contains(content, `"inbounds"`) && strings.Contains(content, `"protocol"`) {
		return "xray (detected)"
	}

	if strings.Contains(content, "[Interface]") && strings.Contains(content, "[Peer]") {
		return "wireguard-go (detected)"
	}

	if strings.Contains(content, "remote ") && strings.Contains(content, "dev tun") {
		return "openvpn (detected)"
	}

	if strings.Contains(content, "proxies:") || strings.Contains(content, "proxy-groups:") {
		return "clash-meta (detected)"
	}

	return "unknown"
}

func groupNameFromURL(rawURL string) string {
	u := rawURL
	if idx := strings.Index(u, "://"); idx != -1 {
		u = u[idx+3:]
	}
	if idx := strings.Index(u, "/"); idx != -1 {
		u = u[:idx]
	}
	if idx := strings.Index(u, ":"); idx != -1 {
		u = u[:idx]
	}

	parts := strings.Split(u, ".")
	if len(parts) >= 2 {
		name := parts[len(parts)-2]
		if len(name) <= 2 && len(parts) >= 3 {
			name = parts[len(parts)-3]
		}
		return name
	}
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return "sub"
}

func createDefaultConfig(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	p := paths.Get()
	content := fmt.Sprintf(`# Bypath Configuration

server:
  api_port: 8080
  dns_port: 53
  socks_port: 2801
  api_token: ""

gateway:
  enabled: true
  interface: ""
  dns_upstream:
    - "1.1.1.1"
    - "8.8.8.8"

engines:
  directory: "%s"
  prefer_system: true
  preferred: ""

profiles:
  directory: "%s"
  active_group: "default"

whitelist:
  countries: ["ir"]
  update_interval: "24h"

isolation:
  enabled: true

sni_spoof:
  enabled: false
  sni: "digikala.com"
`, p.EngineDir, p.ProfileDir)

	return os.WriteFile(path, []byte(content), 0644)
}

func setupLogging(p *paths.Resolved) {
	if p.LogDir == "" {
		return
	}

	os.MkdirAll(p.LogDir, 0755)

	logFile := filepath.Join(p.LogDir, "error.log")
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("⚠️  Cannot open log file %s: %v (using stdout)", logFile, err)
		return
	}

	log.SetOutput(f)
	log.Printf("📝 Logging to %s", logFile)
}

func profileDir() string {
	return paths.Get().ProfileDir
}

func tmpDir() string {
	return paths.Get().TmpDir
}

func engineDir() string {
	return paths.Get().EngineDir
}
