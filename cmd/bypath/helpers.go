package main

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
)

func detectEngine(link *profile.Link, forceEngine string) string {
	if forceEngine != "" {
		return forceEngine
	}
	if link == nil {
		return "unknown"
	}
	if link.EncryptedVLESS() {
		return "xray (required)"
	}
	if link.Protocol == "openvpn" {
		return "sing-box (1.14+)"
	}

	switch link.Protocol {
	case "vmess", "vless", "trojan", "shadowsocks", "hysteria2", "tuic":
		if link.Network == "xhttp" || link.Network == "splithttp" {
			return "xray (required)"
		}
		return "sing-box (auto)"
	case "wireguard":
		return "wireguard-go (auto)"
	case "ssh":
		return "ssh (native)"
	default:
		return "sing-box (fallback)"
	}
}

// benchEngineFor selects the engine used by 'bypath bench' for a link.
func benchEngineFor(link *profile.Link) string {
	if link.EncryptedVLESS() {
		return "xray"
	}
	if link.Protocol == "openvpn" {
		return "sing-box"
	}
	if link.Network == "xhttp" || link.Network == "splithttp" {
		return "xray"
	}
	return "sing-box"
}

// engineBinary resolves an engine binary from PATH or the managed engine directory.
func engineBinary(name string) string {
	bin := name
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if path, err := exec.LookPath(bin); err == nil {
		return path
	}
	return filepath.Join(engineDir(), bin)
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

// groupNameFromURL picks a profile group name for a subscription URL.
//
// Convention (v2rayN / Nekoray / many panels): the URL fragment after '#' is the
// subscription remark/display name, e.g.
//
//	https://panel.example/sub/abc#tonysopranosjr_1  → group "tonysopranosjr_1"
//
// If there is no fragment, fall back to the registrable-ish domain label
// (subcdn.sudonetwork.com → "sudonetwork").
func groupNameFromURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return "sub"
	}

	if u, err := url.Parse(rawURL); err == nil {
		// Prefer #remark — this is what clients show as the subscription name.
		if frag := strings.TrimSpace(u.Fragment); frag != "" {
			if name := sanitizeGroupName(frag); name != "" {
				return name
			}
		}
		// Domain fallback (ignore port)
		host := u.Hostname()
		if host != "" {
			parts := strings.Split(host, ".")
			if len(parts) >= 2 {
				name := parts[len(parts)-2]
				// foo.co.uk → foo
				if len(name) <= 2 && len(parts) >= 3 {
					name = parts[len(parts)-3]
				}
				if name = sanitizeGroupName(name); name != "" {
					return name
				}
			}
			if name := sanitizeGroupName(parts[0]); name != "" {
				return name
			}
		}
	}

	// Last-resort string parse (malformed URL)
	u := rawURL
	if idx := strings.Index(u, "#"); idx != -1 {
		if name := sanitizeGroupName(u[idx+1:]); name != "" {
			return name
		}
		u = u[:idx]
	}
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
		if name = sanitizeGroupName(name); name != "" {
			return name
		}
	}
	if len(parts) > 0 {
		if name := sanitizeGroupName(parts[0]); name != "" {
			return name
		}
	}
	return "sub"
}

// sanitizeGroupName makes a subscription remark safe as a profile group filename.
func sanitizeGroupName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	// URL-decode once if still escaped
	if dec, err := url.QueryUnescape(name); err == nil {
		name = strings.TrimSpace(dec)
	}
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch {
		case r == '/' || r == '\\' || r == 0 || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|':
			b.WriteByte('_')
		case unicode.IsControl(r):
			// skip
		default:
			b.WriteRune(r)
		}
	}
	name = strings.Trim(b.String(), " ._")
	if name == "" || name == "." || name == ".." || strings.EqualFold(name, "default") {
		return ""
	}
	// Windows/Linux filename practical limit
	runes := []rune(name)
	if len(runes) > 64 {
		name = string(runes[:64])
	}
	return name
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
  enabled: false
  native_tun: true
  interface: ""
  dns_upstream:
    - "1.1.1.1"
    - "8.8.8.8"
  dns_mode: "strict"

engines:
  directory: "%s"
  prefer_system: true
  preferred: ""

  fallback:
    enabled: true
    timeout: "10s"
    order:
      - sing-box
      - xray

profiles:
  directory: "%s"
  active_group: ""

routing:
  rules:
    - match: "default"
      outbound: "proxy"

isolation:
  enabled: true

sni_spoof:
  enabled: false
  sni: "example.com"
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

// diagnosticEngines resolves the engine settings for read-only commands that
// do not run the daemon. It accepts -c/--config so the report describes the
// configuration the operator actually uses, and falls back to the paths default
// when the file cannot be loaded.
func diagnosticEngines(args []string) (dir string, preferSystem bool) {
	cfgPath := paths.Get().ConfigFile
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-c", "--config":
			if i+1 < len(args) {
				cfgPath = args[i+1]
			}
		}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return engineDir(), true
	}
	return cfg.Engines.Directory, cfg.Engines.PreferSystem
}
