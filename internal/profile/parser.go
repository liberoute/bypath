package profile

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ParseURI parses a proxy URI (vmess://, vless://, trojan://, ss://, wireguard://, ssh://, socks5://, http://)
// and returns a Link struct.
func ParseURI(uri string) (*Link, error) {
	uri = strings.TrimSpace(uri)

	switch {
	case strings.HasPrefix(uri, "vmess://"):
		return parseVmess(uri)
	case strings.HasPrefix(uri, "vless://"):
		return parseVless(uri)
	case strings.HasPrefix(uri, "trojan://"):
		return parseTrojan(uri)
	case strings.HasPrefix(uri, "ss://"):
		return parseShadowsocks(uri)
	case strings.HasPrefix(uri, "wireguard://") || strings.HasPrefix(uri, "wg://"):
		return parseWireguard(uri)
	case strings.HasPrefix(uri, "ssh://"):
		return parseSSH(uri)
	case strings.HasPrefix(uri, "socks5://") || strings.HasPrefix(uri, "socks://"):
		return parseSocks5(uri)
	case strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://"):
		// Only parse as proxy if it looks like a proxy URI (has @ or port without path)
		if strings.Contains(uri, "@") || isProxyURI(uri) {
			return parseHTTPProxy(uri)
		}
		return nil, fmt.Errorf("unsupported URI (looks like a URL, not a proxy): %s", truncate(uri, 30))
	default:
		return nil, fmt.Errorf("unsupported protocol URI: %s", truncate(uri, 30))
	}
}

// parseVmess parses a vmess:// URI (base64 JSON format).
func parseVmess(uri string) (*Link, error) {
	raw := strings.TrimPrefix(uri, "vmess://")

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		// Try URL-safe base64
		decoded, err = base64.URLEncoding.DecodeString(raw)
		if err != nil {
			// Try raw (no padding)
			decoded, err = base64.RawStdEncoding.DecodeString(raw)
			if err != nil {
				return nil, fmt.Errorf("vmess: invalid base64: %w", err)
			}
		}
	}

	var vmess struct {
		V    interface{} `json:"v"`
		PS   string      `json:"ps"`
		Add  string      `json:"add"`
		Port interface{} `json:"port"`
		ID   string      `json:"id"`
		Aid  interface{} `json:"aid"`
		Scy  string      `json:"scy"`
		Net  string      `json:"net"`
		Type string      `json:"type"`
		Host string      `json:"host"`
		Path string      `json:"path"`
		TLS  string      `json:"tls"`
		SNI  string      `json:"sni"`
	}

	if err := json.Unmarshal(decoded, &vmess); err != nil {
		return nil, fmt.Errorf("vmess: invalid JSON: %w", err)
	}

	port := toInt(vmess.Port)
	alterId := toInt(vmess.Aid)

	link := &Link{
		Protocol: "vmess",
		RawURI:   uri,
		Remark:   vmess.PS,
		Address:  vmess.Add,
		Port:     port,
		UUID:     vmess.ID,
		AlterId:  alterId,
		Security: vmess.Scy,
		Network:  vmess.Net,
		TLS:      vmess.TLS == "tls",
		SNI:      vmess.SNI,
		Path:     vmess.Path,
		Host:     vmess.Host,
	}

	if link.Security == "" {
		link.Security = "auto"
	}
	if link.Network == "" {
		link.Network = "tcp"
	}
	if link.Remark == "" {
		link.Remark = fmt.Sprintf("%s:%d", link.Address, link.Port)
	}

	return link, nil
}

// parseVless parses a vless:// URI.
func parseVless(uri string) (*Link, error) {
	// vless://uuid@host:port?params#remark
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("vless: invalid URI: %w", err)
	}

	port, _ := strconv.Atoi(u.Port())

	link := &Link{
		Protocol: "vless",
		RawURI:   uri,
		Remark:   u.Fragment,
		Address:  u.Hostname(),
		Port:     port,
		UUID:     u.User.Username(),
	}

	params := u.Query()
	link.Network = params.Get("type")
	if link.Network == "" {
		link.Network = "tcp"
	}
	link.Security = params.Get("security")
	link.TLS = params.Get("security") == "tls" || params.Get("security") == "reality"
	link.Insecure = params.Get("insecure") == "1" || params.Get("allowInsecure") == "1"
	link.SNI = params.Get("sni")
	link.Path = params.Get("path")
	link.Host = params.Get("host")
	link.Flow = params.Get("flow")

	// Reality/UTLS fields
	link.RealityPublicKey = params.Get("pbk")
	link.RealityShortID = params.Get("sid")
	link.Fingerprint = params.Get("fp")

	if link.Remark == "" {
		link.Remark = fmt.Sprintf("%s:%d", link.Address, link.Port)
	}

	return link, nil
}

// parseTrojan parses a trojan:// URI.
func parseTrojan(uri string) (*Link, error) {
	// trojan://password@host:port?params#remark
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("trojan: invalid URI: %w", err)
	}

	port, _ := strconv.Atoi(u.Port())

	link := &Link{
		Protocol: "trojan",
		RawURI:   uri,
		Remark:   u.Fragment,
		Address:  u.Hostname(),
		Port:     port,
		UUID:     u.User.Username(), // trojan uses password in user field
		TLS:      true,
	}

	params := u.Query()
	link.Network = params.Get("type")
	if link.Network == "" {
		link.Network = "tcp"
	}
	link.SNI = params.Get("sni")
	link.Path = params.Get("path")
	link.Host = params.Get("host")

	if link.Remark == "" {
		link.Remark = fmt.Sprintf("%s:%d", link.Address, link.Port)
	}

	return link, nil
}

// parseShadowsocks parses a ss:// URI.
func parseShadowsocks(uri string) (*Link, error) {
	// ss://base64(method:password)@host:port#remark
	// or ss://base64(method:password@host:port)#remark
	raw := strings.TrimPrefix(uri, "ss://")

	// Split fragment (remark)
	remark := ""
	if idx := strings.LastIndex(raw, "#"); idx != -1 {
		remark = raw[idx+1:]
		raw = raw[:idx]
	}
	remark, _ = url.QueryUnescape(remark)

	var method, password, host string
	var port int

	// Try format: base64(method:password)@host:port
	if atIdx := strings.LastIndex(raw, "@"); atIdx != -1 {
		userInfo := raw[:atIdx]
		serverInfo := raw[atIdx+1:]

		// Decode userinfo
		decoded, err := base64.RawURLEncoding.DecodeString(userInfo)
		if err != nil {
			decoded, err = base64.StdEncoding.DecodeString(userInfo)
			if err != nil {
				return nil, fmt.Errorf("ss: invalid base64 userinfo: %w", err)
			}
		}

		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("ss: invalid userinfo format")
		}
		method = parts[0]
		password = parts[1]

		// Parse host:port
		u, err := url.Parse("dummy://" + serverInfo)
		if err != nil {
			return nil, fmt.Errorf("ss: invalid server info: %w", err)
		}
		host = u.Hostname()
		port, _ = strconv.Atoi(u.Port())
	} else {
		// Try fully encoded format
		decoded, err := base64.RawURLEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("ss: cannot decode: %w", err)
		}
		// method:password@host:port
		u, err := url.Parse("ss://" + string(decoded))
		if err != nil {
			return nil, fmt.Errorf("ss: invalid decoded URI: %w", err)
		}
		host = u.Hostname()
		port, _ = strconv.Atoi(u.Port())
		method = u.User.Username()
		password, _ = u.User.Password()
	}

	link := &Link{
		Protocol: "shadowsocks",
		RawURI:   uri,
		Remark:   remark,
		Address:  host,
		Port:     port,
		Security: method,
		UUID:     password, // reusing UUID field for password
	}

	if link.Remark == "" {
		link.Remark = fmt.Sprintf("%s:%d", link.Address, link.Port)
	}

	return link, nil
}

// parseWireguard parses a wireguard:// URI.
func parseWireguard(uri string) (*Link, error) {
	// wireguard://privatekey@host:port?publickey=xxx&address=10.0.0.2/32#remark
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("wireguard: invalid URI: %w", err)
	}

	port, _ := strconv.Atoi(u.Port())

	link := &Link{
		Protocol:   "wireguard",
		RawURI:     uri,
		Remark:     u.Fragment,
		Address:    u.Hostname(),
		Port:       port,
		PrivateKey: u.User.Username(),
		Endpoint:   fmt.Sprintf("%s:%d", u.Hostname(), port),
	}

	params := u.Query()
	link.PublicKey = params.Get("publickey")

	if link.Remark == "" {
		link.Remark = fmt.Sprintf("wg-%s:%d", link.Address, link.Port)
	}

	return link, nil
}

// parseSSH parses an ssh:// URI.
// Format: ssh://[user[:password]]@host[:port][?key=<path>&fingerprint=<fp>]#remark
func parseSSH(uri string) (*Link, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("ssh: invalid URI: %w", err)
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("ssh: missing host")
	}

	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 22
	}

	user := "root"
	password := ""
	if u.User != nil {
		if u.User.Username() != "" {
			user = u.User.Username()
		}
		password, _ = u.User.Password()
	}

	params := u.Query()
	keyPath := params.Get("key")

	link := &Link{
		Protocol:    "ssh",
		RawURI:      uri,
		Remark:      u.Fragment,
		Address:     host,
		Port:        port,
		SSHUser:     user,
		SSHPassword: password,
		SSHKeyPath:  keyPath,
	}

	if link.Remark == "" {
		link.Remark = fmt.Sprintf("ssh-%s:%d", link.Address, link.Port)
	}

	return link, nil
}

// Helper functions

func toInt(v interface{}) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case string:
		n, _ := strconv.Atoi(val)
		return n
	case int:
		return val
	default:
		return 0
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// parseSocks5 parses a socks5://[user:pass@]host:port[#remark] URI.
func parseSocks5(uri string) (*Link, error) {
	// Normalize scheme for url.Parse
	normalized := uri
	if strings.HasPrefix(normalized, "socks://") {
		normalized = "socks5://" + strings.TrimPrefix(normalized, "socks://")
	}

	u, err := url.Parse(normalized)
	if err != nil {
		return nil, fmt.Errorf("socks5: invalid URI: %w", err)
	}

	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		port = 1080
	}

	link := &Link{
		Protocol: "socks5",
		RawURI:   uri,
		Remark:   u.Fragment,
		Address:  u.Hostname(),
		Port:     port,
	}

	if u.User != nil {
		link.UUID = u.User.Username()
		link.Security, _ = u.User.Password()
	}

	if link.Remark == "" {
		link.Remark = fmt.Sprintf("socks5-%s:%d", link.Address, link.Port)
	}

	return link, nil
}

// parseHTTPProxy parses a http://[user:pass@]host:port[#remark] URI.
func parseHTTPProxy(uri string) (*Link, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("http-proxy: invalid URI: %w", err)
	}

	port, _ := strconv.Atoi(u.Port())
	if port == 0 {
		if u.Scheme == "https" {
			port = 443
		} else {
			port = 8080
		}
	}

	link := &Link{
		Protocol: "http",
		RawURI:   uri,
		Remark:   u.Fragment,
		Address:  u.Hostname(),
		Port:     port,
		TLS:      u.Scheme == "https",
	}

	if u.User != nil {
		link.UUID = u.User.Username()
		link.Security, _ = u.User.Password()
	}

	if link.Remark == "" {
		link.Remark = fmt.Sprintf("http-%s:%d", link.Address, link.Port)
	}

	return link, nil
}

// isProxyURI checks if an http:// URI looks like a proxy (host:port without path).
func isProxyURI(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	// A proxy URI typically has no path or just "/"
	return u.Port() != "" && (u.Path == "" || u.Path == "/")
}
