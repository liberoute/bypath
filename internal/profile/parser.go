package profile

import (
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
	if u, err := url.Parse(uri); err == nil && u.Port() == "0" {
		return nil, parseFailure("invalid server port (expected 1-65535)")
	}
	link, err := parseURI(uri)
	if err != nil {
		// url.Parse errors can contain userinfo and query credentials.
		return nil, safeParseError(err)
	}
	if err := ValidateParsedLink(link); err != nil {
		return nil, err
	}
	return link, nil
}

func parseURI(uri string) (*Link, error) {

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
		return nil, fmt.Errorf("unsupported URI (looks like a URL, not a proxy): %s", RedactURI(uri))
	default:
		return nil, unsupported("unsupported protocol URI")
	}
}

// parseVmess parses a vmess:// URI (base64 JSON format).
func parseVmess(uri string) (*Link, error) {
	raw := strings.TrimPrefix(uri, "vmess://")
	if strings.Contains(raw, "@") {
		u, err := url.Parse(uri)
		if err != nil {
			return nil, err
		}
		port, _ := strconv.Atoi(u.Port())
		link := &Link{Protocol: "vmess", RawURI: uri, Address: u.Hostname(), Port: port, Remark: u.Fragment, UUID: u.User.Username(), Security: "auto"}
		if password, ok := u.User.Password(); ok {
			link.Security, link.UUID = u.User.Username(), password
		}
		applyURIParams(link, u.Query())
		if link.Remark == "" {
			link.Remark = fmt.Sprintf("%s:%d", link.Address, link.Port)
		}
		return link, nil
	}

	// Decode base64
	decoded, err := decodeProxyBase64(raw)
	if err != nil {
		return nil, err
	}

	var vmess struct {
		V             interface{}     `json:"v"`
		PS            string          `json:"ps"`
		Add           string          `json:"add"`
		Port          interface{}     `json:"port"`
		ID            string          `json:"id"`
		Aid           interface{}     `json:"aid"`
		Scy           string          `json:"scy"`
		Net           string          `json:"net"`
		Type          string          `json:"type"`
		Host          string          `json:"host"`
		Path          string          `json:"path"`
		TLS           string          `json:"tls"`
		SNI           string          `json:"sni"`
		Peer          string          `json:"peer"`
		Network       string          `json:"network"`
		FP            string          `json:"fp"`
		Fingerprint   string          `json:"fingerprint"`
		ALPN          json.RawMessage `json:"alpn"`
		Insecure      interface{}     `json:"insecure"`
		AllowInsecure interface{}     `json:"allowInsecure"`
		ServiceName   string          `json:"serviceName"`
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

	link.Network = firstValue(vmess.Net, vmess.Network)
	link.SNI = firstValue(vmess.SNI, vmess.Peer)
	link.Fingerprint = firstValue(vmess.FP, vmess.Fingerprint)
	link.Insecure = parseBoolParam(fmt.Sprint(vmess.Insecure)) || parseBoolParam(fmt.Sprint(vmess.AllowInsecure))
	link.GRPCServiceName = vmess.ServiceName
	if len(vmess.ALPN) > 0 {
		var text string
		if json.Unmarshal(vmess.ALPN, &text) == nil {
			link.ALPN = splitALPN(text)
		} else if json.Unmarshal(vmess.ALPN, &link.ALPN) != nil {
			return nil, fmt.Errorf("vmess: invalid ALPN")
		}
	}
	if vmess.Type != "" && vmess.Type != "none" {
		link.UnsupportedParams = append(link.UnsupportedParams, "headerType")
	}
	if link.Security == "" {
		link.Security = "auto"
	}
	link.Network = normalizeNetwork(link.Network)
	if link.Network == "" {
		link.Network = "tcp"
	}
	if link.Remark == "" {
		link.Remark = fmt.Sprintf("%s:%d", link.Address, link.Port)
	}

	return link, nil
}

// normalizeNetwork maps legacy/alias transport names to canonical ones.
func normalizeNetwork(net string) string {
	switch strings.ToLower(strings.TrimSpace(net)) {
	case "splithttp", "split":
		return "xhttp"
	case "h2", "http2":
		return "h2"
	case "http":
		return "h2"
	case "websocket":
		return "ws"
	default:
		return strings.ToLower(strings.TrimSpace(net))
	}
}

// applyXHTTPParams copies mode/extra/x_padding_bytes from URI query into the link.
func applyXHTTPParams(link *Link, params url.Values) {
	if mode := params.Get("mode"); mode != "" {
		link.TransportMode = mode
	}
	if extra := params.Get("extra"); extra != "" {
		link.ExtraJSON = extra
	}
	// Standalone x_padding_bytes → merge into extra JSON if extra is empty/missing that key.
	if pad := params.Get("x_padding_bytes"); pad != "" {
		if link.ExtraJSON == "" {
			link.ExtraJSON = fmt.Sprintf(`{"xPaddingBytes":%q}`, pad)
		}
	}
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
	applyURIParams(link, params)

	// VLESS Encryption (Xray 26.x) and the REALITY ML-KEM compatibility hint.
	// The value is preserved verbatim; it is a credential and must not be logged.
	link.Encryption = strings.TrimSpace(params.Get("encryption"))
	link.SupportX25519MLKEM768 = parseBoolParam(params.Get("support-x25519mlkem768"))
	if err := validateVLESSEncryption(link.Encryption); err != nil {
		return nil, fmt.Errorf("vless: %v (%s)", err, RedactURI(uri))
	}

	// XHTTP / SplitHTTP
	applyXHTTPParams(link, params)

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
	applyURIParams(link, params)

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

	params := url.Values{}
	if i := strings.IndexByte(raw, '?'); i >= 0 {
		var err error
		params, err = url.ParseQuery(raw[i+1:])
		if err != nil {
			return nil, fmt.Errorf("ss: invalid query")
		}
		raw = strings.TrimSuffix(raw[:i], "/")
	}
	var method, password, host string
	var port int

	// Try format: base64(method:password)@host:port
	if atIdx := strings.LastIndex(raw, "@"); atIdx != -1 {
		userInfo := raw[:atIdx]
		serverInfo := raw[atIdx+1:]

		// Decode userinfo
		decoded, err := decodeProxyBase64(userInfo)
		if strings.Contains(userInfo, ":") {
			u, perr := url.Parse("ss://" + userInfo + "@" + serverInfo)
			if perr != nil {
				return nil, perr
			}
			pwd, _ := u.User.Password()
			decoded, err = []byte(u.User.Username()+":"+pwd), nil
		}
		if err != nil {
			return nil, fmt.Errorf("ss: invalid base64 userinfo")
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
		decoded, err := decodeProxyBase64(raw)
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
	applyURIParams(link, params)

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

// RedactURI returns a log-safe form of a proxy URI: scheme and host:port only.
// Userinfo (UUID/password) and every query value are dropped, because VLESS
// encryption keys, REALITY keys and subscription tokens can appear there.
func RedactURI(raw string) string {
	raw = strings.TrimSpace(raw)
	scheme := ""
	if i := strings.Index(raw, "://"); i > 0 {
		scheme = strings.ToLower(raw[:i])
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		if scheme != "" {
			return scheme + "://<redacted>"
		}
		return "<redacted>"
	}
	return scheme + "://<redacted>@" + u.Host
}

// parseBoolParam accepts the boolean spellings used by subscription panels.
func parseBoolParam(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// validateVLESSEncryption validates the structure of a VLESS Encryption value
// without ever including the credential segment in an error message.
// Format: handshake.appearance.resumption[.padding][.padding].auth
func validateVLESSEncryption(enc string) error {
	enc = strings.TrimSpace(enc)
	if enc == "" || enc == "none" {
		return nil
	}
	parts := strings.Split(enc, ".")
	if len(parts) < 4 || len(parts) > 6 {
		return fmt.Errorf("unsupported VLESS encryption format: expected 4-6 segments, got %d", len(parts))
	}
	switch parts[0] {
	case "mlkem768x25519plus":
	default:
		return fmt.Errorf("unsupported VLESS encryption handshake %q", parts[0])
	}
	switch parts[1] {
	case "native", "xorpub", "random":
	default:
		return fmt.Errorf("unsupported VLESS encryption appearance %q", parts[1])
	}
	switch parts[2] {
	case "0rtt", "1rtt":
	default:
		return fmt.Errorf("unsupported VLESS encryption resumption %q", parts[2])
	}
	for _, padding := range parts[3 : len(parts)-1] {
		if !validEncryptionPadding(padding) {
			return fmt.Errorf("unsupported VLESS encryption padding block")
		}
	}
	if parts[len(parts)-1] == "" {
		return fmt.Errorf("VLESS encryption is missing the authentication parameter")
	}
	return nil
}

// validEncryptionPadding matches the probability-min-max blocks (e.g. 100-111-1111).
func validEncryptionPadding(s string) bool {
	fields := strings.Split(s, "-")
	if len(fields) != 3 {
		return false
	}
	for _, f := range fields {
		if f == "" {
			return false
		}
		for _, ch := range f {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}

// EncryptedVLESS reports whether the link needs Xray's VLESS Encryption support.
func (l *Link) EncryptedVLESS() bool {
	return l != nil && l.Protocol == "vless" &&
		l.Encryption != "" && l.Encryption != "none"
}

// EncryptionScheme returns only the non-secret scheme prefix (e.g.
// "mlkem768x25519plus.native.0rtt") for diagnostics.
func (l *Link) EncryptionScheme() string {
	if !l.EncryptedVLESS() {
		return ""
	}
	parts := strings.Split(l.Encryption, ".")
	if len(parts) > 3 {
		parts = parts[:3]
	}
	return strings.Join(parts, ".")
}

// EncryptionParameters returns the full non-secret policy of a VLESS Encryption
// value: handshake, appearance, resumption and padding, without the per-link
// authentication segment. Links are interchangeable only when this value is
// identical, so a fallback can never downgrade 0-RTT, the appearance mode or
// the padding profile.
func (l *Link) EncryptionParameters() string {
	if !l.EncryptedVLESS() {
		return ""
	}
	parts := strings.Split(l.Encryption, ".")
	if len(parts) < 4 {
		return l.Encryption
	}
	return strings.Join(parts[:len(parts)-1], ".")
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
	applyURIParams(link, u.Query())

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
	applyURIParams(link, u.Query())

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
