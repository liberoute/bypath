package profile

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ParseDiagnostic is safe for import previews: no URI, endpoint, remark or
// provider-supplied value is copied into it. Line is one-based after decoding.
type ParseDiagnostic struct {
	Line     int    `json:"line"`
	Category string `json:"category"`
	Message  string `json:"message"`
}

type ParseError struct{ Category, Message string }

func (e *ParseError) Error() string     { return e.Message }
func parseFailure(message string) error { return &ParseError{"parse_failure", message} }
func unsupported(message string) error  { return &ParseError{"unsupported_configuration", message} }
func safeParseError(err error) error {
	var p *ParseError
	if errors.As(err, &p) {
		return p
	}
	// Do not relay decoder errors: they may quote the entire input or credentials.
	return parseFailure("malformed proxy URI or encoded payload")
}

// ParseSubscriptionDetailed is the additive preview hook. Legacy callers can
// continue using ParseSubscriptionContent. Partial imports return accepted links
// and a diagnostic for every rejected non-comment line, without leaking secrets.
func ParseSubscriptionDetailed(content string) ([]*Link, []ParseDiagnostic, error) {
	trimmed := strings.TrimSpace(content)
	if decoded, err := decodeProxyBase64(trimmed); err == nil {
		content = string(decoded)
	}
	var links []*Link
	var diagnostics []ParseDiagnostic
	for i, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		link, err := ParseURI(line)
		if err != nil {
			p := safeParseError(err).(*ParseError)
			diagnostics = append(diagnostics, ParseDiagnostic{i + 1, p.Category, p.Message})
			continue
		}
		links = append(links, link)
	}
	if len(links) == 0 {
		return nil, diagnostics, parseFailure("no valid links found in subscription")
	}
	return links, diagnostics, nil
}

func decodeProxyBase64(raw string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(raw); err == nil {
			return b, nil
		}
	}
	return nil, parseFailure("invalid base64 payload")
}
func firstValue(values ...string) string {
	for _, s := range values {
		if s != "" {
			return s
		}
	}
	return ""
}
func splitALPN(raw string) []string {
	var out []string
	for _, s := range strings.Split(raw, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
func applyURIParams(l *Link, p url.Values) {
	l.Network = normalizeNetwork(firstValue(p.Get("type"), p.Get("network")))
	if l.Network == "" {
		l.Network = "tcp"
	}
	// HTTP/SOCKS/SS store their password/method in Security; do not overwrite it.
	if l.Protocol == "vmess" || l.Protocol == "vless" || l.Protocol == "trojan" {
		if security := p.Get("security"); security != "" {
			if l.Protocol != "vmess" {
				l.Security = security
			}
			l.TLS = security == "tls" || security == "reality"
		}
	}
	if l.Protocol == "vmess" && p.Get("encryption") != "" {
		l.Security = p.Get("encryption")
	}
	l.Insecure = parseBoolParam(p.Get("insecure")) || parseBoolParam(p.Get("allowInsecure"))
	l.SNI = firstValue(p.Get("sni"), p.Get("peer"), p.Get("serverName"))
	l.Fingerprint = firstValue(p.Get("fp"), p.Get("fingerprint"))
	l.ALPN = splitALPN(strings.Join(p["alpn"], ","))
	l.Path, l.Host, l.Flow = p.Get("path"), p.Get("host"), p.Get("flow")
	l.GRPCServiceName = firstValue(p.Get("serviceName"), p.Get("service_name"))
	l.GRPCMultiMode = parseBoolParam(p.Get("multiMode")) || (l.Network == "grpc" && p.Get("mode") == "multi")
	l.RealityPublicKey, l.RealityShortID, l.RealitySpiderX = p.Get("pbk"), p.Get("sid"), p.Get("spx")
	if l.Network == "xhttp" {
		applyXHTTPParams(l, p)
	}
	if p.Get("ed") != "" {
		l.WSMaxEarlyData = toInt(p.Get("ed"))
	}
	l.WSEarlyDataHeader = p.Get("eh")
	known := map[string]bool{}
	for _, k := range strings.Fields("type network security insecure allowInsecure sni peer serverName fp fingerprint alpn path host flow serviceName service_name multiMode mode pbk sid spx extra x_padding_bytes ed eh encryption support-x25519mlkem768 headerType") {
		known[k] = true
	}
	for k := range p {
		if !known[k] {
			l.UnsupportedParams = append(l.UnsupportedParams, "unmapped_parameter")
		}
	}
	if p.Get("headerType") != "" && p.Get("headerType") != "none" {
		l.UnsupportedParams = append(l.UnsupportedParams, "headerType")
	}
	if l.Network != "xhttp" && (p.Get("extra") != "" || p.Get("x_padding_bytes") != "" || (p.Get("mode") != "" && l.Network != "grpc")) {
		l.UnsupportedParams = append(l.UnsupportedParams, "transport_option")
	}
	if l.Network == "grpc" && p.Get("mode") != "" && p.Get("mode") != "multi" && p.Get("mode") != "gun" {
		l.UnsupportedParams = append(l.UnsupportedParams, "grpc_mode")
	}
	for _, k := range []string{"insecure", "allowInsecure", "multiMode"} {
		if v := strings.ToLower(p.Get(k)); v != "" && v != "0" && v != "1" && v != "true" && v != "false" && v != "yes" && v != "no" && v != "on" && v != "off" {
			l.UnsupportedParams = append(l.UnsupportedParams, "invalid_boolean")
		}
	}
}

// ValidateParsedLink also protects old persisted profiles at engine generation.
func ValidateParsedLink(l *Link) error {
	if l == nil || l.Address == "" {
		return parseFailure("missing server address")
	}
	if l.Port < 1 || l.Port > 65535 {
		return parseFailure("invalid server port (expected 1-65535)")
	}
	if strings.ContainsAny(l.Address, " /\\\t\r\n") {
		return parseFailure("invalid server address")
	}
	if strings.Contains(l.Address, ":") && net.ParseIP(l.Address) == nil {
		return parseFailure("invalid IP address")
	}
	if len(l.UnsupportedParams) > 0 {
		return unsupported("profile contains unsupported or invalid parameters")
	}
	switch normalizeNetwork(l.Network) {
	case "", "tcp", "ws", "h2", "grpc", "xhttp":
	default:
		return unsupported("unsupported transport")
	}
	if l.ExtraJSON != "" {
		var extra map[string]interface{}
		if json.Unmarshal([]byte(l.ExtraJSON), &extra) != nil || extra == nil {
			return parseFailure("XHTTP extra must be a JSON object")
		}
	}
	for _, a := range l.ALPN {
		if len(a) == 0 || len(a) > 255 || strings.ContainsAny(a, "\r\n\x00") {
			return parseFailure("invalid ALPN protocol")
		}
	}
	if l.Protocol == "vless" || l.Protocol == "trojan" {
		switch l.Security {
		case "", "none", "tls", "reality":
		default:
			return unsupported("unsupported TLS security mode")
		}
	}
	if l.Flow != "" && l.Protocol != "vless" {
		return unsupported("flow is supported only for VLESS")
	}
	if l.Network == "tcp" && (l.Path != "" || l.Host != "") {
		return unsupported("TCP HTTP headers are unsupported")
	}
	if l.Security != "reality" && (l.RealityPublicKey != "" || l.RealityShortID != "" || l.RealitySpiderX != "") {
		return unsupported("REALITY parameters require REALITY security")
	}
	if l.Network != "grpc" && (l.GRPCServiceName != "" || l.GRPCMultiMode) {
		return unsupported("gRPC options require gRPC transport")
	}
	if l.Network != "ws" && (l.WSMaxEarlyData != 0 || l.WSEarlyDataHeader != "") {
		return unsupported("WebSocket options require WebSocket transport")
	}
	if l.WSMaxEarlyData < 0 {
		return parseFailure("invalid WebSocket early data size")
	}
	if l.Protocol == "shadowsocks" || l.Protocol == "socks5" || l.Protocol == "http" {
		if l.Network != "" && l.Network != "tcp" {
			return unsupported("proxy transport options are not supported for this protocol")
		}
	}
	if l.Protocol == "shadowsocks" && (l.TLS || l.Insecure || l.SNI != "" || len(l.ALPN) > 0 || l.Fingerprint != "") {
		return unsupported("Shadowsocks TLS options are unsupported")
	}
	if !l.TLS && (l.Insecure || l.SNI != "" || len(l.ALPN) > 0 || l.Fingerprint != "") {
		return unsupported("TLS parameters require TLS")
	}
	if l.Protocol == "vmess" || l.Protocol == "vless" || l.Protocol == "trojan" || l.Protocol == "shadowsocks" {
		if l.UUID == "" {
			return parseFailure("missing proxy authentication")
		}
	}
	return nil
}

// DiagnosticSummary is suitable for a preview warning without echoing input.
func DiagnosticSummary(diagnostics []ParseDiagnostic) string {
	if len(diagnostics) == 0 {
		return ""
	}
	return fmt.Sprintf("%d subscription line(s) rejected; inspect parse diagnostics", len(diagnostics))
}
