package tunnel

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/liberoute/bypath/internal/profile"
)

func validateProtocolMapping(engine string, l *profile.Link) error {
	if l.Protocol == "openvpn" {
		return nil
	} // endpoint validation/version gate follows
	reject := func(message string) error {
		return &profile.ParseError{Category: "unsupported_configuration", Message: message}
	}
	if len(l.UnsupportedParams) != 0 {
		return reject("profile contains unsupported parameters")
	}
	if strings.Contains(l.SNI, ",") {
		return reject("multiple TLS server names are unsupported")
	}
	if l.ExtraJSON != "" {
		var extra map[string]interface{}
		if json.Unmarshal([]byte(l.ExtraJSON), &extra) != nil || extra == nil {
			return reject("invalid XHTTP extra object")
		}
	}
	if engine == "wireguard-go" && l.Protocol == "wireguard" {
		return nil
	}
	if engine != "sing-box" && engine != "xray" {
		return reject("unsupported engine/protocol combination")
	}
	switch l.Protocol {
	case "vmess", "vless", "trojan", "shadowsocks", "socks5", "socks", "http":
	case "wireguard", "openvpn", "ssh":
		if engine != "sing-box" {
			return reject("protocol is not mapped for xray")
		}
	default:
		return reject("unsupported proxy protocol (direct fallback forbidden)")
	}
	switch l.Network {
	case "", "tcp", "ws", "h2", "http", "http2", "grpc":
	case "xhttp", "splithttp":
		if engine != "xray" {
			return reject("XHTTP requires xray; fallback forbidden")
		}
	default:
		return reject("unsupported proxy transport")
	}
	if l.Security == "reality" && l.Protocol != "vless" {
		return reject("REALITY is currently supported only for VLESS")
	}
	if engine == "sing-box" && l.RealitySpiderX != "" {
		return reject("REALITY spiderX requires xray")
	}
	if engine == "sing-box" && l.Network == "grpc" && (l.GRPCMultiMode || l.Host != "") {
		return reject("gRPC multi-mode/authority cannot be represented by sing-box")
	}
	if (l.Protocol == "shadowsocks" || l.Protocol == "socks5" || l.Protocol == "socks" || l.Protocol == "http") && l.Network != "" && l.Network != "tcp" {
		return reject("this proxy protocol cannot preserve transport settings")
	}
	if l.Protocol == "socks5" || l.Protocol == "socks" {
		if l.TLS {
			return reject("TLS SOCKS upstream is unsupported")
		}
	}
	return nil
}
func grpcService(l *profile.Link) string {
	if l.GRPCServiceName != "" {
		return l.GRPCServiceName
	}
	return strings.TrimPrefix(l.Path, "/")
}
// alpnForTransport restricts the negotiated protocol to what the transport can
// actually carry. A WebSocket upgrade is HTTP/1.1 (RFC 6455): offering h2 lets
// the server negotiate HTTP/2, the upgrade is then rejected, and every request
// through the tunnel fails with EOF. Servers honour their own preference, so
// h2 must not merely be listed after http/1.1 — it must not be offered.
func alpnForTransport(network string, alpn []string) []string {
	if network == "ws" {
		return []string{"http/1.1"}
	}
	return alpn
}
func singboxTLS(l *profile.Link, sni string) map[string]interface{} {
	if sni == "" {
		sni = l.Address
	}
	tls := map[string]interface{}{"enabled": true, "insecure": l.Insecure, "server_name": sni}
	if l.Security == "reality" {
		delete(tls, "insecure")
	}
	if alpn := alpnForTransport(l.Network, l.ALPN); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	if l.Fingerprint != "" {
		tls["utls"] = map[string]interface{}{"enabled": true, "fingerprint": l.Fingerprint}
	}
	return tls
}
func xrayTLS(l *profile.Link) map[string]interface{} {
	sni := l.SNI
	if sni == "" {
		sni = l.Address
	}
	tls := map[string]interface{}{"serverName": sni, "allowInsecure": l.Insecure}
	if alpn := alpnForTransport(l.Network, l.ALPN); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	if l.Fingerprint != "" {
		tls["fingerprint"] = l.Fingerprint
	}
	return tls
}

// UnsupportedConfiguration is usable by benchmark callers without string matching.
func UnsupportedConfiguration(message string) error {
	return &profile.ParseError{Category: "unsupported_configuration", Message: fmt.Sprint(message)}
}
