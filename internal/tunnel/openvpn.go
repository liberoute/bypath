package tunnel

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/liberoute/bypath/internal/credential"
	"github.com/liberoute/bypath/internal/openvpn"
	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/securefile"
)

// generateSingBoxOpenVPN renders a sing-box 1.14 openvpn-client endpoint.
// The endpoint uses sing-box's internal stack (system:false), pulls no routes
// and never touches host DNS, interfaces or firewall. Only explicitly
// supported profile options are mapped; scripts/plugins are rejected upstream
// by the openvpn parser.
func (cg *ConfigGenerator) generateSingBoxOpenVPN(link *profile.Link) (string, error) {
	profilePath, err := cg.openVPNProfilePath(link)
	if err != nil {
		return "", err
	}
	prof, err := openvpn.ParseFile(profilePath)
	if err != nil {
		return "", err
	}
	if link.OVPNAuthUserPassFile != "" {
		user, pass, err := openvpn.CredentialsFromFile(link.OVPNAuthUserPassFile)
		if err != nil {
			return "", err
		}
		prof.Username, prof.Password = user, pass
	} else if creds, ok := credential.Lookup(link); ok {
		// Credentials supplied through the product UI live in the encrypted or
		// session store, never in the profile file.
		prof.Username, prof.Password = creds.Username, creds.Password
	}

	endpoint := map[string]interface{}{
		"type":          "openvpn-client",
		"tag":           "proxy",
		"route_no_pull": true,
	}

	if len(prof.Remotes) == 1 {
		endpoint["server"] = cg.openVPNHost(prof.Remotes[0].Host)
		endpoint["server_port"] = prof.Remotes[0].Port
		if prof.Remotes[0].Network != "" {
			endpoint["network"] = prof.Remotes[0].Network
		}
	} else {
		servers := make([]map[string]interface{}, 0, len(prof.Remotes))
		for _, r := range prof.Remotes {
			s := map[string]interface{}{"server": cg.openVPNHost(r.Host), "server_port": r.Port}
			if r.Network != "" {
				s["network"] = r.Network
			}
			servers = append(servers, s)
		}
		endpoint["servers"] = servers
		if prof.RemoteRandom {
			endpoint["remote_random"] = true
		}
	}

	if prof.Username != "" {
		endpoint["username"] = prof.Username
		endpoint["password"] = prof.Password
	}
	if prof.Auth != "" {
		endpoint["auth"] = prof.Auth
	}
	if prof.Cipher != "" {
		endpoint["cipher"] = prof.Cipher
	}
	if len(prof.DataCiphers) > 0 {
		endpoint["data_ciphers"] = prof.DataCiphers
	}
	if prof.DataCiphersFallback != "" {
		endpoint["data_ciphers_fallback"] = prof.DataCiphersFallback
	}
	if prof.Compression != "" {
		endpoint["compression"] = prof.Compression
	}
	if prof.CompressionLZO != "" {
		endpoint["compression_lzo"] = prof.CompressionLZO
	}
	if prof.PingInterval > 0 {
		endpoint["ping_interval"] = durationSeconds(prof.PingInterval)
	}
	if prof.PingRestart > 0 {
		endpoint["ping_restart"] = durationSeconds(prof.PingRestart)
	}
	if prof.RenegotiateSeconds > 0 {
		endpoint["renegotiate_interval"] = durationSeconds(prof.RenegotiateSeconds)
	}
	if prof.ExplicitExitNotify > 0 {
		endpoint["explicit_exit_notify"] = prof.ExplicitExitNotify
	}
	if prof.Address != "" {
		endpoint["address"] = []string{prof.Address}
	}

	tls, err := cg.buildOpenVPNTLS(link, prof)
	if err != nil {
		return "", err
	}
	if len(tls) > 0 {
		endpoint["tls"] = tls
	}

	cfg := map[string]interface{}{
		"log": map[string]interface{}{
			"level": "info",
		},
		"inbounds":  cg.singboxInbounds(link),
		"endpoints": []map[string]interface{}{endpoint},
		"outbounds": cg.singboxOutbounds(link),
		"route":     cg.singboxOpenVPNRoute(),
		"dns":       cg.singboxDNS(link),
	}
	return cg.writeJSON("singbox", cfg)
}

// openVPNProfilePath resolves the packaged .ovpn reference against the
// profiles directory.
func (cg *ConfigGenerator) openVPNProfilePath(link *profile.Link) (string, error) {
	return OpenVPNProfilePath(cg.ProfileDir, link)
}

// OpenVPNProfilePath resolves a link's packaged .ovpn reference against the
// profiles directory. A migrated group records working-directory-relative
// paths that do not resolve from the installed daemon's directory, so the
// reference is searched under the current root (see
// profile.ResolveArtifactPath). An empty directory keeps the legacy behaviour
// of trusting the recorded path.
func OpenVPNProfilePath(profileDir string, link *profile.Link) (string, error) {
	if strings.TrimSpace(profileDir) == "" {
		return link.OVPNPath, nil
	}
	path, err := profile.ResolveArtifactPath(profileDir, link.OVPNPath)
	if err != nil {
		return "", fmt.Errorf("OpenVPN profile for %q: %w", link.Remark, err)
	}
	return path, nil
}

// openVPNHost substitutes a pre-resolved, validated endpoint address so the
// engine does not fall back to its own unvalidated round-robin lookup.
func (cg *ConfigGenerator) openVPNHost(host string) string {
	if ip, ok := cg.PinnedHosts[host]; ok && ip != "" {
		return ip
	}
	return host
}

// buildOpenVPNTLS writes PEM material to owner-only files and references it by
// path so generated JSON never embeds private keys or certificates.
func (cg *ConfigGenerator) buildOpenVPNTLS(link *profile.Link, prof *openvpn.Profile) (map[string]interface{}, error) {
	tls := map[string]interface{}{}

	if len(prof.CACerts) > 0 {
		path, err := cg.writeOVPNSecret(link, "ca.pem", joinPEM(prof.CACerts))
		if err != nil {
			return nil, err
		}
		tls["certificate_path"] = path
	}
	if prof.ClientCert != "" {
		path, err := cg.writeOVPNSecret(link, "cert.pem", prof.ClientCert)
		if err != nil {
			return nil, err
		}
		tls["client_certificate_path"] = path
	}
	if prof.ClientKey != "" {
		path, err := cg.writeOVPNSecret(link, "key.pem", prof.ClientKey)
		if err != nil {
			return nil, err
		}
		tls["client_key_path"] = path
	}
	if prof.ControlWrapType != "" && prof.ControlWrapKey != "" {
		path, err := cg.writeOVPNSecret(link, "control-wrap.key", prof.ControlWrapKey)
		if err != nil {
			return nil, err
		}
		wrap := map[string]interface{}{
			"type":     prof.ControlWrapType,
			"key_path": path,
		}
		if prof.ControlWrapDirection != "" {
			wrap["direction"] = prof.ControlWrapDirection
		}
		tls["control_wrap"] = wrap
	}
	if prof.RemoteCertTLS != "" {
		tls["remote_certificate_tls"] = prof.RemoteCertTLS
	}
	if prof.VerifyX509Name != "" {
		tls["server_name"] = prof.VerifyX509Name
		if prof.VerifyX509Type != "" {
			tls["server_name_type"] = prof.VerifyX509Type
		}
	}
	if prof.TLSVersionMin != "" {
		tls["version_min"] = prof.TLSVersionMin
	}
	if prof.TLSVersionMax != "" {
		tls["version_max"] = prof.TLSVersionMax
	}
	if prof.TLSCipher != "" {
		tls["cipher"] = prof.TLSCipher
	}
	return tls, nil
}

// writeOVPNSecret writes one extracted secret with 0600 permissions inside the
// current generation directory. Nothing is shared between generations, so a
// failed attempt or a stopped tunnel can never delete another tunnel's keys.
func (cg *ConfigGenerator) writeOVPNSecret(link *profile.Link, name, content string) (string, error) {
	gen, err := cg.currentGenDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(gen, "openvpn")
	if err := securefile.MkdirAll(dir); err != nil {
		return "", fmt.Errorf("creating OpenVPN secret directory: %w", err)
	}
	path := filepath.Join(dir, name)
	if err := securefile.WriteFile(path, []byte(content)); err != nil {
		return "", fmt.Errorf("writing OpenVPN %s: %w", name, err)
	}
	return path, nil
}

func joinPEM(blocks []string) string {
	out := ""
	for i, b := range blocks {
		if i > 0 {
			out += "\n"
		}
		out += b
	}
	return out
}

func durationSeconds(n int) string {
	return strconv.Itoa(n) + "s"
}

// singboxOpenVPNRoute keeps the same policy hooks as other links but never
// pre-resolves every domain through direct DNS: quarantine/whitelist rules
// still win when configured, and everything else exits through the endpoint.
func (cg *ConfigGenerator) singboxOpenVPNRoute() map[string]interface{} {
	if len(cg.RoutingRules) > 0 {
		return cg.singboxRouteFromRules()
	}

	rules := []map[string]interface{}{
		{"action": "sniff", "timeout": "300ms"},
	}
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
	rules = append(rules, map[string]interface{}{
		"ip_is_private": true,
		"action":        "route",
		"outbound":      "direct",
	})

	route := map[string]interface{}{
		"rules": rules,
		"final": "proxy",
		// The endpoint's server hostname must resolve before the tunnel exists,
		// so bootstrap it through the plain-DNS transport. Without this sing-box
		// refuses to initialize domains resolved by two or more DNS transports.
		"default_domain_resolver": map[string]interface{}{"server": "dns-direct"},
	}
	if cg.GatewayMode {
		route["auto_detect_interface"] = true
	}
	return route
}
