// Package openvpn parses OpenVPN client profiles (.ovpn) into a restricted,
// non-executable description that can be rendered as a sing-box openvpn-client
// endpoint. OpenVPN scripts, plugins and host-mutating options are rejected or
// ignored: bypath never runs directives from a profile and never changes the
// host's routes, DNS, interfaces or firewall.
package openvpn

import (
	"bufio"
	"bytes"
	"encoding/pem"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
)

// Remote is one `remote host [port] [proto]` line.
type Remote struct {
	Host    string
	Port    int
	Network string // tcp or udp
}

// Profile is the parsed, validated client profile.
type Profile struct {
	Remotes             []Remote
	RemoteRandom        bool
	Proto               string // tcp or udp
	Device              string // tun only
	Auth                string
	Cipher              string
	DataCiphers         []string
	DataCiphersFallback string

	CACerts    []string // PEM blocks
	ClientCert string
	ClientKey  string

	ControlWrapType      string // tls_crypt, tls_auth
	ControlWrapKey       string
	ControlWrapDirection string

	RemoteCertTLS  string
	VerifyX509Name string
	VerifyX509Type string
	TLSCipher      string
	TLSVersionMin  string
	TLSVersionMax  string

	Username string
	Password string
	// AuthUserPassRef is the unresolved `auth-user-pass <file>` argument.
	AuthUserPassRef string
	// RequiresUserPass records that the profile asks for a username/password.
	// It is true for inline blocks, a bare directive and a file reference.
	RequiresUserPass bool
	// ExternalRefs lists CA/cert/key/tls-auth/tls-crypt files resolved from the
	// profile directory, so an importer can report what was packaged.
	ExternalRefs []string

	Compression        string
	CompressionLZO     string
	PingInterval       int
	PingRestart        int
	RenegotiateSeconds int
	ExplicitExitNotify int
	Address            string // ifconfig CIDR, if the profile pins one

	Warnings []string
}

// ParseFile reads and parses an .ovpn file. External references (CA/cert/key/
// tls-auth/tls-crypt/auth-user-pass) are resolved through a resolver confined to
// the profile directory: absolute paths, parent traversal, symlink escapes,
// non-regular files and oversized files are rejected. The returned Profile
// never holds paths except AuthUserPassRef for diagnostics.
func ParseFile(path string) (*Profile, error) {
	data, err := readProfileFile(path)
	if err != nil {
		return nil, err
	}
	return parseProfileFile(path, data)
}

// parseProfileFile validates one already-read profile snapshot. PackageFile uses
// the same function so packaging can never validate different bytes than it
// writes, and each profile gets exactly one read.
func parseProfileFile(path string, data []byte) (*Profile, error) {
	resolver, err := newConfinedResolver(filepath.Dir(path), maxSecretSize)
	if err != nil {
		return nil, err
	}
	defer resolver.Close()
	resolve := resolver.Resolve

	p, err := parse(string(data), resolve)
	if err != nil {
		return nil, err
	}
	if p.AuthUserPassRef != "" {
		content, err := resolve(p.AuthUserPassRef)
		if err != nil {
			return nil, err
		}
		user, pass, err := parseCredentials(content)
		if err != nil {
			return nil, fmt.Errorf("auth-user-pass file %q: %w", p.AuthUserPassRef, err)
		}
		p.Username, p.Password = user, pass
	}
	return p, nil
}

// Parse parses profile text without resolving file references. Profiles that
// reference external files must be loaded with ParseFile.
func Parse(content string) (*Profile, error) {
	return parse(content, nil)
}

func parse(content string, resolve func(string) (string, error)) (*Profile, error) {
	p := &Profile{}
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var blockTag string
	var blockLines []string

	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)

		if blockTag != "" {
			if strings.EqualFold(line, "</"+blockTag+">") {
				if err := p.consumeBlock(blockTag, strings.Join(blockLines, "\n")); err != nil {
					return nil, err
				}
				blockTag, blockLines = "", nil
				continue
			}
			blockLines = append(blockLines, raw)
			continue
		}

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") {
			if strings.HasPrefix(line, "</") {
				return nil, fmt.Errorf("unexpected closing tag %s", line)
			}
			tag := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch tag {
			case "ca", "cert", "key", "tls-auth", "tls-crypt", "auth-user-pass":
				blockTag, blockLines = tag, nil
			default:
				return nil, fmt.Errorf("unsupported inline OpenVPN block <%s>", tag)
			}
			continue
		}

		if err := p.consumeDirective(line, resolve); err != nil {
			return nil, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading OpenVPN profile: %w", err)
	}
	if blockTag != "" {
		return nil, fmt.Errorf("unterminated inline block <%s>", blockTag)
	}

	if len(p.Remotes) == 0 {
		return nil, fmt.Errorf("OpenVPN profile has no remote server")
	}
	if p.Device != "" && p.Device != "tun" && !strings.HasPrefix(p.Device, "tun") {
		return nil, fmt.Errorf("OpenVPN device %q is not supported (TAP/L2 requires host bridging)", p.Device)
	}
	if p.Proto == "" {
		p.Proto = p.Remotes[0].Network
	}
	if p.Proto == "" {
		p.Proto = "udp"
	}
	// Profiles commonly place `remote` before `proto`; remotes without an
	// explicit protocol inherit the final profile-wide value.
	for i := range p.Remotes {
		if p.Remotes[i].Network == "" {
			p.Remotes[i].Network = p.Proto
		}
	}
	if p.Auth == "" {
		p.Auth = "SHA1"
	}
	return p, nil
}

func (p *Profile) consumeBlock(tag, content string) error {
	content = strings.TrimSpace(content)
	if content == "" {
		return fmt.Errorf("empty inline block <%s>", tag)
	}
	switch tag {
	case "ca":
		if err := validatePEM(content); err != nil {
			return fmt.Errorf("<ca>: %w", err)
		}
		p.CACerts = append(p.CACerts, content)
	case "cert":
		if err := validatePEM(content); err != nil {
			return fmt.Errorf("<cert>: %w", err)
		}
		p.ClientCert = content
	case "key":
		if err := validatePEM(content); err != nil {
			return fmt.Errorf("<key>: %w", err)
		}
		p.ClientKey = content
	case "tls-auth", "tls-crypt":
		if err := validatePEM(content); err != nil {
			return fmt.Errorf("<%s>: %w", tag, err)
		}
		p.ControlWrapType = strings.ReplaceAll(tag, "-", "_")
		p.ControlWrapKey = content
	case "auth-user-pass":
		p.RequiresUserPass = true
		user, pass, err := parseCredentials(content)
		if err != nil {
			return err
		}
		p.Username, p.Password = user, pass
	default:
		return fmt.Errorf("unsupported inline OpenVPN block <%s>", tag)
	}
	return nil
}

func (p *Profile) consumeDirective(line string, resolve func(string) (string, error)) error {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}
	name := strings.ToLower(fields[0])
	args := fields[1:]
	arg := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}

	switch name {
	// Harmless client bookkeeping.
	case "client", "tls-client", "nobind", "persist-key", "persist-tun",
		"auth-nocache", "mute", "mute-replay-warnings", "push-peer-info",
		"resolv-retry", "remap-usr1", "single-session", "verb", "rcvbuf", "sndbuf",
		"auth-retry", "tls-exit", "tls-timeout", "hand-window", "connect-retry",
		"connect-retry-max", "connect-timeout", "float", "pull":
		return nil

	case "remote-random":
		p.RemoteRandom = true
		return nil

	case "dev":
		dev := strings.ToLower(arg(0))
		if strings.HasPrefix(dev, "tap") {
			return fmt.Errorf("OpenVPN TAP device is not supported (L2 requires host bridging)")
		}
		p.Device = dev
		return nil

	case "dev-type":
		dev := strings.ToLower(arg(0))
		if dev == "tap" {
			return fmt.Errorf("OpenVPN TAP device is not supported (L2 requires host bridging)")
		}
		if dev == "tun" {
			p.Device = "tun"
		}
		return nil

	case "proto":
		net, err := normalizeProto(arg(0))
		if err != nil {
			return err
		}
		p.Proto = net
		return nil

	case "remote":
		host := arg(0)
		if host == "" {
			return fmt.Errorf("remote directive is missing a host")
		}
		port := 1194
		if v := arg(1); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 || n > 65535 {
				return fmt.Errorf("remote directive has an invalid port")
			}
			port = n
		}
		net := p.Proto
		if v := arg(2); v != "" {
			n, err := normalizeProto(v)
			if err != nil {
				return err
			}
			net = n
		}
		p.Remotes = append(p.Remotes, Remote{Host: host, Port: port, Network: net})
		return nil

	case "auth":
		p.Auth = strings.ToUpper(arg(0))
		return nil

	case "cipher":
		p.Cipher = arg(0)
		return nil

	case "data-ciphers":
		p.DataCiphers = splitCiphers(arg(0))
		return nil

	case "data-ciphers-fallback":
		p.DataCiphersFallback = arg(0)
		return nil

	case "remote-cert-tls":
		v := strings.ToLower(arg(0))
		switch v {
		case "server":
			p.RemoteCertTLS = "server"
		case "client":
			return fmt.Errorf("remote-cert-tls client is not valid for a client profile")
		case "none", "":
		default:
			return fmt.Errorf("unsupported remote-cert-tls value")
		}
		return nil

	case "verify-x509-name":
		p.VerifyX509Name = arg(0)
		p.VerifyX509Type = arg(1)
		return nil

	case "tls-version-min":
		p.TLSVersionMin = normalizeTLSVersion(arg(0))
		return nil

	case "tls-version-max":
		p.TLSVersionMax = normalizeTLSVersion(arg(0))
		return nil

	case "tls-cipher":
		p.TLSCipher = arg(0)
		return nil

	case "key-direction":
		v, err := normalizeKeyDirection(arg(0))
		if err != nil {
			return err
		}
		p.ControlWrapDirection = v
		return nil

	case "explicit-exit-notify":
		n := 1
		if v := arg(0); v != "" {
			parsed, err := strconv.Atoi(v)
			if err != nil || parsed < 0 {
				return fmt.Errorf("explicit-exit-notify has an invalid value")
			}
			n = parsed
		}
		p.ExplicitExitNotify = n
		return nil

	case "ping":
		p.PingInterval = atoiOrZero(arg(0))
		return nil
	case "ping-restart", "ping-exit":
		p.PingRestart = atoiOrZero(arg(0))
		return nil
	case "reneg-sec":
		p.RenegotiateSeconds = atoiOrZero(arg(0))
		return nil

	case "comp-lzo":
		v := strings.ToLower(arg(0))
		switch v {
		case "", "yes", "adaptive", "no":
			p.CompressionLZO = v
			if v == "" {
				p.CompressionLZO = "yes"
			}
		default:
			return fmt.Errorf("unsupported comp-lzo mode")
		}
		return nil

	case "compress":
		v := strings.ToLower(arg(0))
		switch v {
		case "", "lz4", "lz4-v2", "stub", "stub-v2", "no":
			p.Compression = v
			if v == "" {
				p.Compression = "stub"
			}
		default:
			return fmt.Errorf("unsupported compress mode")
		}
		return nil

	case "ifconfig":
		p.Address = dottedNetmaskToCIDR(arg(0), arg(1))
		return nil

	case "auth-user-pass":
		p.RequiresUserPass = true
		if len(args) > 0 {
			p.AuthUserPassRef = args[0]
		}
		return nil

	// External PEM references: only allowed through ParseFile, which resolves
	// them relative to the profile directory.
	case "ca", "cert", "key", "tls-auth", "tls-crypt":
		ref := arg(0)
		if ref == "" {
			return fmt.Errorf("%s directive is missing a file path", name)
		}
		if resolve == nil {
			return fmt.Errorf("%s references external file %q; use ParseFile", name, ref)
		}
		content, err := resolve(ref)
		if err != nil {
			return err
		}
		p.ExternalRefs = append(p.ExternalRefs, ref)
		if err := validatePEM(content); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		switch name {
		case "ca":
			p.CACerts = append(p.CACerts, strings.TrimSpace(content))
		case "cert":
			p.ClientCert = strings.TrimSpace(content)
		case "key":
			p.ClientKey = strings.TrimSpace(content)
		case "tls-auth", "tls-crypt":
			p.ControlWrapType = strings.ReplaceAll(name, "-", "_")
			p.ControlWrapKey = strings.TrimSpace(content)
			if dir := arg(1); dir != "" {
				v, err := normalizeKeyDirection(dir)
				if err != nil {
					return err
				}
				p.ControlWrapDirection = v
			}
		}
		return nil

	// Host-mutating or runtime directives: never applied. bypath runs the
	// endpoint on an internal stack with route_no_pull, so host routes and DNS
	// are untouched. Recorded as warnings, not silently accepted as features.
	case "route", "route-ipv6", "route-gateway", "route-metric", "route-delay",
		"route-nopull", "redirect-gateway", "redirect-private", "block-outside-dns",
		"dhcp-option", "dhcp-renew", "dhcp-release", "register-dns", "ip-win32",
		"tap-sleep", "pull-filter", "setenv", "setenv-safe":
		p.Warnings = append(p.Warnings, fmt.Sprintf("ignored host/runtime directive %q (bypath routes internally)", name))
		return nil

	// Executable or privilege-changing directives are a hard reject.
	case "script-security", "up", "up-restart", "down", "down-pre", "ipchange",
		"route-up", "route-pre-down", "plugin", "tls-verify", "tls-export-cert",
		"auth-user-pass-verify", "client-connect", "client-disconnect",
		"learn-address", "chroot", "user", "group", "setgid", "setuid", "cd",
		"daemon", "syslog", "log", "log-append", "status", "askpass",
		"management", "management-client", "secret", "engine", "providers":
		return fmt.Errorf("refusing unsafe OpenVPN directive %q: bypath never executes profile scripts or changes host state", name)

	default:
		return fmt.Errorf("unsupported OpenVPN directive %q", name)
	}
}

// normalizeKeyDirection maps OpenVPN's numeric directions (0/1) to the
// client/server values sing-box accepts.
func normalizeKeyDirection(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "client", "1":
		return "client", nil
	case "server", "0":
		return "server", nil
	default:
		return "", fmt.Errorf("key-direction must be client or server")
	}
}

func normalizeProto(v string) (string, error) {
	switch strings.ToLower(v) {
	case "tcp", "tcp-client", "tcp4", "tcp6":
		return "tcp", nil
	case "udp", "udp4", "udp6":
		return "udp", nil
	default:
		return "", fmt.Errorf("unsupported OpenVPN protocol %q", v)
	}
}

func normalizeTLSVersion(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	switch {
	case strings.HasPrefix(v, "1.0"):
		return "1.0"
	case strings.HasPrefix(v, "1.1"):
		return "1.1"
	case strings.HasPrefix(v, "1.2"):
		return "1.2"
	case strings.HasPrefix(v, "1.3"):
		return "1.3"
	}
	return v
}

func splitCiphers(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ":") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func atoiOrZero(v string) int {
	n, _ := strconv.Atoi(v)
	return n
}

// CredentialsFromFile reads a username/password file (line 1 user, line 2 pass).
func CredentialsFromFile(path string) (string, string, error) {
	f, err := openProfileFile(path)
	if err != nil {
		return "", "", fmt.Errorf("reading OpenVPN credentials: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", "", fmt.Errorf("reading OpenVPN credentials: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", "", fmt.Errorf("OpenVPN credentials file is not a regular file")
	}
	data, err := readLimited(f, maxCredentialsSize)
	if err != nil {
		return "", "", fmt.Errorf("reading OpenVPN credentials: %w", err)
	}
	user, pass, err := parseCredentials(string(data))
	if err != nil {
		return "", "", fmt.Errorf("OpenVPN credentials: %w", err)
	}
	return user, pass, nil
}

func parseCredentials(content string) (string, string, error) {
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")
	if len(lines) < 2 {
		return "", "", fmt.Errorf("credentials must contain a username line and a password line")
	}
	user := strings.TrimSpace(lines[0])
	pass := strings.TrimSpace(lines[1])
	if user == "" || pass == "" {
		return "", "", fmt.Errorf("credentials contain an empty username or password")
	}
	return user, pass, nil
}

func validatePEM(content string) error {
	rest := []byte(strings.TrimSpace(content))
	if len(rest) == 0 {
		return fmt.Errorf("empty PEM data")
	}
	found := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		found = true
	}
	if !found {
		return fmt.Errorf("invalid PEM data")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return fmt.Errorf("invalid trailing data after PEM block")
	}
	return nil
}

// dottedNetmaskToCIDR converts OpenVPN ifconfig arguments to CIDR.
func dottedNetmaskToCIDR(addr, mask string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return ""
	}
	m := net.ParseIP(mask)
	if m == nil {
		return ""
	}
	m4 := m.To4()
	if m4 == nil || ip.To4() == nil {
		return ""
	}
	ones, bits := net.IPMask(m4).Size()
	if bits == 0 {
		return ""
	}
	return fmt.Sprintf("%s/%d", addr, ones)
}
