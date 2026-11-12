package openvpn

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// syntheticPEM builds a structurally valid PEM block with a marker payload.
// The DER body is meaningless: the parser validates container structure, not
// certificate contents.
func pemBody(marker string) string {
	return base64.StdEncoding.EncodeToString([]byte(marker))
}

func syntheticPEM(label, marker string) string {
	return "-----BEGIN " + label + "-----\n" +
		base64.StdEncoding.EncodeToString([]byte(marker)) + "\n" +
		"-----END " + label + "-----"
}

func TestParseInlineProfile(t *testing.T) {
	content := strings.Join([]string{
		"client",
		"dev tun",
		"proto udp",
		"remote vpn.example.net 443",
		"resolv-retry infinite",
		"nobind",
		"persist-key",
		"persist-tun",
		"auth SHA512",
		"auth-nocache",
		"data-ciphers AES-256-GCM:AES-192-GCM:AES-128-GCM",
		"data-ciphers-fallback AES-256-GCM",
		"remote-cert-tls server",
		"explicit-exit-notify 5",
		"ping 10",
		"ping-restart 60",
		"reneg-sec 3600",
		"verb 3",
		"<ca>",
		syntheticPEM("CERTIFICATE", "ca-synthetic"),
		"</ca>",
		"<cert>",
		syntheticPEM("CERTIFICATE", "client-synthetic"),
		"</cert>",
		"<key>",
		syntheticPEM("PRIVATE KEY", "key-synthetic"),
		"</key>",
		"<tls-crypt>",
		syntheticPEM("OpenVPN Static key V1", "tls-crypt-synthetic"),
		"</tls-crypt>",
		"key-direction client",
		"<auth-user-pass>",
		"test-user",
		"test-pass",
		"</auth-user-pass>",
	}, "\n")

	p, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(p.Remotes) != 1 || p.Remotes[0].Host != "vpn.example.net" || p.Remotes[0].Port != 443 || p.Remotes[0].Network != "udp" {
		t.Fatalf("unexpected remotes: %+v", p.Remotes)
	}
	if p.Proto != "udp" || p.Device != "tun" {
		t.Fatalf("proto/device = %q/%q", p.Proto, p.Device)
	}
	if p.Auth != "SHA512" {
		t.Fatalf("auth = %q", p.Auth)
	}
	if got := strings.Join(p.DataCiphers, ":"); got != "AES-256-GCM:AES-192-GCM:AES-128-GCM" {
		t.Fatalf("data-ciphers = %q", got)
	}
	if p.DataCiphersFallback != "AES-256-GCM" {
		t.Fatalf("fallback = %q", p.DataCiphersFallback)
	}
	if p.RemoteCertTLS != "server" {
		t.Fatalf("remote-cert-tls = %q", p.RemoteCertTLS)
	}
	if p.PingInterval != 10 || p.PingRestart != 60 || p.RenegotiateSeconds != 3600 {
		t.Fatalf("timers = %d/%d/%d", p.PingInterval, p.PingRestart, p.RenegotiateSeconds)
	}
	if p.ExplicitExitNotify != 5 {
		t.Fatalf("explicit-exit-notify = %d", p.ExplicitExitNotify)
	}
	if len(p.CACerts) != 1 || !strings.Contains(p.CACerts[0], pemBody("ca-synthetic")) {
		t.Fatalf("ca not loaded: %#v", p.CACerts)
	}
	if !strings.Contains(p.ClientCert, pemBody("client-synthetic")) || !strings.Contains(p.ClientKey, pemBody("key-synthetic")) {
		t.Fatalf("client material not loaded")
	}
	if p.ControlWrapType != "tls_crypt" || !strings.Contains(p.ControlWrapKey, pemBody("tls-crypt-synthetic")) {
		t.Fatalf("control wrap = %q", p.ControlWrapType)
	}
	if p.ControlWrapDirection != "client" {
		t.Fatalf("key-direction = %q", p.ControlWrapDirection)
	}
	if p.Username != "test-user" || p.Password != "test-pass" {
		t.Fatalf("credentials not parsed")
	}
	if len(p.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", p.Warnings)
	}
}

func TestParseMultipleRemotesAndNetworkOptions(t *testing.T) {
	content := `
client
remote-random
remote vpn1.example.net 1194
remote vpn2.example.net 443 tcp
tls-version-min 1.2
tls-version-max 1.3
tls-cipher TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384
verify-x509-name vpn.example.net name
ifconfig 10.8.0.2 255.255.255.0
compress lz4-v2
comp-lzo adaptive
`
	p, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.RemoteRandom || len(p.Remotes) != 2 {
		t.Fatalf("remotes = %+v random=%v", p.Remotes, p.RemoteRandom)
	}
	if p.Remotes[1].Network != "tcp" || p.Remotes[1].Port != 443 {
		t.Fatalf("second remote = %+v", p.Remotes[1])
	}
	if p.TLSVersionMin != "1.2" || p.TLSVersionMax != "1.3" {
		t.Fatalf("tls versions = %q/%q", p.TLSVersionMin, p.TLSVersionMax)
	}
	if p.VerifyX509Name != "vpn.example.net" || p.VerifyX509Type != "name" {
		t.Fatalf("verify-x509-name = %q/%q", p.VerifyX509Name, p.VerifyX509Type)
	}
	if p.Address != "10.8.0.2/24" {
		t.Fatalf("ifconfig address = %q", p.Address)
	}
	if p.Compression != "lz4-v2" || p.CompressionLZO != "adaptive" {
		t.Fatalf("compression = %q/%q", p.Compression, p.CompressionLZO)
	}
}

func TestParseRejectsUnsafeDirectives(t *testing.T) {
	unsafe := []string{
		"script-security 2",
		"up /tmp/payload.sh",
		"up-restart /tmp/payload.sh",
		"down /tmp/payload.sh",
		"route-up /tmp/payload.sh",
		"plugin /tmp/evil.so",
		"tls-verify /tmp/verify.sh",
		"auth-user-pass-verify /tmp/check.sh via-env",
		"management 127.0.0.1 7505",
		"secret static.key",
		"log /var/log/openvpn.log",
		"user nobody",
		"chroot /tmp",
	}
	for _, directive := range unsafe {
		content := "client\nremote vpn.example.net 1194\n" + directive + "\n"
		if _, err := Parse(content); err == nil {
			t.Errorf("%q was accepted, want rejection", directive)
		} else if !strings.Contains(err.Error(), "unsafe") {
			t.Errorf("%q: error %v does not mention unsafe rejection", directive, err)
		}
	}
}

func TestParseRemoteInheritsProtoDeclaredLater(t *testing.T) {
	// OpenVPN emits `remote` before `proto`; an empty remote network must inherit
	// the profile-wide protocol instead of silently defaulting to UDP.
	for proto, want := range map[string]string{"tcp": "tcp", "udp": "udp"} {
		p, err := Parse("client\nremote vpn.example.net 443\nproto " + proto + "\n")
		if err != nil {
			t.Fatalf("Parse(%s): %v", proto, err)
		}
		if p.Proto != want {
			t.Fatalf("profile proto = %q, want %q", p.Proto, want)
		}
		if len(p.Remotes) != 1 || p.Remotes[0].Network != want {
			t.Fatalf("remote network = %+v, want %q", p.Remotes, want)
		}
	}

	// An explicit per-remote protocol wins over the profile default.
	p, err := Parse("client\nremote vpn.example.net 443 tcp\nproto udp\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Remotes[0].Network != "tcp" {
		t.Fatalf("explicit remote network = %q, want tcp", p.Remotes[0].Network)
	}
}

func TestParseRejectsUnknownDirective(t *testing.T) {
	_, err := Parse("client\nremote vpn.example.net 1194\nfrobnicate yes\n")
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("err = %v, want unsupported directive error", err)
	}
}

func TestParseIgnoresHostMutatingDirectives(t *testing.T) {
	content := `
client
dev tun
remote vpn.example.net 1194
redirect-gateway def1
route 10.0.0.0 255.0.0.0
dhcp-option DNS 10.8.0.1
block-outside-dns
setenv UV_IPV6 yes
pull-filter ignore "route-ipv6"
`
	p, err := Parse(content)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(p.Warnings) != 6 {
		t.Fatalf("warnings = %v, want 6", p.Warnings)
	}
	for _, w := range p.Warnings {
		if !strings.Contains(w, "ignored") {
			t.Fatalf("unexpected warning %q", w)
		}
	}
}

func TestParseRejectsTAP(t *testing.T) {
	for _, dev := range []string{"dev tap0", "dev-type tap"} {
		if _, err := Parse("client\nremote vpn.example.net 1194\n" + dev + "\n"); err == nil {
			t.Fatalf("%q accepted, want TAP rejection", dev)
		}
	}
}

func TestParseRequiresRemote(t *testing.T) {
	if _, err := Parse("client\ndev tun\n"); err == nil {
		t.Fatal("profile without remote accepted")
	}
}

func TestParseRejectsUnterminatedBlock(t *testing.T) {
	_, err := Parse("client\nremote vpn.example.net 1194\n<ca>\n")
	if err == nil || !strings.Contains(err.Error(), "unterminated") {
		t.Fatalf("err = %v, want unterminated block", err)
	}
}

func TestParseRejectsUnsupportedBlock(t *testing.T) {
	_, err := Parse("client\nremote vpn.example.net 1194\n<connection>\nremote vpn.example.net 1194\n</connection>\n")
	if err == nil || !strings.Contains(err.Error(), "unsupported inline") {
		t.Fatalf("err = %v, want unsupported inline block", err)
	}
}

func TestParseRejectsMalformedPEM(t *testing.T) {
	for _, block := range []string{"<ca>", "<cert>", "<key>", "<tls-auth>", "<tls-crypt>"} {
		closing := strings.Replace(block, "<", "</", 1)
		content := "client\nremote vpn.example.net 1194\n" + block + "\nnot-a-pem\n" + closing + "\n"
		if _, err := Parse(content); err == nil {
			t.Fatalf("%s with garbage accepted", block)
		}
	}
}

func TestParseRejectsInvalidProtocolAndTLSVersion(t *testing.T) {
	if _, err := Parse("client\nremote vpn.example.net 1194\nproto sctp\n"); err == nil {
		t.Fatal("sctp protocol accepted")
	}
	if _, err := Parse("client\nremote vpn.example.net 1194\nkey-direction sideways\n"); err == nil {
		t.Fatal("invalid key-direction accepted")
	}
}

func TestParseFileResolvesExternalReferences(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("ca.crt", syntheticPEM("CERTIFICATE", "ca-external"))
	write("client.crt", syntheticPEM("CERTIFICATE", "cert-external"))
	write("client.key", syntheticPEM("PRIVATE KEY", "key-external"))
	write("ta.key", syntheticPEM("OpenVPN Static key V1", "ta-external"))
	write("creds.txt", "file-user\nfile-pass\n")

	profilePath := filepath.Join(dir, "profile.ovpn")
	ovpn := strings.Join([]string{
		"client",
		"dev tun",
		"remote vpn.example.net 1194",
		"ca ca.crt",
		"cert client.crt",
		"key client.key",
		"tls-auth ta.key 1",
		"auth-user-pass creds.txt",
	}, "\n")
	if err := os.WriteFile(profilePath, []byte(ovpn), 0600); err != nil {
		t.Fatal(err)
	}

	p, err := ParseFile(profilePath)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(p.CACerts) != 1 || !strings.Contains(p.CACerts[0], pemBody("ca-external")) {
		t.Fatalf("external ca not loaded")
	}
	if !strings.Contains(p.ClientCert, pemBody("cert-external")) || !strings.Contains(p.ClientKey, pemBody("key-external")) {
		t.Fatalf("external client material not loaded")
	}
	if p.ControlWrapType != "tls_auth" || !strings.Contains(p.ControlWrapKey, pemBody("ta-external")) {
		t.Fatalf("external tls-auth not loaded: %q", p.ControlWrapType)
	}
	if p.ControlWrapDirection != "client" {
		t.Fatalf("tls-auth direction = %q, want client", p.ControlWrapDirection)
	}
	if p.Username != "file-user" || p.Password != "file-pass" {
		t.Fatalf("external credentials not loaded")
	}

	if _, err := Parse(ovpn); err == nil || !strings.Contains(err.Error(), "ParseFile") {
		t.Fatalf("Parse with external refs err = %v, want ParseFile guidance", err)
	}
}

func TestCredentialsFromFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.txt")
	if err := os.WriteFile(good, []byte("alice\r\ns3cret\r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	user, pass, err := CredentialsFromFile(good)
	if err != nil || user != "alice" || pass != "s3cret" {
		t.Fatalf("credentials = %q/%q err=%v", user, pass, err)
	}

	cases := map[string]string{
		"only-user":  "alice\n",
		"empty-user": "\ns3cret\n",
		"empty-pass": "alice\n\n",
	}
	for name, content := range cases {
		path := filepath.Join(dir, name+".txt")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := CredentialsFromFile(path); err == nil {
			t.Errorf("%s accepted, want error", name)
		}
	}
	if _, _, err := CredentialsFromFile(filepath.Join(dir, "missing.txt")); err == nil {
		t.Error("missing credentials file accepted")
	}
}

func TestParseErrorsDoNotLeakSecretMaterial(t *testing.T) {
	secret := "SUPERSECRET-" + strings.Repeat("x", 24)
	content := strings.Join([]string{
		"client",
		"remote vpn.example.net 1194",
		"<key>",
		syntheticPEM("PRIVATE KEY", secret),
		"</key>",
		"script-security 2",
	}, "\n")
	_, err := Parse(content)
	if err == nil {
		t.Fatal("unsafe profile accepted")
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), base64.StdEncoding.EncodeToString([]byte(secret))) {
		t.Fatalf("error leaked secret material: %v", err)
	}
}

func TestNormalizeTLSVersion(t *testing.T) {
	cases := map[string]string{
		"1.2":    "1.2",
		"1.2.3":  "1.2",
		"tls1.3": "tls1.3",
		"1.10":   "1.1",
		" 1.0 ":  "1.0",
	}
	for in, want := range cases {
		if got := normalizeTLSVersion(in); got != want {
			t.Errorf("normalizeTLSVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
