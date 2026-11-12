package tunnel

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/securefile"
)

func cfgTestPEM(label, marker string) string {
	return "-----BEGIN " + label + "-----\n" +
		base64.StdEncoding.EncodeToString([]byte(marker)) + "\n" +
		"-----END " + label + "-----"
}

type openVPNFixture struct {
	profilePath string
	caPEM       string
	certPEM     string
	keyPEM      string
	wrapPEM     string
}

func writeOpenVPNFixture(t *testing.T, body []string) openVPNFixture {
	t.Helper()
	dir := t.TempDir()
	f := openVPNFixture{
		caPEM:   cfgTestPEM("CERTIFICATE", "ca-fixture"),
		certPEM: cfgTestPEM("CERTIFICATE", "cert-fixture"),
		keyPEM:  cfgTestPEM("PRIVATE KEY", "key-fixture"),
		wrapPEM: cfgTestPEM("OpenVPN Static key V1", "wrap-fixture"),
	}
	lines := append([]string{
		"client",
		"dev tun",
		"<ca>", f.caPEM, "</ca>",
		"<cert>", f.certPEM, "</cert>",
		"<key>", f.keyPEM, "</key>",
		"<tls-crypt>", f.wrapPEM, "</tls-crypt>",
	}, body...)
	f.profilePath = filepath.Join(dir, "fixture.ovpn")
	if err := os.WriteFile(f.profilePath, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func defaultOpenVPNBody() []string {
	return []string{
		"proto udp",
		"remote vpn.example.net 443",
		"auth SHA512",
		"data-ciphers AES-256-GCM:AES-128-GCM",
		"data-ciphers-fallback AES-256-GCM",
		"remote-cert-tls server",
		"explicit-exit-notify 5",
		"ping 10",
		"ping-restart 60",
		"reneg-sec 3600",
		"key-direction client",
		"<auth-user-pass>", "fixture-user", "fixture-pass", "</auth-user-pass>",
		"verb 3",
	}
}

func openVPNLink(f openVPNFixture) *profile.Link {
	return &profile.Link{
		Protocol: "openvpn",
		Remark:   "fixture",
		Address:  "vpn.example.net",
		Port:     443,
		Network:  "udp",
		OVPNPath: f.profilePath,
	}
}

func generateOpenVPNConfig(t *testing.T, link *profile.Link) (string, map[string]interface{}) {
	t.Helper()
	cg := NewConfigGenerator(t.TempDir())
	path, err := cg.Generate(&engine.Engine{Name: "sing-box"}, link)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("config is not valid JSON: %v", err)
	}
	return path, cfg
}

func firstEndpoint(t *testing.T, cfg map[string]interface{}) map[string]interface{} {
	t.Helper()
	endpoints, ok := cfg["endpoints"].([]interface{})
	if !ok || len(endpoints) != 1 {
		t.Fatalf("endpoints = %#v, want exactly one", cfg["endpoints"])
	}
	ep, ok := endpoints[0].(map[string]interface{})
	if !ok {
		t.Fatalf("endpoint is not an object")
	}
	return ep
}

func TestOpenVPNConfigEndpointShape(t *testing.T) {
	f := writeOpenVPNFixture(t, defaultOpenVPNBody())
	link := openVPNLink(f)
	link.ListenPort = 2811

	path, cfg := generateOpenVPNConfig(t, link)
	ep := firstEndpoint(t, cfg)

	if ep["type"] != "openvpn-client" || ep["tag"] != "proxy" {
		t.Fatalf("endpoint identity = %v/%v", ep["type"], ep["tag"])
	}
	if ep["route_no_pull"] != true {
		t.Fatalf("route_no_pull = %v, want true", ep["route_no_pull"])
	}
	if _, ok := ep["system"]; ok {
		t.Fatalf("system stack must not be requested: %v", ep["system"])
	}
	if ep["server"] != "vpn.example.net" || ep["server_port"] != float64(443) || ep["network"] != "udp" {
		t.Fatalf("remote mapping = %v:%v/%v", ep["server"], ep["server_port"], ep["network"])
	}
	if ep["auth"] != "SHA512" || ep["data_ciphers_fallback"] != "AES-256-GCM" {
		t.Fatalf("crypto mapping = %v/%v", ep["auth"], ep["data_ciphers_fallback"])
	}
	ciphers, _ := ep["data_ciphers"].([]interface{})
	if len(ciphers) != 2 || ciphers[0] != "AES-256-GCM" || ciphers[1] != "AES-128-GCM" {
		t.Fatalf("data_ciphers = %v", ep["data_ciphers"])
	}
	if ep["explicit_exit_notify"] != float64(5) {
		t.Fatalf("explicit_exit_notify = %v", ep["explicit_exit_notify"])
	}
	if ep["ping_interval"] != "10s" || ep["ping_restart"] != "60s" || ep["renegotiate_interval"] != "3600s" {
		t.Fatalf("timers = %v/%v/%v", ep["ping_interval"], ep["ping_restart"], ep["renegotiate_interval"])
	}
	if ep["username"] != "fixture-user" || ep["password"] != "fixture-pass" {
		t.Fatalf("credentials not mapped")
	}

	tls, ok := ep["tls"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing tls section")
	}
	if tls["remote_certificate_tls"] != "server" {
		t.Fatalf("remote_certificate_tls = %v", tls["remote_certificate_tls"])
	}
	wrap, ok := tls["control_wrap"].(map[string]interface{})
	if !ok || wrap["type"] != "tls_crypt" || wrap["direction"] != "client" {
		t.Fatalf("control_wrap = %#v", tls["control_wrap"])
	}

	// Extracted PEM material must live in owner-only files, never in JSON.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"BEGIN CERTIFICATE", "BEGIN PRIVATE KEY", "BEGIN OpenVPN Static key"} {
		if strings.Contains(string(raw), needle) {
			t.Fatalf("generated JSON embeds PEM material (%q)", needle)
		}
	}
	if !securefile.IsOwnerOnly(path) {
		t.Fatal("config is readable by users other than its owner")
	}

	for field, want := range map[string]string{
		"certificate_path":        f.caPEM,
		"client_certificate_path": f.certPEM,
		"client_key_path":         f.keyPEM,
	} {
		p, _ := tls[field].(string)
		if p == "" {
			t.Fatalf("tls.%s missing", field)
		}
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("reading tls.%s: %v", field, err)
		}
		if strings.TrimSpace(string(got)) != strings.TrimSpace(want) {
			t.Fatalf("tls.%s content mismatch", field)
		}
		if !securefile.IsOwnerOnly(p) {
			t.Fatalf("%s is readable by users other than its owner", field)
		}
	}
	if p, _ := wrap["key_path"].(string); p == "" {
		t.Fatalf("control_wrap.key_path missing")
	}
}

func TestOpenVPNConfigRouteAndDNSStayInsideTunnel(t *testing.T) {
	f := writeOpenVPNFixture(t, defaultOpenVPNBody())
	_, cfg := generateOpenVPNConfig(t, openVPNLink(f))

	route, ok := cfg["route"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing route")
	}
	if route["final"] != "proxy" {
		t.Fatalf("route final = %v, want proxy", route["final"])
	}
	resolver, _ := route["default_domain_resolver"].(map[string]interface{})
	if resolver["server"] != "dns-direct" {
		t.Fatalf("default_domain_resolver = %#v, want dns-direct bootstrap", route["default_domain_resolver"])
	}
	rules, _ := route["rules"].([]interface{})
	if len(rules) == 0 {
		t.Fatalf("route has no rules")
	}
	if _, ok := route["auto_detect_interface"]; ok {
		t.Fatalf("non-gateway route must not auto-detect the host interface")
	}

	outbounds, _ := cfg["outbounds"].([]interface{})
	for _, o := range outbounds {
		ob, _ := o.(map[string]interface{})
		if ob["tag"] == "proxy" {
			t.Fatalf("outbound duplicates the endpoint tag: %v", ob)
		}
	}
	if len(outbounds) == 0 || outbounds[0].(map[string]interface{})["tag"] != "direct" {
		t.Fatalf("first outbound must be direct: %v", outbounds)
	}

	dns, ok := cfg["dns"].(map[string]interface{})
	if !ok {
		t.Fatalf("missing dns")
	}
	if dns["final"] != "dns-tunnel" {
		t.Fatalf("dns final = %v, want dns-tunnel", dns["final"])
	}
	servers, _ := dns["servers"].([]interface{})
	first, _ := servers[0].(map[string]interface{})
	if first["tag"] != "dns-tunnel" || first["detour"] != "proxy" || first["type"] != "https" {
		t.Fatalf("primary DNS must traverse the endpoint: %#v", first)
	}

	// The VPN server hostname must resolve directly or the tunnel cannot bootstrap.
	rulesDNS, _ := dns["rules"].([]interface{})
	foundBootstrap := false
	for _, r := range rulesDNS {
		rule, _ := r.(map[string]interface{})
		if rule["server"] != "dns-direct" {
			continue
		}
		domains, _ := rule["domain"].([]interface{})
		for _, d := range domains {
			if d == "vpn.example.net" {
				foundBootstrap = true
			}
		}
	}
	if !foundBootstrap {
		t.Fatalf("server hostname missing from direct DNS bootstrap rules: %v", dns["rules"])
	}

	inbounds, _ := cfg["inbounds"].([]interface{})
	ib, _ := inbounds[0].(map[string]interface{})
	if ib["type"] != "mixed" || ib["listen_port"] != float64(2801) {
		t.Fatalf("inbound = %#v", ib)
	}
}

func TestOpenVPNConfigMultipleRemotes(t *testing.T) {
	f := writeOpenVPNFixture(t, []string{
		"remote-random",
		"remote vpn1.example.net 1194",
		"remote vpn2.example.net 443 tcp",
	})
	_, cfg := generateOpenVPNConfig(t, openVPNLink(f))
	ep := firstEndpoint(t, cfg)

	if _, ok := ep["server"]; ok {
		t.Fatalf("single-server fields must not be set for a multi-remote profile")
	}
	if ep["remote_random"] != true {
		t.Fatalf("remote_random = %v", ep["remote_random"])
	}
	servers, _ := ep["servers"].([]interface{})
	if len(servers) != 2 {
		t.Fatalf("servers = %v", ep["servers"])
	}
	second, _ := servers[1].(map[string]interface{})
	if second["server"] != "vpn2.example.net" || second["server_port"] != float64(443) || second["network"] != "tcp" {
		t.Fatalf("second server = %#v", second)
	}
}

func TestOpenVPNConfigAuthFileOverride(t *testing.T) {
	body := []string{"proto udp", "remote vpn.example.net 1194"}
	f := writeOpenVPNFixture(t, body)
	authFile := filepath.Join(filepath.Dir(f.profilePath), "auth.txt")
	if err := os.WriteFile(authFile, []byte("file-user\nfile-pass\n"), 0600); err != nil {
		t.Fatal(err)
	}
	link := openVPNLink(f)
	link.OVPNAuthUserPassFile = authFile

	_, cfg := generateOpenVPNConfig(t, link)
	ep := firstEndpoint(t, cfg)
	if ep["username"] != "file-user" || ep["password"] != "file-pass" {
		t.Fatalf("auth file override not applied")
	}
}

func TestOpenVPNConfigRejectsWrongEngine(t *testing.T) {
	f := writeOpenVPNFixture(t, defaultOpenVPNBody())
	cg := NewConfigGenerator(t.TempDir())
	_, err := cg.Generate(&engine.Engine{Name: "xray"}, openVPNLink(f))
	if err == nil || !strings.Contains(err.Error(), "sing-box") {
		t.Fatalf("err = %v, want sing-box requirement", err)
	}
}

func TestOpenVPNConfigRequiresProfilePath(t *testing.T) {
	link := &profile.Link{Protocol: "openvpn", Address: "vpn.example.net", Port: 1194}
	cg := NewConfigGenerator(t.TempDir())
	_, err := cg.Generate(&engine.Engine{Name: "sing-box"}, link)
	if err == nil || !strings.Contains(err.Error(), ".ovpn") {
		t.Fatalf("err = %v, want missing profile error", err)
	}
}

func TestOpenVPNValidateEngineSupportVersionGate(t *testing.T) {
	f := writeOpenVPNFixture(t, defaultOpenVPNBody())
	link := openVPNLink(f)

	// Descriptor engines have no binary path, so the version probe is skipped.
	if err := ValidateEngineSupport(&engine.Engine{Name: "sing-box"}, link); err != nil {
		t.Fatalf("descriptor sing-box rejected: %v", err)
	}
	if err := ValidateEngineSupport(&engine.Engine{Name: "openvpn", Path: "openvpn"}, link); err == nil {
		t.Fatalf("native openvpn engine accepted")
	}
}

func TestOpenVPNSecretsLiveInPerGenerationDir(t *testing.T) {
	f := writeOpenVPNFixture(t, defaultOpenVPNBody())
	root := t.TempDir()
	cg := NewConfigGenerator(root)
	link := openVPNLink(f)

	first, err := cg.Generate(&engine.Engine{Name: "sing-box"}, link)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, err := os.ReadFile(first)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	ep := firstEndpoint(t, cfg)
	tls, _ := ep["tls"].(map[string]interface{})
	keyPath, _ := tls["client_key_path"].(string)
	if keyPath == "" {
		t.Fatalf("client key path missing: %#v", tls)
	}
	if filepath.Dir(filepath.Dir(keyPath)) != filepath.Dir(first) {
		t.Fatalf("secret %q is not inside generation dir %q", keyPath, filepath.Dir(first))
	}
	if !securefile.IsOwnerOnly(keyPath) {
		t.Fatalf("secret %s is readable by users other than its owner", keyPath)
	}
	if !securefile.IsOwnerOnly(first) {
		t.Fatalf("config %s is readable by users other than its owner", first)
	}

	// A second generation must not share files with the first.
	second, err := cg.Generate(&engine.Engine{Name: "sing-box"}, link)
	if err != nil {
		t.Fatalf("second Generate: %v", err)
	}
	if filepath.Dir(first) == filepath.Dir(second) {
		t.Fatal("two generations share a directory")
	}

	cg.Cleanup()
	for _, p := range []string{first, second, keyPath} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived cleanup (err=%v)", p, err)
		}
	}
	if _, err := os.Stat(root); err != nil {
		t.Errorf("cleanup removed the temp root: %v", err)
	}
}

func TestDiscardConfigOnlyRemovesOwnedGeneration(t *testing.T) {
	f := writeOpenVPNFixture(t, defaultOpenVPNBody())
	root := t.TempDir()
	cg := NewConfigGenerator(root)
	cfgFile, err := cg.Generate(&engine.Engine{Name: "sing-box"}, openVPNLink(f))
	if err != nil {
		t.Fatal(err)
	}

	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	cg.DiscardConfig(outside)
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("DiscardConfig removed a file outside its temp root: %v", err)
	}
	RemoveGenerationDir(root, outside)
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("RemoveGenerationDir removed an unrelated file: %v", err)
	}

	cg.DiscardConfig(cfgFile)
	if _, err := os.Stat(filepath.Dir(cfgFile)); !os.IsNotExist(err) {
		t.Fatalf("generation dir survived DiscardConfig: %v", err)
	}
}

// A group imported by a portable install records data/profiles/... references.
// The installed daemon must still find the packaged artifact.
func TestOpenVPNConfigResolvesMigratedArtifactPath(t *testing.T) {
	f := writeOpenVPNFixture(t, defaultOpenVPNBody())
	profilesDir := filepath.Dir(f.profilePath)
	link := openVPNLink(f)
	link.OVPNPath = filepath.ToSlash(filepath.Join("data", "profiles", filepath.Base(profilesDir), "fixture.ovpn"))

	cg := NewConfigGenerator(t.TempDir())
	cg.ProfileDir = profilesDir
	path, err := cg.Generate(&engine.Engine{Name: "sing-box"}, link)
	if err != nil {
		t.Fatalf("Generate with migrated path: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestOpenVPNConfigReportsUnresolvableArtifact(t *testing.T) {
	f := writeOpenVPNFixture(t, defaultOpenVPNBody())
	link := openVPNLink(f)
	link.OVPNPath = "data/profiles/ovpn/gone.ovpn"

	cg := NewConfigGenerator(t.TempDir())
	cg.ProfileDir = t.TempDir()
	_, err := cg.Generate(&engine.Engine{Name: "sing-box"}, link)
	if err == nil {
		t.Fatal("missing artifact generated a config")
	}
	if !strings.Contains(err.Error(), "gone.ovpn") || !strings.Contains(err.Error(), "fixture") {
		t.Fatalf("error does not name the link and artifact: %v", err)
	}
}

func TestOpenVPNConfigPinsValidatedEndpoint(t *testing.T) {
	f := writeOpenVPNFixture(t, defaultOpenVPNBody())
	link := openVPNLink(f)
	cg := NewConfigGenerator(t.TempDir())
	cg.PinnedHosts = map[string]string{"vpn.example.net": "192.0.2.45"}
	path, err := cg.Generate(&engine.Engine{Name: "sing-box"}, link)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if got := firstEndpoint(t, cfg)["server"]; got != "192.0.2.45" {
		t.Fatalf("server = %v, want the validated endpoint", got)
	}
}
