package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/credential"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
)

const testVLESS = "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=tls&type=ws#node-a"

func newTestLocal(t *testing.T) (*Local, *paths.Resolved) {
	t.Helper()
	dir := t.TempDir()
	p := &paths.Resolved{
		Mode:       paths.ModeLocal,
		ConfigFile: filepath.Join(dir, "config.yaml"),
		DataDir:    dir,
		ProfileDir: filepath.Join(dir, "profiles"),
		TmpDir:     filepath.Join(dir, "tmp"),
		GeoDir:     filepath.Join(dir, "geo"),
		EngineDir:  filepath.Join(dir, "engines"),
	}
	for _, d := range []string{p.ProfileDir, p.TmpDir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{}
	cfg.Server.APIPort = 8080
	cfg.Server.SOCKSPort = 2801
	cfg.Server.Listen = "127.0.0.1"
	cfg.Gateway.Enabled = true
	cfg.Gateway.DNSMode = "strict"
	cfg.Gateway.DNSUpstream = []string{"1.1.1.1"}
	cfg.HealthCheck.Interval = "30s"
	cfg.Profiles.Directory = p.ProfileDir
	cfg.Profiles.ActiveGroup = "default"

	mgr, err := profile.NewManager(p.ProfileDir, "default")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewLocal(Options{Paths: p, Config: cfg, ConfigPath: p.ConfigFile, Profiles: mgr})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { credential_Reset() })
	return svc, p
}

func credential_Reset() {
	// Keep tests independent: the default store is package-global.
	credential.SetDefault(nil)
}

func TestImportListsAndPreventsDuplicates(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()

	res, err := svc.ImportURI(ctx, "work", testVLESS)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(res.Created) != 1 || res.Created[0].Remark != "node-a" {
		t.Fatalf("unexpected import result: %+v", res)
	}

	dup, err := svc.ImportURI(ctx, "other", testVLESS)
	if err != nil {
		t.Fatalf("duplicate import: %v", err)
	}
	if len(dup.Created) != 0 || len(dup.Skipped) != 1 {
		t.Fatalf("duplicate was not reported: %+v", dup)
	}

	list, err := svc.ListConnections(ctx, ConnectionFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].ID != "work:node-a" {
		t.Fatalf("unexpected list: %+v", list)
	}
	if list[0].Protocol != "vless" || list[0].Engine != "sing-box" {
		t.Fatalf("unexpected protocol/engine: %+v", list[0])
	}
}

func TestImportOpenVPNKeepsDisplayNameSpaces(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	const profile = "client\ndev tun\nproto udp\nremote 203.0.113.20 1194\n"

	res, err := svc.ImportOpenVPN(ctx, OVPNImport{
		OVPNSource: OVPNSource{Text: profile, Name: "Space Test OVPN"},
		Group:      "lab",
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(res.Created) != 1 || res.Created[0].Remark != "Space Test OVPN" {
		t.Fatalf("display name was not preserved: %+v", res)
	}
	if res.Created[0].ID != "lab:Space Test OVPN" {
		t.Fatalf("unexpected id: %+v", res.Created[0])
	}
}

func TestConnectionViewsNeverCarrySecrets(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "default", testVLESS); err != nil {
		t.Fatal(err)
	}
	detail, err := svc.GetConnection(ctx, "default:node-a")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, secret := range []string{"11111111-1111", testVLESS, "example.com:443?"} {
		if strings.Contains(text, secret) {
			t.Fatalf("connection view leaked %q: %s", secret, text)
		}
	}
}

func TestCredentialsSessionThenSaved(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "default", testVLESS); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetCredentials(ctx, "default:node-a", Credentials{Username: "alice", Password: "s3cret"}, false); err != nil {
		t.Fatal(err)
	}
	view, err := svc.GetConnection(ctx, "default:node-a")
	if err != nil {
		t.Fatal(err)
	}
	if view.CredentialStore != "session" || !view.HasCredentials || view.CredentialsSaved {
		t.Fatalf("session credential state wrong: %+v", view.Connection)
	}
	if err := svc.SetCredentials(ctx, "default:node-a", Credentials{Username: "alice", Password: "s3cret"}, true); err != nil {
		t.Fatal(err)
	}
	view, _ = svc.GetConnection(ctx, "default:node-a")
	if !view.CredentialsSaved || view.CredentialStore != "saved" {
		t.Fatalf("saved credential state wrong: %+v", view.Connection)
	}
	// The group file must never contain the password.
	raw, err := os.ReadFile(filepath.Join(svc.paths.ProfileDir, "default.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "s3cret") {
		t.Fatalf("password written to profile file: %s", raw)
	}
}

func TestSetActiveIsTruthfulAndRenameKeepsSelection(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "default", testVLESS); err != nil {
		t.Fatal(err)
	}
	res, err := svc.SetActive(ctx, "default:node-a")
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied || !res.RestartRequired {
		t.Fatalf("SetActive must not claim a live switch: %+v", res)
	}
	if link := svc.Profiles().GetActiveLink(); link == nil || link.Remark != "node-a" {
		t.Fatalf("selection not persisted: %+v", link)
	}

	if err := svc.RenameConnection(ctx, "default:node-a", "renamed"); err != nil {
		t.Fatal(err)
	}
	if link := svc.Profiles().GetActiveLink(); link == nil || link.Remark != "renamed" {
		t.Fatalf("active selection not rewritten on rename: %+v", link)
	}
	if _, err := svc.GetConnection(ctx, "default:node-a"); CodeOf(err) != CodeNotFound {
		t.Fatalf("old id still resolves: %v", err)
	}
}

func TestDeleteRemovesConnectionAndCredentials(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "default", testVLESS); err != nil {
		t.Fatal(err)
	}
	link, _, err := svc.findLink("default:node-a")
	if err != nil {
		t.Fatal(err)
	}
	key := credential.KeyFor(link)
	if err := svc.SetCredentials(ctx, "default:node-a", Credentials{Username: "u", Password: "p"}, true); err != nil {
		t.Fatal(err)
	}
	if !svc.Credentials().HasSaved(key) {
		t.Fatal("credential was not saved")
	}
	if err := svc.DeleteConnection(ctx, "default:node-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetConnection(ctx, "default:node-a"); CodeOf(err) != CodeNotFound {
		t.Fatalf("connection survived delete: %v", err)
	}
	if svc.Credentials().HasSaved(key) {
		t.Fatal("saved credential survived delete")
	}
}

func TestSettingsRejectInvalidAndPersistValid(t *testing.T) {
	svc, p := newTestLocal(t)
	ctx := context.Background()
	svc.Config().Server.APIToken = "top-secret-token"

	bad := "bogus"
	if _, err := svc.UpdateSettings(ctx, SettingsPatch{DNSMode: &bad}); CodeOf(err) != CodeInvalid {
		t.Fatalf("invalid dns mode accepted: %v", err)
	}
	if svc.Config().Gateway.DNSMode != "strict" {
		t.Fatal("failed validation mutated live config")
	}

	every := "15s"
	change, err := svc.UpdateSettings(ctx, SettingsPatch{HealthEvery: &every})
	if err != nil {
		t.Fatal(err)
	}
	if change.RestartRequired {
		t.Fatalf("health interval change should hot-reload, got restart: %+v", change)
	}
	data, err := os.ReadFile(p.ConfigFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "15s") {
		t.Fatalf("config not persisted: %s", data)
	}
}

func TestBackupExcludesTokenAndRestoreRoundTrips(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	svc.Config().Server.APIToken = "top-secret-token"
	svc.Config().Routing.ExternalOutbounds = map[string]string{"x": "socks5://user:pass@127.0.0.1:1080"}

	if _, err := svc.Backup(ctx, true); CodeOf(err) != CodeInvalid {
		t.Fatal("secret backup must be refused")
	}
	backup, err := svc.Backup(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	text := string(backup.Config)
	for _, secret := range []string{"top-secret-token", "user:pass"} {
		if strings.Contains(text, secret) {
			t.Fatalf("backup leaked %q: %s", secret, text)
		}
	}
	raw, _ := json.Marshal(backup)
	if err := svc.Restore(ctx, raw); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if svc.Config().Gateway.DNSMode != "strict" {
		t.Fatal("restore did not apply configuration")
	}

	// Host-local security state is never restored: a backup from another host
	// (or a tampered one) must not redirect the root daemon at a caller-chosen
	// engine directory, move profile writes, or clear the API token.
	tampered := Backup{Version: 1, Config: []byte(
		"server:\n  listen: 0.0.0.0\n  api_token: \"\"\n  api_port: 9090\n" +
			"engines:\n  directory: /tmp/bypath-evil-engines\n" +
			"profiles:\n  directory: /tmp/bypath-evil-profiles\n")}
	raw, _ = json.Marshal(tampered)
	if err := svc.Restore(ctx, raw); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := svc.Config().Engines.Directory; got == "/tmp/bypath-evil-engines" {
		t.Fatal("restore redirected the engine directory")
	}
	if got := svc.Config().Profiles.Directory; got == "/tmp/bypath-evil-profiles" {
		t.Fatal("restore redirected the profile directory")
	}
	if got := svc.Config().Server.APIToken; got != "top-secret-token" {
		t.Fatalf("restore replaced the live API token: %q", got)
	}
	if got := svc.Config().Server.Listen; got != "127.0.0.1" {
		t.Fatalf("restore moved the API listener to %q", got)
	}
	if got := svc.Config().Server.APIPort; got != 8080 {
		t.Fatalf("restore changed the API port to %d", got)
	}

	// ssh_host_key and the panel exposure are host-local too. The document below
	// omits both; defaults must not replace this host's explicit choices.
	svc.Config().Server.SSHHostKey = config.SSHHostKeyStrict
	svc.Config().Server.Web = config.WebConfig{Enabled: true, Listen: "127.0.0.1", Port: 9090}
	hostLocal := Backup{Version: 1, Config: []byte(
		"server:\n  ssh_host_key: off\n  web:\n    enabled: true\n    listen: 0.0.0.0\n    allow_lan: true\n    port: 80\n")}
	raw, _ = json.Marshal(hostLocal)
	if err := svc.Restore(ctx, raw); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := svc.Config().Server.SSHHostKey; got != config.SSHHostKeyStrict {
		t.Fatalf("restore changed the SSH host-key policy to %q", got)
	}
	if web := svc.Config().Server.Web; !web.Enabled || web.Listen != "127.0.0.1" || web.AllowLAN || web.Port != 9090 {
		t.Fatalf("restore changed the panel exposure: %+v", web)
	}
}

func TestGenericLANPatchCannotBypassStagedProxyApply(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	for _, value := range []bool{true, false} {
		if _, err := svc.UpdateSettings(ctx, SettingsPatch{LANAccess: &value}); CodeOf(err) != CodeInvalid {
			t.Fatalf("LAN patch accepted: %v", err)
		}
	}
	listen := "0.0.0.0"
	if _, err := svc.UpdateSettings(ctx, SettingsPatch{Listen: &listen}); CodeOf(err) != CodeInvalid {
		t.Fatalf("management bind patch accepted: %v", err)
	}
	if svc.Config().Server.Listen != "127.0.0.1" || svc.Config().Server.SOCKSListenAddress() != "127.0.0.1" {
		t.Fatal("rejected patch modified bindings")
	}
}

// TestSOCKSExposureIsHostLocalState covers the two persistence paths that could
// leak or silently widen the proxy: backups must not carry credentials, and a
// restore must not move the listener or introduce credentials this build cannot
// enforce on its own clients.
func TestSOCKSExposureIsHostLocalState(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	svc.Config().Server.SOCKSListen = "127.0.0.1"

	backup, err := svc.Backup(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"socks_username", "socks_password"} {
		if strings.Contains(string(backup.Config), field) {
			t.Fatalf("backup carries %s: %s", field, backup.Config)
		}
	}

	tampered := Backup{Version: 1, Config: []byte(
		"server:\n  socks_listen: 0.0.0.0\n  socks_allow_lan: true\n  socks_username: attacker\n  socks_password: chosen\n")}
	raw, _ := json.Marshal(tampered)
	if err := svc.Restore(ctx, raw); err != nil {
		t.Fatalf("restore: %v", err)
	}
	cfg := svc.Config()
	if got := cfg.Server.SOCKSListenAddress(); got != "127.0.0.1" {
		t.Fatalf("restore moved the proxy listener to %q", got)
	}
	if cfg.Server.SOCKSAllowLAN {
		t.Fatal("restore enabled LAN exposure")
	}
	if cfg.Server.SOCKSUsername != "" || cfg.Server.SOCKSPassword != "" {
		t.Fatal("restore adopted SOCKS credentials the gateway's own clients never send")
	}
}

// TestRestoreKeepsHostPolicy covers C2-07: a tampered backup must not be able
// to enable gateway mode, open a DNS listener, weaken the DNS policy, route the
// default path direct, disable isolation, or arm an auto-start chain.
func TestRestoreKeepsHostPolicy(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()

	host := svc.Config()
	host.Gateway = config.GatewayConfig{Enabled: false, DNSMode: "strict"}
	host.Server.DNSPort = 53
	host.Routing = config.RoutingConfig{Rules: []config.RoutingRule{{Match: "default", Outbound: "proxy"}}}
	host.Isolation = config.IsolationConfig{Enabled: true}
	host.Whitelist = config.WhitelistConfig{
		Countries:         []string{"ir"},
		GeositeCountries:  []string{"ir"},
		GeositeURL:        "https://example.invalid/host-geosite.json",
		BypassDomains:     []string{"host.example"},
		ForceProxyDomains: []string{"must-tunnel.example"},
		UpdateInterval:    "24h",
	}
	host.Engines.PreferSystem = false
	host.Chains = []config.ChainConfig{{
		Name:      "home",
		Hops:      []config.HopConfig{{Profile: "imported:host"}},
		AutoStart: true,
	}}

	backup := Backup{Version: 1, Config: []byte(
		"gateway:\n  enabled: true\n  dns_mode: local\n  native_tun: true\n" +
			"  dns_upstream: [\"203.0.113.9\"]\n  local_dns:\n    - server: 203.0.113.10\n      domains: [local]\n" +
			"server:\n  dns_port: 5353\n" +
			"routing:\n  rules:\n    - match: default\n      outbound: direct\n  external_outbounds:\n    evil: socks5://203.0.113.11:1080\n" +
			"isolation:\n  enabled: false\n" +
			"whitelist:\n  geosite_url: https://evil.invalid/geosite.json\n" +
			"  countries: [us]\n  geosite_countries: [cn]\n" +
			"  bypass_domains: [evil.example]\n  force_proxy_domains: []\n" +
			"engines:\n  prefer_system: true\n" +
			"chains:\n  - name: injected\n    hops:\n      - profile: imported:something\n    auto_start: true\n" +
			"  - name: home\n    hops:\n      - profile: imported:evil\n    auto_start: true\n")}
	raw, _ := json.Marshal(backup)
	if err := svc.Restore(ctx, raw); err != nil {
		t.Fatalf("restore: %v", err)
	}

	cfg := svc.Config()
	if cfg.Gateway.Enabled || cfg.Gateway.NativeTUN {
		t.Fatalf("restore enabled gateway mode: %+v", cfg.Gateway)
	}
	if cfg.Gateway.DNSMode != "strict" {
		t.Fatalf("restore weakened the DNS policy to %q", cfg.Gateway.DNSMode)
	}
	if len(cfg.Gateway.DNSUpstream) != 0 || len(cfg.Gateway.LocalDNS) != 0 {
		t.Fatalf("restore changed resolvers: %+v", cfg.Gateway)
	}
	if cfg.Server.DNSPort != 53 {
		t.Fatalf("restore moved the DNS listener to %d", cfg.Server.DNSPort)
	}
	if len(cfg.Routing.Rules) != 1 || cfg.Routing.Rules[0].Outbound != "proxy" {
		t.Fatalf("restore changed routing rules: %+v", cfg.Routing.Rules)
	}
	if len(cfg.Routing.ExternalOutbounds) != 0 {
		t.Fatalf("restore injected external outbounds: %+v", cfg.Routing.ExternalOutbounds)
	}
	if !cfg.Isolation.Enabled {
		t.Fatal("restore disabled isolation")
	}
	if cfg.Whitelist.GeositeURL != "https://example.invalid/host-geosite.json" {
		t.Fatalf("restore replaced the geosite URL with %q", cfg.Whitelist.GeositeURL)
	}
	if got := strings.Join(cfg.Whitelist.Countries, ","); got != "ir" {
		t.Fatalf("restore widened direct routing to countries %q", got)
	}
	if got := strings.Join(cfg.Whitelist.GeositeCountries, ","); got != "ir" {
		t.Fatalf("restore widened direct routing to geosite countries %q", got)
	}
	if got := strings.Join(cfg.Whitelist.BypassDomains, ","); got != "host.example" {
		t.Fatalf("restore widened direct routing to domains %q", got)
	}
	if got := strings.Join(cfg.Whitelist.ForceProxyDomains, ","); got != "must-tunnel.example" {
		t.Fatalf("restore changed force-proxy domains to %q", got)
	}
	if cfg.Whitelist.UpdateInterval != "24h" {
		t.Fatalf("restore changed the whitelist update interval to %q", cfg.Whitelist.UpdateInterval)
	}
	if cfg.Engines.PreferSystem {
		t.Fatal("restore changed the engine preference")
	}
	autoStart := map[string]bool{}
	homeHops := ""
	for _, c := range cfg.Chains {
		autoStart[c.Name] = c.AutoStart
		if c.Name == "home" && len(c.Hops) == 1 {
			homeHops = c.Hops[0].Profile
		}
	}
	if autoStart["injected"] {
		t.Fatal("restore armed a chain this host never started automatically")
	}
	if !autoStart["home"] {
		t.Fatal("restore cleared a chain this host starts automatically")
	}
	if homeHops != "imported:host" {
		t.Fatalf("restore replaced the hops of an auto-start chain with %q", homeHops)
	}
}

func TestBenchMapsEmptyProfileAndScopeErrors(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()

	if _, err := svc.Bench(ctx, BenchRequest{}); CodeOf(err) != CodeNotFound {
		t.Fatalf("empty profile: code = %q, want %q", CodeOf(err), CodeNotFound)
	}
	if _, err := svc.Bench(ctx, BenchRequest{Group: "work"}); CodeOf(err) != CodeNotFound {
		t.Fatalf("unknown group: code = %q, want %q", CodeOf(err), CodeNotFound)
	}

	mgr := svc.Profiles()
	if err := mgr.AddLink("work", &profile.Link{Remark: "placeholder", Protocol: "vless", Address: "0.0.0.0", Port: 443}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Bench(ctx, BenchRequest{Group: "work"}); CodeOf(err) != CodeNotFound {
		t.Fatalf("placeholder-only group: code = %q, want %q", CodeOf(err), CodeNotFound)
	}
}
