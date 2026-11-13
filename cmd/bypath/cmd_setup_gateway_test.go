package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/liberoute/bypath/internal/config"
)

type stubFileInfo struct{ mode os.FileMode }

func (s stubFileInfo) Name() string       { return "tun" }
func (s stubFileInfo) Size() int64        { return 0 }
func (s stubFileInfo) Mode() os.FileMode  { return s.mode }
func (s stubFileInfo) ModTime() time.Time { return time.Time{} }
func (s stubFileInfo) IsDir() bool        { return false }
func (s stubFileInfo) Sys() any           { return nil }

// fakeSetupHost answers the prerequisite probes without touching the machine.
type fakeSetupHost struct {
	euid       int
	bins       map[string]bool
	tun        bool
	installErr error
	runs       []string
	installed  [][]string
}

func newFakeSetupHost() *fakeSetupHost {
	return &fakeSetupHost{euid: 0, tun: true, bins: map[string]bool{"ip": true, "iptables": true, "ip6tables": true, "apt-get": true}}
}

func (f *fakeSetupHost) host() setupHost {
	return setupHost{
		euid: func() int { return f.euid },
		lookPath: func(bin string) (string, error) {
			if f.bins[bin] {
				return "/usr/sbin/" + bin, nil
			}
			return "", errors.New("executable not found")
		},
		stat: func(path string) (os.FileInfo, error) {
			if path == "/dev/net/tun" && f.tun {
				return stubFileInfo{mode: os.ModeDevice | os.ModeCharDevice}, nil
			}
			return nil, os.ErrNotExist
		},
		run: func(ctx context.Context, name string, args ...string) error {
			f.runs = append(f.runs, name+" "+strings.Join(args, " "))
			if name == "apt-get" && len(args) > 0 && args[0] == "install" {
				pkgs := append([]string{}, args[2:]...)
				f.installed = append(f.installed, pkgs)
				if f.installErr != nil {
					return f.installErr
				}
				for _, pkg := range pkgs {
					f.provide(pkg)
				}
			}
			return nil
		},
	}
}

func (f *fakeSetupHost) provide(pkg string) {
	switch pkg {
	case "iptables":
		f.bins["iptables"] = true
		f.bins["ip6tables"] = true
	case "iproute2":
		f.bins["ip"] = true
	}
}

func promptWith(input string) *prompter {
	return &prompter{in: bufio.NewReader(strings.NewReader(input)), tty: false, out: io.Discard}
}

func TestGatewayPrerequisitesReportMissingPackages(t *testing.T) {
	f := newFakeSetupHost()
	f.bins = map[string]bool{"ip": true}
	missing := missingRequirements(gatewayPrerequisites(f.host()))
	if len(missing) != 2 {
		t.Fatalf("missing = %+v, want iptables and ip6tables", missing)
	}
	for _, req := range missing {
		if req.Key != "iptables" && req.Key != "ip6tables" {
			t.Fatalf("unexpected missing requirement %q", req.Key)
		}
		if req.Package != "iptables" {
			t.Fatalf("%s must map to the iptables package, got %q", req.Key, req.Package)
		}
	}
	if pkgs := missingPackages(missing); len(pkgs) != 1 || pkgs[0] != "iptables" {
		t.Fatalf("package plan = %v, want [iptables]", pkgs)
	}
}

func TestGatewayPrerequisitesRefuseWithoutRoot(t *testing.T) {
	f := newFakeSetupHost()
	f.euid = 1000
	err := ensureGatewayPrerequisites(promptWith(""), &setupOptions{nonInteractive: true}, f.host())
	if err == nil {
		t.Fatal("a non-root gateway setup must be refused before anything is written")
	}
	for _, want := range []string{"sudo", "normal account with sudo is supported"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to mention %q", err, want)
		}
	}
	if len(f.runs) != 0 {
		t.Fatalf("a non-root run must not execute anything: %v", f.runs)
	}
}

func TestGatewayPrerequisitesDeclinedInstallLeavesHostAlone(t *testing.T) {
	f := newFakeSetupHost()
	f.bins = map[string]bool{"ip": true, "apt-get": true}
	var prompt bytes.Buffer
	p := &prompter{in: bufio.NewReader(strings.NewReader("n\n")), tty: true, out: &prompt}
	err := ensureGatewayPrerequisites(p, &setupOptions{}, f.host())
	if err == nil {
		t.Fatal("declining the installation must refuse gateway mode")
	}
	for _, want := range []string{"Install the missing packages now (apt-get install -y iptables) [y/N]", "sudo apt install iptables", "nothing was changed"} {
		if !strings.Contains(prompt.String()+err.Error(), want) {
			t.Fatalf("offer/refusal missing %q:\n%s\n%v", want, prompt.String(), err)
		}
	}
	if len(f.installed) != 0 || len(f.runs) != 0 {
		t.Fatalf("declined installation must not run apt: runs=%v installed=%v", f.runs, f.installed)
	}
}

func TestGatewayPrerequisitesNonInteractiveNeedsExplicitApproval(t *testing.T) {
	f := newFakeSetupHost()
	f.bins = map[string]bool{"ip": true, "apt-get": true}
	err := ensureGatewayPrerequisites(promptWith(""), &setupOptions{nonInteractive: true}, f.host())
	if err == nil || !strings.Contains(err.Error(), "nothing was changed") {
		t.Fatalf("error = %v, want a refusal with the manual command", err)
	}
	if len(f.runs) != 0 {
		t.Fatalf("non-interactive setup must not install without --install-packages: %v", f.runs)
	}
}

func TestGatewayPrerequisitesInstallFailure(t *testing.T) {
	f := newFakeSetupHost()
	f.bins = map[string]bool{"ip": true, "apt-get": true}
	f.installErr = errors.New("E: Unable to locate package iptables")
	err := ensureGatewayPrerequisites(promptWith("y\n"), &setupOptions{}, f.host())
	if err == nil {
		t.Fatal("a failed package installation must refuse gateway mode")
	}
	for _, want := range []string{"package installation failed", "nothing was changed"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %q, want it to mention %q", err, want)
		}
	}
	if len(f.installed) != 1 || strings.Join(f.installed[0], " ") != "iptables" {
		t.Fatalf("installed = %v, want one attempt with iptables", f.installed)
	}
	if f.bins["iptables"] {
		t.Fatal("a failed installation must not be reported as satisfied")
	}
}

func TestGatewayPrerequisitesInstallSucceeds(t *testing.T) {
	f := newFakeSetupHost()
	f.bins = map[string]bool{"ip": true, "apt-get": true}
	if err := ensureGatewayPrerequisites(promptWith("y\n"), &setupOptions{}, f.host()); err != nil {
		t.Fatalf("approved installation should satisfy the prerequisites: %v", err)
	}
	if len(f.installed) != 1 || strings.Join(f.installed[0], " ") != "iptables" {
		t.Fatalf("installed = %v, want one attempt with iptables", f.installed)
	}
	if !f.bins["iptables"] || !f.bins["ip6tables"] {
		t.Fatalf("both firewall binaries must be available after install: %v", f.bins)
	}
	if len(f.runs) != 2 || !strings.Contains(f.runs[0], "update") {
		t.Fatalf("runs = %v, want update then install", f.runs)
	}
}

func TestGatewayPrerequisitesTunNeedsManualStep(t *testing.T) {
	f := newFakeSetupHost()
	f.tun = false
	err := ensureGatewayPrerequisites(promptWith(""), &setupOptions{nonInteractive: true}, f.host())
	if err == nil || !strings.Contains(err.Error(), "modprobe tun") {
		t.Fatalf("error = %v, want the manual modprobe step", err)
	}
	if len(f.runs) != 0 {
		t.Fatalf("apt cannot provide a TUN device; nothing should run: %v", f.runs)
	}
}

func TestGatewayPrerequisiteFailurePreservesExistingConfig(t *testing.T) {
	cfg, err := config.Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server.APIToken = "keep-this-token"
	cfg.Profiles.ActiveGroup = "home"
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	f := newFakeSetupHost()
	f.bins = map[string]bool{"ip": true}
	if err := ensureGatewayPrerequisites(promptWith(""), &setupOptions{nonInteractive: true}, f.host()); err == nil {
		t.Fatal("the gate must fail while packages are missing")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(data) {
		t.Fatal("a failed prerequisite check modified the existing configuration")
	}
	resumed, exists, err := loadSetupConfig(path)
	if err != nil || !exists {
		t.Fatalf("existing configuration must still load after a failed run: exists=%v err=%v", exists, err)
	}
	if resumed.Server.APIToken != "keep-this-token" || resumed.Profiles.ActiveGroup != "home" {
		t.Fatalf("resume lost existing settings: %+v", resumed.Server.APIToken)
	}

	if err := ensureGatewayPrerequisites(promptWith(""), &setupOptions{nonInteractive: true}, newFakeSetupHost().host()); err != nil {
		t.Fatalf("a satisfied host must pass the gate on resume: %v", err)
	}
}

func TestAddressChangeRiskClassification(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		risk  bool
	}{
		{
			name:  "debian dhcp",
			files: map[string]string{"/etc/network/interfaces": "auto eth0\niface eth0 inet dhcp\n"},
			risk:  true,
		},
		{
			name:  "debian static",
			files: map[string]string{"/etc/network/interfaces": "auto eth0\niface eth0 inet static\n  address 192.168.1.118/24\n"},
			risk:  false,
		},
		{
			name:  "dhcpcd block without static",
			files: map[string]string{"/etc/dhcpcd.conf": "interface eth0\n"},
			risk:  true,
		},
		{
			name:  "dhcpcd static address",
			files: map[string]string{"/etc/dhcpcd.conf": "interface eth0\nstatic ip_address=192.168.1.118/24\n"},
			risk:  false,
		},
		{
			name:  "networkd dhcp",
			files: map[string]string{"/etc/systemd/network/20-lan.network": "[Match]\nName=eth0\n[Network]\nDHCP=yes\n"},
			risk:  true,
		},
		{
			name:  "networkd static",
			files: map[string]string{"/etc/systemd/network/20-lan.network": "[Match]\nName=eth0\n[Network]\nDHCP=no\nAddress=192.168.1.118/24\n"},
			risk:  false,
		},
		{
			name:  "networkmanager automatic",
			files: map[string]string{"/etc/NetworkManager/system-connections/lan.nmconnection": "[connection]\ninterface-name=eth0\n[ipv4]\nmethod=auto\n"},
			risk:  true,
		},
		{
			name:  "networkmanager manual",
			files: map[string]string{"/etc/NetworkManager/system-connections/lan.nmconnection": "[connection]\ninterface-name=eth0\n[ipv4]\nmethod=manual\n"},
			risk:  false,
		},
		{
			name:  "no evidence",
			files: map[string]string{},
			risk:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			risk, reason := addressChangeRisk("eth0", tc.files)
			if risk != tc.risk {
				t.Fatalf("risk = %v (%s), want %v", risk, reason, tc.risk)
			}
			if risk && reason == "" {
				t.Fatal("a risk warning must explain itself")
			}
		})
	}
}

func TestRenderAddressWarningMentionsReservation(t *testing.T) {
	msg := renderAddressWarning("eth0", "192.168.1.118", "eth0 is configured by DHCP in /etc/network/interfaces")
	for _, want := range []string{"192.168.1.118", "DHCP reservation", "lease"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("warning = %q, want it to mention %q", msg, want)
		}
	}
}

func TestRenderLANClientGuidanceUsesGatewayAndDNS(t *testing.T) {
	ans := &answers{iface: "eth0", ifaceAddr: "192.168.1.118", ifaceCIDR: "192.168.1.118/24", dnsPort: 53}
	msg := renderLANClientGuidance(ans)
	for _, want := range []string{
		"Default gateway: 192.168.1.118",
		"DNS server:      192.168.1.118\n",
		"255.255.255.0 (/24)",
		"DHCP reservation",
		"Bypath cannot check this for you",
		"ipv4.addresses <reserved-address>/24 ipv4.gateway 192.168.1.118 ipv4.dns 192.168.1.118",
		"back to automatic (DHCP)",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("guidance missing %q:\n%s", want, msg)
		}
	}
}

// TestRenderLANClientGuidanceNeverInventsAnAddress pins that the only IPv4
// literals in the recipe are the gateway itself and the subnet mask: Bypath
// cannot know which client addresses are free.
func TestRenderLANClientGuidanceNeverInventsAnAddress(t *testing.T) {
	ipv4 := regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	for _, tc := range []struct{ addr, cidr, mask string }{
		{"192.168.1.118", "192.168.1.118/24", "255.255.255.0"},
		{"10.20.0.1", "10.20.0.1/16", "255.255.0.0"},
		{"172.16.5.2", "172.16.5.2/28", "255.255.255.240"},
		{"192.168.50.1", "bogus", ""},
	} {
		msg := renderLANClientGuidance(&answers{iface: "eth0", ifaceAddr: tc.addr, ifaceCIDR: tc.cidr, dnsPort: 53})
		for _, lit := range ipv4.FindAllString(msg, -1) {
			if lit != tc.addr && lit != tc.mask {
				t.Fatalf("%s: guidance suggests address %s that nobody confirmed is free:\n%s", tc.cidr, lit, msg)
			}
		}
	}
}

func TestRenderLANClientGuidanceNonstandardDNSPort(t *testing.T) {
	ans := &answers{iface: "eth0", ifaceAddr: "192.168.1.118", ifaceCIDR: "192.168.1.118/24", dnsPort: 5335}
	msg := renderLANClientGuidance(ans)
	if !strings.Contains(msg, "DNS server:      192.168.1.118\n") {
		t.Fatalf("the client DNS setting must be the bare address:\n%s", msg)
	}
	for _, bad := range []string{"192.168.1.118:5335", ", port 5335", "set the port explicitly"} {
		if strings.Contains(msg, bad) {
			t.Fatalf("guidance implies a client DNS setting can carry a port (%q):\n%s", bad, msg)
		}
	}
	for _, want := range []string{"ordinary port 53", "cannot carry", "redirects", "on eth0 to port 5335"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("nonstandard-port explanation missing %q:\n%s", want, msg)
		}
	}
}

func TestRenderPanelAccessUsesConfiguredPort(t *testing.T) {
	cfg, err := config.Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server.Web.Enabled = true
	cfg.Server.Web.Listen = "127.0.0.1"
	cfg.Server.Web.Port = 9443
	msg := renderPanelAccess(cfg, "dietpi", "192.168.1.118")
	codePath := filepath.Join(filepath.Dir(cfg.Profiles.Directory), "web", "setup-code")
	for _, want := range []string{
		"loopback only",
		"http://127.0.0.1:9443",
		"ssh -N -L 9443:127.0.0.1:9443 dietpi@192.168.1.118",
		"open http://127.0.0.1:9443 on that computer",
		"sudo cat " + codePath,
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("panel guidance missing %q:\n%s", want, msg)
		}
	}
	if cfg.Server.Web.AllowLAN || cfg.Server.Web.Listen != "127.0.0.1" {
		t.Fatalf("rendering guidance must not widen the panel listener: %+v", cfg.Server.Web)
	}

	if msg := renderPanelAccess(cfg, "", ""); !strings.Contains(msg, "<user>@<this-host-address>") {
		t.Fatalf("unknown user/host must be placeholders, not guesses:\n%s", msg)
	}

	cfg.Server.Web.Listen = "::1"
	if msg := renderPanelAccess(cfg, "u", "h"); !strings.Contains(msg, "-L 9443:[::1]:9443") {
		t.Fatalf("IPv6 loopback must be bracketed for ssh -L:\n%s", msg)
	}

	cfg.Server.Web.Listen = "192.168.1.118"
	if msg := renderPanelAccess(cfg, "u", "h"); msg != "" {
		t.Fatalf("a LAN panel needs no tunnel recipe, got:\n%s", msg)
	}
	cfg.Server.Web.Listen = "127.0.0.1"
	cfg.Server.Web.Enabled = false
	if msg := renderPanelAccess(cfg, "u", "h"); msg != "" {
		t.Fatalf("a disabled panel needs no tunnel recipe, got:\n%s", msg)
	}
}

func TestGatewayPrerequisitesDryRunNeverInstalls(t *testing.T) {
	cases := []struct {
		name string
		opts setupOptions
		in   string
		tty  bool
		want string
	}{
		{"approved by flag", setupOptions{dryRun: true, installPackages: true, nonInteractive: true}, "", false, "a real run would execute `apt-get update && apt-get install -y iptables`"},
		{"interactive yes is never asked", setupOptions{dryRun: true}, "y\n", true, "a real run would offer `apt-get install -y iptables`"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeSetupHost()
			f.bins = map[string]bool{"ip": true, "apt-get": true}
			var out bytes.Buffer
			p := &prompter{in: bufio.NewReader(strings.NewReader(tc.in)), tty: tc.tty, out: &out}
			stdout := captureStdout(t, func() {
				if err := ensureGatewayPrerequisites(p, &tc.opts, f.host()); !errors.Is(err, errDryRunPrerequisites) {
					t.Fatalf("err = %v, want the dry-run marker", err)
				}
			})
			if len(f.runs) != 0 || len(f.installed) != 0 {
				t.Fatalf("dry run executed commands: %v", f.runs)
			}
			if out.Len() != 0 {
				t.Fatalf("dry run prompted: %q", out.String())
			}
			if !strings.Contains(stdout, tc.want) || !strings.Contains(stdout, "no package was installed") {
				t.Fatalf("dry-run report missing %q:\n%s", tc.want, stdout)
			}
		})
	}

	f := newFakeSetupHost()
	f.euid = 1000
	f.bins = map[string]bool{"apt-get": true}
	err := ensureGatewayPrerequisites(promptWith(""), &setupOptions{dryRun: true, installPackages: true}, f.host())
	if !errors.Is(err, errDryRunPrerequisites) || len(f.runs) != 0 {
		t.Fatalf("non-root dry run must preview, not fail or run: err=%v runs=%v", err, f.runs)
	}
}

func TestSetupHostForDryRunRefusesExecution(t *testing.T) {
	h := setupHostFor(&setupOptions{dryRun: true, installPackages: true})
	err := h.run(context.Background(), "apt-get", "install", "-y", "iptables")
	if err == nil || !strings.Contains(err.Error(), "dry run: refusing to execute apt-get install -y iptables") {
		t.Fatalf("dry-run host must refuse execution, got %v", err)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		data, _ := io.ReadAll(r)
		done <- string(data)
	}()
	defer func() { os.Stdout = orig }()
	fn()
	w.Close()
	os.Stdout = orig
	return <-done
}

func TestGatewayModeKeepsSOCKSOnLoopback(t *testing.T) {
	cfg, err := config.Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	ans := &answers{
		gatewayMode: true,
		iface:       "eth0",
		listenAddr:  "127.0.0.1",
		allowLAN:    false,
		socksPort:   2801,
		dnsPort:     53,
		upstreams:   []string{"1.1.1.1"},
		group:       "default",
	}
	if err := applyAnswers(cfg, ans); err != nil {
		t.Fatal(err)
	}
	if cfg.Server.SOCKSListen != "127.0.0.1" || cfg.Server.SOCKSAllowLAN || len(cfg.Server.SOCKSAllowCIDRs) != 0 {
		t.Fatalf("gateway mode must keep the SOCKS listener on loopback: %+v", cfg.Server)
	}
}
