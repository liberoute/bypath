package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/diag"
	"github.com/liberoute/bypath/internal/paths"
)

type setupOptions struct {
	configPath     string
	nonInteractive bool
	dryRun         bool

	mode         string
	iface        string
	trusted      multiFlag
	socksPort    int
	listen       string
	listenIP     string
	dnsPort      int
	dnsUpstreams multiFlag
	web          string
	webPort      int

	uris          multiFlag
	subscriptions multiFlag
	group         string
	selectName    string

	startService    bool
	enableService   bool
	enableGateway   bool
	installPackages bool
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

type answers struct {
	gatewayMode    bool
	enableNow      bool
	iface          string
	ifaceAddr      string
	ifaceCIDR      string
	listenAddr     string
	allowLAN       bool
	trusted        []string
	socksPort      int
	dnsPort        int
	upstreams      []string
	webEnabled     bool
	webListen      string
	webAllowLAN    bool
	webPort        int
	group          string
	selectName     string
	uris           []string
	subs           []string
	startService   bool
	persistService bool
	// addressMayChange records that the LAN address is not proven static, so
	// the review and the final client recipe repeat the DHCP warning.
	addressMayChange bool
	addressReason    string
	// deferActivation keeps gateway.enabled false at write time when a systemd
	// unit exists: startAndVerify turns it on only after the connection works.
	deferActivation bool
}

func cmdSetup(args []string) {
	opts, err := parseSetupFlags(args)
	if err != nil {
		os.Exit(2)
	}
	p := prompter{
		in:  bufio.NewReader(os.Stdin),
		tty: term.IsTerminal(int(os.Stdin.Fd())),
		out: os.Stdout,
	}
	opts.nonInteractive = opts.nonInteractive || !p.tty
	if opts.nonInteractive && opts.mode == "" {
		fmt.Println("❌ --mode is required with --non-interactive (proxy or gateway).")
		os.Exit(2)
	}

	cfgPath, err := filepath.Abs(opts.configPath)
	if err != nil {
		fmt.Printf("❌ Invalid config path: %v\n", err)
		os.Exit(1)
	}
	cfg, exists, err := loadSetupConfig(cfgPath)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}

	if !opts.nonInteractive {
		printEnvironment(cfgPath, exists)
	}

	ans, err := collectAnswers(&p, opts, cfg)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}
	// A systemd unit activates the gateway only after startAndVerify proves a
	// connection; without a unit the supervised `bypath run` needs the flag now.
	ans.deferActivation = ans.enableNow && unitInstalled()

	if err := applyAnswers(cfg, ans); err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		fmt.Printf("❌ Could not render the configuration: %v\n", err)
		os.Exit(1)
	}
	if opts.dryRun {
		fmt.Println("--- configuration that would be written (api_token redacted) ---")
		fmt.Print(redactConfigYAML(string(data)))
		fmt.Println("--- dry run: nothing was written, imported or started ---")
		return
	}

	if err := writeConfig(cfgPath, data); err != nil {
		fmt.Printf("❌ Could not write %s: %v\n", cfgPath, err)
		os.Exit(1)
	}
	fmt.Printf("✅ Configuration written to %s\n", cfgPath)

	imported, importErr := runImports(cfg, cfgPath, ans)
	if importErr != nil {
		fmt.Printf("⚠️  %v\n", importErr)
	}

	reportPlan(cfg, ans, cfgPath)
	if imported == 0 {
		fmt.Println("\nNext: add a connection with `bypath setup` again, or in the panel once the service runs.")
		os.Exit(exitCode(importErr))
	}

	if ans.gatewayMode && !ans.enableNow {
		fmt.Println("\nGateway mode is staged but DISABLED: verify a connection first, then re-run")
		fmt.Println("`bypath setup --mode gateway --enable-gateway` (or enable it from the panel).")
		os.Exit(0)
	}

	if !ans.startService {
		fmt.Println("\nVerification was skipped. Start the gateway yourself, then run `bypath doctor --egress`.")
		os.Exit(exitCode(importErr))
	}

	if ok := startAndVerify(cfgPath, ans); !ok {
		os.Exit(1)
	}
	if err := offerServicePersistence(&p, opts, ans); err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}
}

// offerServicePersistence runs only after a verified start. Starting and
// enabling are different: installation never enables the unit, a wizard start
// runs it until the next reboot, and an explicit yes (or --enable-service)
// makes it return at boot. Gateway mode is a third, independent switch.
func offerServicePersistence(p *prompter, opts *setupOptions, ans *answers) error {
	if !unitInstalled() || serviceState() != "active" {
		return nil
	}
	enable := ans.persistService
	if !opts.nonInteractive && !enable {
		answer, err := p.confirm("Enable the service at boot so it returns after a reboot (systemctl enable bypath)", false)
		if err != nil {
			return err
		}
		enable = answer
	}
	if !enable {
		fmt.Println("\nℹ️  The service is running now but will NOT start after a reboot.")
		fmt.Println("   start = run now; enable = also run at boot; gateway mode = carry the LAN.")
		fmt.Println("   Enable later with `sudo systemctl enable bypath`.")
		return nil
	}
	if err := enableServiceAtBoot(); err != nil {
		return fmt.Errorf("enabling the service at boot: %v", err)
	}
	fmt.Println("\n✅ The service is enabled and will start after a reboot.")
	fmt.Println("   start = run now; enable = also run at boot; gateway mode = carry the LAN.")
	return nil
}

// enableServiceAtBoot verifies the result instead of trusting `systemctl
// enable`: a unit without an [Install] section or a masked unit exits 0 on some
// systemd versions while remaining disabled.
func enableServiceAtBoot() error {
	if err := exec.Command("systemctl", "enable", "bypath").Run(); err != nil {
		return err
	}
	out, err := exec.Command("systemctl", "is-enabled", "bypath").Output()
	if err != nil {
		return fmt.Errorf("systemctl is-enabled reported an error: %v", err)
	}
	switch state := strings.TrimSpace(string(out)); state {
	case "enabled":
		return nil
	case "enabled-runtime":
		return fmt.Errorf("the unit is enabled only for this boot (%q); a permanent enable failed", state)
	default:
		return fmt.Errorf("systemctl is-enabled reports %q, not enabled", state)
	}
}

func exitCode(err error) int {
	if err != nil {
		return 1
	}
	return 0
}

func parseSetupFlags(args []string) (*setupOptions, error) {
	defaultConfig := paths.Get().ConfigFile
	opts := &setupOptions{configPath: defaultConfig}
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&opts.configPath, "config", defaultConfig, "configuration file to create or update")
	fs.StringVar(&opts.configPath, "c", defaultConfig, "alias for --config")
	fs.BoolVar(&opts.nonInteractive, "non-interactive", false, "take every answer from flags")
	fs.BoolVar(&opts.dryRun, "dry-run", false, "print the resulting configuration without writing it")
	fs.StringVar(&opts.mode, "mode", "", "proxy (no LAN takeover) or gateway")
	fs.StringVar(&opts.iface, "interface", "", "LAN interface for gateway mode (never assumed)")
	fs.Var(&opts.trusted, "trusted-cidr", "trusted client subnet for a LAN proxy/listener (repeatable)")
	fs.IntVar(&opts.socksPort, "socks-port", 0, "proxy port (default 2801)")
	fs.StringVar(&opts.listen, "listen", "", "proxy listener: localhost, lan or all (default localhost)")
	fs.StringVar(&opts.listenIP, "listen-ip", "", "explicit proxy bind address (overrides --listen)")
	fs.IntVar(&opts.dnsPort, "dns-port", 0, "gateway DNS port (default 53)")
	fs.Var(&opts.dnsUpstreams, "dns-upstream", "upstream DNS server (repeatable)")
	fs.StringVar(&opts.web, "web", "", "panel listener: off, loopback or lan (default loopback)")
	fs.IntVar(&opts.webPort, "web-port", 0, "panel port (default api_port + 1)")
	fs.Var(&opts.uris, "uri", "proxy URI to import (repeatable)")
	fs.Var(&opts.subscriptions, "subscription", "subscription URL to import (repeatable)")
	fs.StringVar(&opts.group, "group", "", "organisation group for imported connections (default \"default\")")
	fs.StringVar(&opts.selectName, "select", "", "name of the connection to select after import")
	fs.BoolVar(&opts.startService, "start-service", false, "start/restart the systemd unit now and verify the first connection (does not enable it at boot)")
	fs.BoolVar(&opts.enableService, "enable-service", false, "after a verified start, enable the unit at boot (implies --start-service; does not enable gateway mode)")
	fs.BoolVar(&opts.enableGateway, "enable-gateway", false, "write gateway.enabled: true after you verified a connection yourself (does not start or enable the unit)")
	fs.BoolVar(&opts.installPackages, "install-packages", false, "approve apt-get installation of missing gateway prerequisites (never implied; nothing is installed without it)")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	mode := strings.ToLower(strings.TrimSpace(opts.mode))
	if mode != "" && mode != "proxy" && mode != "gateway" {
		return nil, fmt.Errorf("--mode must be proxy or gateway")
	}
	opts.mode = mode
	return opts, nil
}

func loadSetupConfig(path string) (*config.Config, bool, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			cfg, perr := config.Parse(nil)
			if perr != nil {
				return nil, false, perr
			}
			return cfg, false, nil
		}
		return nil, false, err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, true, fmt.Errorf("existing configuration %s is not valid (%v); fix or move it aside before running setup", path, err)
	}
	return cfg, true, nil
}

type lanIface struct {
	Name string
	Addr string
	CIDR string
}

func discoverLANs() []lanIface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []lanIface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		switch {
		case strings.HasPrefix(iface.Name, "tun"),
			strings.HasPrefix(iface.Name, "docker"),
			strings.HasPrefix(iface.Name, "veth"),
			strings.HasPrefix(iface.Name, "br-"):
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ip, network, err := net.ParseCIDR(addr.String())
			if err != nil || ip.To4() == nil || !ip.IsPrivate() {
				continue
			}
			out = append(out, lanIface{Name: iface.Name, Addr: ip.String(), CIDR: network.String()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func defaultRouteInterface() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

func printEnvironment(cfgPath string, exists bool) {
	fmt.Println("Bypath first-run setup")
	fmt.Printf("  platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	if _, err := os.Stat("/dev/net/tun"); err == nil {
		fmt.Println("  TUN:      /dev/net/tun present")
	} else {
		fmt.Println("  TUN:      not available (gateway mode will not work; proxy-only still will)")
	}
	var missingTools []string
	for _, bin := range []string{"ip", "iptables", "ip6tables"} {
		if _, err := exec.LookPath(bin); err != nil {
			missingTools = append(missingTools, bin)
		}
	}
	if len(missingTools) == 0 {
		fmt.Println("  tools:    ip, iptables and ip6tables present")
	} else {
		fmt.Printf("  tools:    missing %s — gateway mode needs them (Debian/DietPi: `sudo apt install iproute2 iptables`)\n", strings.Join(missingTools, ", "))
	}
	if os.Geteuid() != 0 {
		fmt.Println("  account:  normal user — gateway mode needs sudo; `sudo bypath setup …` is supported")
	} else {
		fmt.Println("  account:  root")
	}
	if _, err := exec.LookPath("systemctl"); err == nil {
		fmt.Println("  systemd:  available")
	} else {
		fmt.Println("  systemd:  not available (the gateway must be supervised another way)")
	}
	if state := serviceState(); state != "" {
		fmt.Printf("  service:  bypath is %s\n", state)
	}
	if exists {
		fmt.Printf("  config:   updating the existing %s\n", cfgPath)
	} else {
		fmt.Printf("  config:   creating %s\n", cfgPath)
	}
	lans := discoverLANs()
	if len(lans) == 0 {
		fmt.Println("  LAN:      no private IPv4 interface detected")
	} else {
		fmt.Println("  LAN interfaces:")
		for _, lan := range lans {
			fmt.Printf("              %-16s %-15s %s\n", lan.Name, lan.Addr, lan.CIDR)
		}
	}
	fmt.Println()
}

func collectAnswers(p *prompter, opts *setupOptions, cfg *config.Config) (*answers, error) {
	ans := &answers{
		group:          strings.TrimSpace(opts.group),
		selectName:     strings.TrimSpace(opts.selectName),
		uris:           append([]string{}, opts.uris...),
		subs:           append([]string{}, opts.subscriptions...),
		startService:   opts.startService || opts.enableService,
		persistService: opts.enableService,
	}
	if ans.group == "" {
		ans.group = cfg.Profiles.ActiveGroup
	}
	if ans.group == "" {
		ans.group = "default"
	}

	switch opts.mode {
	case "gateway":
		ans.gatewayMode = true
	case "proxy":
		ans.gatewayMode = false
	default:
		idx, err := p.choice("Mode", []string{
			"proxy-only — clients use a SOCKS port; nothing on the LAN is rerouted (recommended first)",
			"gateway — this host becomes the LAN gateway and DNS, and must not start without a working connection",
		}, 0)
		if err != nil {
			return nil, err
		}
		ans.gatewayMode = idx == 1
	}

	lans := discoverLANs()
	if ans.gatewayMode {
		if err := ensureGatewayPrerequisites(p, opts, defaultSetupHost()); err != nil {
			return nil, err
		}
		if opts.iface == "" {
			if opts.nonInteractive {
				return nil, fmt.Errorf("--interface is required for gateway mode; detected: %s", describeLANs(lans))
			}
			if len(lans) == 0 {
				return nil, fmt.Errorf("no private IPv4 interface was detected; gateway mode needs one")
			}
			def := defaultRouteInterface()
			idx := 0
			for i, lan := range lans {
				if lan.Name == def {
					idx = i
				}
			}
			labels := make([]string, len(lans))
			for i, lan := range lans {
				labels[i] = fmt.Sprintf("%s (%s, %s)", lan.Name, lan.Addr, lan.CIDR)
			}
			chosen, err := p.choice("LAN interface", labels, idx)
			if err != nil {
				return nil, err
			}
			opts.iface = lans[chosen].Name
		}
		found := false
		for _, lan := range lans {
			if lan.Name == opts.iface {
				ans.iface, ans.ifaceAddr, ans.ifaceCIDR = lan.Name, lan.Addr, lan.CIDR
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("interface %q has no private IPv4 address; detected: %s", opts.iface, describeLANs(lans))
		}
		ans.addressMayChange, ans.addressReason = addressChangeRisk(ans.iface, loadAddressConfig())
		if ans.addressMayChange {
			fmt.Print(renderAddressWarning(ans.iface, ans.ifaceAddr, ans.addressReason))
			fmt.Println()
		}
	}

	// Proxy listener
	listen := strings.ToLower(strings.TrimSpace(opts.listen))
	if opts.listenIP != "" {
		listen = "ip"
	}
	if listen == "" {
		if opts.nonInteractive {
			listen = "localhost"
		} else {
			idx, err := p.choice("Proxy listener", []string{
				"localhost — only this machine can use the proxy (recommended)",
				"LAN address — other devices use this host's address; requires trusted subnets and a firewall",
				"all IPv4 interfaces — same, but also binds addresses added later; requires trusted subnets",
			}, 0)
			if err != nil {
				return nil, err
			}
			listen = []string{"localhost", "lan", "all"}[idx]
		}
	}
	switch listen {
	case "localhost":
		ans.listenAddr = "127.0.0.1"
		ans.allowLAN = false
	case "lan":
		if len(lans) == 0 {
			return nil, fmt.Errorf("no LAN interface is available for --listen lan")
		}
		if opts.nonInteractive {
			if len(lans) != 1 {
				return nil, fmt.Errorf("--listen lan is ambiguous with %d interfaces; pass --listen-ip", len(lans))
			}
			ans.listenAddr = lans[0].Addr
			ans.ifaceCIDR = lans[0].CIDR
			ans.iface = lans[0].Name
		} else {
			labels := make([]string, len(lans))
			for i, lan := range lans {
				labels[i] = fmt.Sprintf("%s (%s)", lan.Name, lan.Addr)
			}
			chosen, err := p.choice("Listen on which interface", labels, 0)
			if err != nil {
				return nil, err
			}
			ans.listenAddr = lans[chosen].Addr
			ans.ifaceCIDR = lans[chosen].CIDR
			if ans.iface == "" {
				ans.iface = lans[chosen].Name
			}
		}
		ans.allowLAN = true
	case "all":
		ans.listenAddr = "0.0.0.0"
		ans.allowLAN = true
	case "ip":
		ans.listenAddr = strings.TrimSpace(opts.listenIP)
		ans.allowLAN = !config.IsLoopbackHost(ans.listenAddr)
	default:
		return nil, fmt.Errorf("--listen must be localhost, lan or all")
	}

	trusted := append([]string{}, opts.trusted...)
	if ans.allowLAN {
		// A non-interactive run never assumes a subnet: the operator must name
		// the trusted clients explicitly before a LAN or wildcard listener.
		if len(trusted) == 0 && len(lans) == 1 && !opts.nonInteractive {
			trusted = []string{lans[0].CIDR}
		}
		if len(trusted) == 0 {
			if opts.nonInteractive {
				return nil, fmt.Errorf("a LAN listener needs --trusted-cidr (detected: %s)", describeLANs(lans))
			}
			value, err := p.ask("Trusted client subnets, comma separated", ans.ifaceCIDR)
			if err != nil {
				return nil, err
			}
			for _, part := range strings.Split(value, ",") {
				if item := strings.TrimSpace(part); item != "" {
					trusted = append(trusted, item)
				}
			}
		}
	}
	ans.trusted = trusted

	ans.socksPort = opts.socksPort
	if ans.socksPort == 0 {
		if cfg.Server.SOCKSPort > 0 {
			ans.socksPort = cfg.Server.SOCKSPort
		} else {
			ans.socksPort = 2801
		}
		if !opts.nonInteractive {
			value, err := p.ask("Proxy port", fmt.Sprint(ans.socksPort))
			if err != nil {
				return nil, err
			}
			if _, err := fmt.Sscan(value, &ans.socksPort); err != nil {
				return nil, fmt.Errorf("proxy port must be a number")
			}
		}
	}

	if ans.gatewayMode {
		ans.dnsPort = opts.dnsPort
		if ans.dnsPort == 0 {
			if cfg.Server.DNSPort > 0 && !opts.nonInteractive {
				ans.dnsPort = cfg.Server.DNSPort
			} else {
				ans.dnsPort = 53
			}
		}
		busy := diag.DefaultHost().Listeners(ans.dnsPort)
		if len(busy) > 0 && !serviceServesDNSPort(cfg, ans.dnsPort) {
			if opts.nonInteractive {
				return nil, fmt.Errorf("port %d is already in use (%s); choose another with --dns-port — bypath never stops an existing resolver", ans.dnsPort, strings.Join(busy, ", "))
			}
			fmt.Printf("⚠️  Port %d is already in use: %s\n", ans.dnsPort, strings.Join(busy, ", "))
			fmt.Println("   Bypath never stops systemd-resolved, dnsmasq or another resolver.")
			idx, err := p.choice("DNS port", []string{
				"use 5335 — the gateway answers DNS on 5335; point clients at it explicitly",
				"keep " + fmt.Sprint(ans.dnsPort) + " — I will free the port myself and rerun",
				"cancel setup",
			}, 0)
			if err != nil {
				return nil, err
			}
			switch idx {
			case 0:
				ans.dnsPort = 5335
			case 1:
				return nil, fmt.Errorf("port %d is still in use; nothing was changed", ans.dnsPort)
			default:
				return nil, fmt.Errorf("setup cancelled")
			}
		}
		// A DNS port other than 53 cannot be expressed by DHCP or by ordinary
		// client DNS settings: those carry an address, not a port. Say that
		// before anything is activated instead of surprising the operator later.
		if ans.dnsPort != 53 {
			fmt.Printf("⚠️  DNS runs on port %d, which is nonstandard: standard DHCP and DNS\n", ans.dnsPort)
			fmt.Println("   client settings cannot specify a port. Every client must be pointed at")
			fmt.Printf("   this gateway's address and port %d explicitly (or use a client-side\n", ans.dnsPort)
			fmt.Println("   port-53 redirect). Choose port 53 if clients must use plain DHCP DNS.")
		}
		upstreams := append([]string{}, opts.dnsUpstreams...)
		if len(upstreams) == 0 {
			upstreams = cfg.Gateway.DNSUpstream
		}
		if len(upstreams) == 0 {
			upstreams = []string{"1.1.1.1", "8.8.8.8"}
		}
		ans.upstreams = upstreams
	}

	web := strings.ToLower(strings.TrimSpace(opts.web))
	if web == "" {
		if opts.nonInteractive {
			web = "loopback"
		} else {
			idx, err := p.choice("Web panel", []string{
				"loopback only — reachable on this machine; the first local visit creates the administrator",
				"LAN — reachable from the trusted network; put TLS in front of it",
				"disabled",
			}, 0)
			if err != nil {
				return nil, err
			}
			web = []string{"loopback", "lan", "off"}[idx]
		}
	}
	switch web {
	case "off":
		ans.webEnabled = false
		ans.webListen = "127.0.0.1"
		ans.webAllowLAN = false
	case "loopback":
		ans.webEnabled = true
		ans.webListen = "127.0.0.1"
	case "lan":
		if ans.ifaceAddr == "" && len(lans) == 1 {
			ans.ifaceAddr = lans[0].Addr
		}
		if ans.ifaceAddr == "" {
			return nil, fmt.Errorf("--web lan needs a LAN interface; use --interface")
		}
		ans.webEnabled = true
		ans.webListen = ans.ifaceAddr
		ans.webAllowLAN = true
	default:
		return nil, fmt.Errorf("--web must be off, loopback or lan")
	}
	ans.webPort = opts.webPort
	if ans.webPort == 0 {
		base := cfg.Server.APIPort
		if base == 0 {
			base = 8080
		}
		if cfg.Server.Web.Port > 0 && web != "off" {
			ans.webPort = cfg.Server.Web.Port
		} else {
			ans.webPort = base + 1
		}
		if ans.webEnabled && !opts.nonInteractive {
			value, err := p.ask("Panel port", fmt.Sprint(ans.webPort))
			if err != nil {
				return nil, err
			}
			if _, err := fmt.Sscan(value, &ans.webPort); err != nil {
				return nil, fmt.Errorf("panel port must be a number")
			}
		}
	}

	ans.enableNow = opts.enableGateway && ans.gatewayMode

	if !opts.nonInteractive {
		if err := p.collectImports(ans); err != nil {
			return nil, err
		}
		if ans.gatewayMode && !ans.enableNow {
			ok, err := p.confirm("Enable gateway mode now (only if you already have a verified connection)", false)
			if err != nil {
				return nil, err
			}
			ans.enableNow = ok
		}
		if !ans.startService {
			ok, err := p.confirm("Start the service at the end and verify the first connection", false)
			if err != nil {
				return nil, err
			}
			ans.startService = ok
		}
	} else if ans.gatewayMode && len(ans.uris) == 0 && len(ans.subs) == 0 && !ans.enableNow && countConnections(cfg) == 0 {
		return nil, fmt.Errorf("gateway mode needs a connection: pass --uri or --subscription, or run --mode proxy first")
	}

	// An enabled gateway without a connection would come up as an empty
	// full tunnel, so activation always requires a connection to select.
	if gatewayNeedsConnection(ans, cfg) {
		return nil, fmt.Errorf("enabling the gateway needs a connection: pass --uri or --subscription, or enable it from the panel after verifying one")
	}
	if ans.enableNow {
		// Activation is applied only after the connection is verified.
		ans.startService = true
	}
	if !opts.nonInteractive {
		return ans, printReview(ans, cfg)
	}
	return ans, nil
}

func (p *prompter) collectImports(ans *answers) error {
	for {
		value, err := p.secret("Proxy URI or subscription URL (empty to skip): ")
		if err != nil {
			return err
		}
		if value == "" {
			return nil
		}
		if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
			ans.subs = append(ans.subs, value)
		} else {
			ans.uris = append(ans.uris, value)
		}
	}
}

func printReview(ans *answers, cfg *config.Config) error {
	fmt.Println("\nReview")
	if ans.gatewayMode {
		fmt.Printf("  mode:        gateway (%s, DNS %d)\n", ans.iface, ans.dnsPort)
		if ans.enableNow {
			fmt.Println("  activation:  gateway enabled in this run")
		} else {
			fmt.Println("  activation:  staged, gateway stays disabled until verified")
		}
		if ans.addressMayChange {
			fmt.Printf("  address:     %s may change by DHCP — reserve it before clients rely on it\n", ans.ifaceAddr)
		}
	} else {
		fmt.Println("  mode:        proxy-only")
	}
	fmt.Printf("  proxy:       %s:%d\n", ans.listenAddr, ans.socksPort)
	if ans.gatewayMode && !ans.allowLAN {
		fmt.Println("               loopback only — gateway clients are routed, they do not use the SOCKS port")
	}
	if ans.allowLAN {
		fmt.Printf("  trusted:     %s\n", strings.Join(ans.trusted, ", "))
	}
	if ans.webEnabled {
		fmt.Printf("  panel:       %s:%d\n", ans.webListen, ans.webPort)
	} else {
		fmt.Println("  panel:       disabled")
	}
	fmt.Printf("  group:       %s\n", ans.group)
	fmt.Printf("  imports:     %d URI(s), %d subscription(s)\n", len(ans.uris), len(ans.subs))
	fmt.Printf("  verify:      %t\n", ans.startService)
	if ans.persistService {
		fmt.Println("  at boot:     enable after the verified start")
	} else {
		fmt.Println("  at boot:     not enabled (starting now is not the same as enabling)")
	}
	return nil
}

func applyAnswers(cfg *config.Config, ans *answers) error {
	cfg.Server.SOCKSPort = ans.socksPort
	cfg.Server.SOCKSListen = ans.listenAddr
	cfg.Server.SOCKSAllowLAN = ans.allowLAN
	cfg.Server.SOCKSAllowCIDRs = nil
	if ans.allowLAN {
		cfg.Server.SOCKSAllowCIDRs = ans.trusted
	}
	cfg.Profiles.ActiveGroup = ans.group
	cfg.Server.Web.Enabled = ans.webEnabled
	if ans.webEnabled {
		cfg.Server.Web.Listen = ans.webListen
		cfg.Server.Web.Port = ans.webPort
		cfg.Server.Web.AllowLAN = ans.webAllowLAN
	}
	if len(cfg.Routing.Rules) == 0 {
		cfg.Routing.Rules = []config.RoutingRule{{Match: "default", Outbound: "proxy"}}
	}
	if ans.gatewayMode {
		cfg.Gateway.Interface = ans.iface
		cfg.Gateway.NativeTUN = true
		cfg.Gateway.DNSMode = "strict"
		cfg.Server.DNSPort = ans.dnsPort
		cfg.Gateway.DNSUpstream = ans.upstreams
	}
	// A gateway flag written before verification would start an unproven
	// gateway at boot; startAndVerify enables it after the link is proven.
	cfg.Gateway.Enabled = ans.enableNow && !ans.deferActivation
	return cfg.NormalizeAndValidate()
}

func writeConfig(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		backup := path + ".bak"
		if existing, readErr := os.ReadFile(path); readErr == nil {
			_ = os.WriteFile(backup, existing, 0600)
		}
	}
	tmp, err := os.CreateTemp(dir, ".bypath-config-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func redactConfigYAML(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "api_token:") {
			indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
			lines[i] = indent + `api_token: "••• redacted •••"`
		}
	}
	return strings.Join(lines, "\n")
}

// runImports stores the connections and selects one. It returns how many
// connections the group holds afterwards.
func runImports(cfg *config.Config, cfgPath string, ans *answers) (int, error) {
	ctx := context.Background()
	p := pathsFor()
	svc, err := openSetupContract(p, cfg, cfgPath)
	if err != nil {
		return 0, fmt.Errorf("opening the profile store: %v", err)
	}
	var firstErr error
	for _, uri := range ans.uris {
		res, err := svc.ImportURI(ctx, ans.group, uri)
		if err != nil {
			firstErr = fmt.Errorf("one URI was rejected: %v", err)
			fmt.Printf("⚠️  %v\n", firstErr)
			continue
		}
		if len(res.Skipped) > 0 {
			fmt.Printf("ℹ️  %s already exists; skipped\n", res.Skipped[0].Name)
		}
	}
	for _, sub := range ans.subs {
		if _, err := svc.AddSubscription(ctx, ans.group, sub); err != nil {
			msg := err.Error()
			if strings.Contains(msg, "already exists") {
				fmt.Println("ℹ️  subscription already registered; refreshing it instead")
			} else {
				firstErr = fmt.Errorf("subscription rejected: %v", err)
				fmt.Printf("⚠️  %v\n", firstErr)
				continue
			}
		}
		fmt.Println("   fetching subscription…")
		result, err := svc.RefreshSubscription(ctx, ans.group, sub, nil)
		if err != nil {
			firstErr = fmt.Errorf("subscription fetch failed: %v", err)
			fmt.Printf("⚠️  %v\n", firstErr)
			continue
		}
		fmt.Printf("✅ Subscription registered in group %s\n", result.Group)
	}
	list, err := svc.ListConnections(ctx, app.ConnectionFilter{Group: ans.group})
	if err != nil {
		return 0, err
	}
	if len(list) == 0 {
		return 0, firstErr
	}
	target := list[0]
	if ans.selectName != "" {
		found := false
		for _, conn := range list {
			if conn.Remark == ans.selectName {
				target = conn
				found = true
				break
			}
		}
		if !found {
			return len(list), fmt.Errorf("no connection named %q in group %s; nothing was selected", ans.selectName, ans.group)
		}
	}
	if _, err := svc.SetActive(ctx, target.ID); err != nil {
		return len(list), fmt.Errorf("selecting %q: %v", target.Remark, err)
	}
	fmt.Printf("✅ Selected %q (%s)\n", target.Remark, strings.ToUpper(target.Protocol))
	return len(list), firstErr
}

func pathsFor() *paths.Resolved {
	return paths.Get()
}

// openSetupContract prefers the running daemon's control socket. A root daemon
// rejects unauthenticated loopback API calls by design, so importing through
// the TCP API while the service is up would fail with 401 even as root.
func openSetupContract(p *paths.Resolved, cfg *config.Config, cfgPath string) (app.Contract, error) {
	if filepath.Clean(cfgPath) == filepath.Clean(p.ConfigFile) {
		return app.OpenDefault()
	}
	return app.OpenWith(p, cfg, cfgPath)
}

// gatewayNeedsConnection reports whether activation was requested while no
// connection exists to carry it.
func gatewayNeedsConnection(ans *answers, cfg *config.Config) bool {
	return ans.gatewayMode && ans.enableNow &&
		len(ans.uris) == 0 && len(ans.subs) == 0 && countConnections(cfg) == 0
}

func countConnections(cfg *config.Config) int {
	files, _ := filepath.Glob(filepath.Join(cfg.Profiles.Directory, "*.json"))
	count := 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		var group struct {
			Links []json.RawMessage `json:"links"`
		}
		if err := json.Unmarshal(data, &group); err != nil {
			continue
		}
		count += len(group.Links)
	}
	return count
}

type prompter struct {
	in  *bufio.Reader
	tty bool
	out io.Writer
}

func (p *prompter) ask(label, def string) (string, error) {
	fmt.Fprintf(p.out, "%s", label)
	if def != "" {
		fmt.Fprintf(p.out, " [%s]", def)
	}
	fmt.Fprint(p.out, ": ")
	line, err := p.in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def, nil
	}
	return line, nil
}

func (p *prompter) secret(label string) (string, error) {
	fmt.Fprintf(p.out, "%s", label)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		data, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(p.out)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
	line, err := p.in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func (p *prompter) confirm(label string, def bool) (bool, error) {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	value, err := p.ask(fmt.Sprintf("%s [%s]", label, hint), "")
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return def, nil
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	}
	return false, fmt.Errorf("answer yes or no")
}

func (p *prompter) choice(label string, options []string, def int) (int, error) {
	fmt.Printf("%s:\n", label)
	for i, option := range options {
		fmt.Printf("  %d) %s\n", i+1, option)
	}
	value, err := p.ask("Choose", fmt.Sprint(def+1))
	if err != nil {
		return 0, err
	}
	var idx int
	if _, err := fmt.Sscan(value, &idx); err != nil || idx < 1 || idx > len(options) {
		return 0, fmt.Errorf("%s: pick a number between 1 and %d", label, len(options))
	}
	return idx - 1, nil
}

func describeLANs(lans []lanIface) string {
	if len(lans) == 0 {
		return "none"
	}
	parts := make([]string, len(lans))
	for i, lan := range lans {
		parts[i] = fmt.Sprintf("%s (%s, %s)", lan.Name, lan.Addr, lan.CIDR)
	}
	return strings.Join(parts, ", ")
}

func reportPlan(cfg *config.Config, ans *answers, cfgPath string) {
	fmt.Println("\nConfiguration")
	if cfg.Gateway.Enabled {
		fmt.Printf("  mode:    gateway via %s\n", cfg.Gateway.Interface)
	} else if ans.gatewayMode {
		fmt.Printf("  mode:    gateway staged (disabled) via %s\n", cfg.Gateway.Interface)
	} else {
		fmt.Println("  mode:    proxy-only")
	}
	fmt.Printf("  proxy:   %s:%d\n", cfg.Server.SOCKSListenAddress(), cfg.Server.SOCKSPort)
	if len(cfg.Server.SOCKSAllowCIDRs) > 0 {
		fmt.Printf("  trusted: %s\n", strings.Join(cfg.Server.SOCKSAllowCIDRs, ", "))
	}
	if cfg.Server.Web.Enabled {
		fmt.Printf("  panel:   %s:%d\n", cfg.Server.Web.Listen, cfg.Server.Web.Port)
	}
}

func systemctl(action string) error {
	return exec.Command("systemctl", action, "bypath").Run()
}

func serviceState() string {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return ""
	}
	out, err := exec.Command("systemctl", "is-active", "bypath").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func unitInstalled() bool {
	if _, err := os.Stat("/etc/systemd/system/bypath.service"); err == nil {
		return true
	}
	_, err := os.Stat("/usr/lib/systemd/system/bypath.service")
	return err == nil
}

// serviceServesDNSPort reports whether the running bypath daemon itself holds
// the DNS port. An active unit alone proves nothing: a proxy-only daemon opens
// no DNS socket, so a foreign listener on port 53 must still be reported.
func serviceServesDNSPort(cfg *config.Config, port int) bool {
	return serviceState() == "active" && cfg.Gateway.Enabled && cfg.Server.DNSPort == port
}

// startAndVerify supervises one start, proves the tunnel exit, and only then
// activates gateway mode. A failed verification leaves gateway mode disabled.
func startAndVerify(cfgPath string, ans *answers) bool {
	if !unitInstalled() {
		fmt.Println("\nℹ️  No bypath systemd unit is installed, so setup will not start anything.")
		fmt.Println("   Run `bypath run` in a supervised session, then `bypath doctor --egress`.")
		return true
	}
	if os.Geteuid() != 0 {
		fmt.Println("\n❌ Starting the service needs root. Re-run this step with sudo.")
		return false
	}
	action := "start"
	if serviceState() == "active" {
		action = "restart"
	}
	fmt.Printf("\nStarting the gateway (%s bypath)…\n", action)
	if err := systemctl(action); err != nil {
		fmt.Printf("❌ systemctl %s bypath failed: %v\n", action, err)
		fmt.Println("   Inspect `systemctl status bypath` and `journalctl -u bypath`.")
		return false
	}
	status, ok := waitConnected(120 * time.Second)
	if !ok {
		fmt.Printf("❌ The gateway did not reach CONNECTED (last state: %s).\n", status.State)
		fmt.Println("   Nothing on the LAN was changed. Inspect `journalctl -u bypath` and rerun `bypath doctor`.")
		return false
	}
	fmt.Println("✅ Gateway reports CONNECTED")

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	svc, err := app.OpenDefault()
	if err != nil {
		fmt.Printf("⚠️  Could not query the gateway: %v\n", err)
		return false
	}
	proof, proofErr := svc.ProbeExitIdentity(ctx)
	if proofErr != nil {
		fmt.Printf("⚠️  The tunnel is connected but its exit identity could not be checked: %v\n", proofErr)
		return false
	}
	verdict := proof.Verdict()
	if !verdict.Allowed {
		fmt.Printf("❌ %s\n", verdict.Detail)
		fmt.Println("   Gateway mode stays disabled.")
		return false
	}
	if verdict.Verified {
		fmt.Printf("✅ Exit identity verified: tunnel %s, direct path %s\n",
			strings.Join(proof.Exits, ", "), strings.Join(proof.Uplink, ", "))
	} else {
		fmt.Printf("⚠️  Tunnel connectivity is proven, but the exit identity is UNVERIFIED: %s\n", verdict.Detail)
		fmt.Println("   The gateway stays usable; verify the exit later with `bypath doctor --egress`.")
	}
	if !ans.gatewayMode {
		fmt.Println("✅ The proxy tier is working. Enable gateway mode when you are ready.")
		return true
	}
	fmt.Println("\nActivating gateway mode (LAN gateway and DNS)…")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		return false
	}
	cfg.Gateway.Enabled = true
	cfg.Gateway.Interface = ans.iface
	cfg.Gateway.NativeTUN = true
	cfg.Gateway.DNSMode = "strict"
	if err := cfg.NormalizeAndValidate(); err != nil {
		fmt.Printf("❌ %v\n", err)
		return false
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		return false
	}
	if err := writeConfig(cfgPath, data); err != nil {
		fmt.Printf("❌ %v\n", err)
		return false
	}
	if err := systemctl("restart"); err != nil {
		fmt.Printf("❌ Restart failed: %v — revert with `bypath setup --mode proxy` if the LAN is affected.\n", err)
		return false
	}
	status, ok = waitConnected(120 * time.Second)
	if !ok {
		fmt.Printf("❌ Gateway mode did not reach CONNECTED (last state: %s).\n", status.State)
		fmt.Println("   Roll back with `bypath setup --mode proxy` and restart the service.")
		return false
	}
	fmt.Println("✅ Gateway mode is active and connected")
	fmt.Print(renderLANClientGuidance(ans))
	fmt.Println()
	return true
}

func waitConnected(timeout time.Duration) (app.Status, bool) {
	deadline := time.Now().Add(timeout)
	last := ""
	for time.Now().Before(deadline) {
		svc, err := app.OpenDefault()
		if err == nil {
			status, statusErr := svc.Status(context.Background())
			if statusErr == nil {
				if status.State != last {
					fmt.Printf("   state: %s\n", status.State)
					last = status.State
				}
				if status.State == "CONNECTED" {
					return status, true
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	return app.Status{State: last}, false
}
