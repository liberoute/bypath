package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/liberoute/bypath/internal/config"
)

// gatewayRequirement is one host capability gateway mode cannot start without.
type gatewayRequirement struct {
	Key     string
	Label   string
	OK      bool
	Package string // Debian/DietPi package that provides it; empty when apt cannot help
	Manual  string // exact manual fix shown to the operator
}

// setupHost isolates the host probes and the package installation so the
// prerequisite gate can be exercised without touching the machine.
type setupHost struct {
	euid     func() int
	lookPath func(string) (string, error)
	stat     func(string) (os.FileInfo, error)
	run      func(ctx context.Context, name string, args ...string) error
}

func defaultSetupHost() setupHost {
	return setupHost{
		euid:     os.Geteuid,
		lookPath: exec.LookPath,
		stat:     os.Stat,
		run: func(ctx context.Context, name string, args ...string) error {
			cmd := exec.CommandContext(ctx, name, args...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		},
	}
}

// setupHostFor withholds command execution from a dry run, so no code path
// reached by --dry-run can install a package, even with --install-packages.
func setupHostFor(opts *setupOptions) setupHost {
	h := defaultSetupHost()
	if opts.dryRun {
		h.run = func(_ context.Context, name string, args ...string) error {
			return fmt.Errorf("dry run: refusing to execute %s %s", name, strings.Join(args, " "))
		}
	}
	return h
}

// errDryRunPrerequisites marks a dry run whose real counterpart would stop at
// the prerequisite gate; the preview continues and setup exits non-zero.
var errDryRunPrerequisites = errors.New("dry run: gateway prerequisites are not met")

func (h setupHost) canRun(bin string) bool {
	_, err := h.lookPath(bin)
	return err == nil
}

func (h setupHost) tunPresent() bool {
	info, err := h.stat("/dev/net/tun")
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

// gatewayPrerequisites is the complete set the gateway start path relies on.
// A missing entry is reported before any configuration is written.
func gatewayPrerequisites(h setupHost) []gatewayRequirement {
	return []gatewayRequirement{
		{
			Key:    "root",
			Label:  "root privileges (firewall, TUN and the bypath unit)",
			OK:     h.euid() == 0,
			Manual: "re-run with sudo: `sudo bypath setup --mode gateway ...` — a normal account with sudo is supported",
		},
		{
			Key:     "iproute2",
			Label:   "iproute2 (the `ip` command)",
			OK:      h.canRun("ip"),
			Package: "iproute2",
			Manual:  "sudo apt install iproute2",
		},
		{
			Key:     "iptables",
			Label:   "iptables (IPv4 routing and the fail-closed FORWARD rules)",
			OK:      h.canRun("iptables"),
			Package: "iptables",
			Manual:  "sudo apt install iptables",
		},
		{
			Key:     "ip6tables",
			Label:   "ip6tables (IPv6 fail-closed isolation)",
			OK:      h.canRun("ip6tables"),
			Package: "iptables",
			Manual:  "sudo apt install iptables",
		},
		{
			Key:    "tun",
			Label:  "TUN device /dev/net/tun",
			OK:     h.tunPresent(),
			Manual: "load the module with `sudo modprobe tun` (in a container, pass `--device /dev/net/tun`)",
		},
	}
}

func missingRequirements(reqs []gatewayRequirement) []gatewayRequirement {
	var missing []gatewayRequirement
	for _, req := range reqs {
		if !req.OK {
			missing = append(missing, req)
		}
	}
	return missing
}

func missingPackages(reqs []gatewayRequirement) []string {
	seen := map[string]bool{}
	var pkgs []string
	for _, req := range reqs {
		if req.Package == "" || seen[req.Package] {
			continue
		}
		seen[req.Package] = true
		pkgs = append(pkgs, req.Package)
	}
	sort.Strings(pkgs)
	return pkgs
}

// ensureGatewayPrerequisites refuses gateway mode until the host can enforce
// it. It runs before anything is written, so a declined or failed installation
// leaves an existing configuration byte-for-byte untouched; the operator can
// install the packages and re-run the same command.
func ensureGatewayPrerequisites(p *prompter, opts *setupOptions, h setupHost) error {
	reqs := gatewayPrerequisites(h)
	missing := missingRequirements(reqs)
	if len(missing) == 0 {
		fmt.Println("✅ Gateway prerequisites: root, iproute2, iptables, ip6tables and TUN are available.")
		return nil
	}

	fmt.Println("\nGateway mode prerequisites are not met:")
	for _, req := range missing {
		fmt.Printf("  ✗ %s\n      fix: %s\n", req.Label, req.Manual)
	}
	fmt.Println("  Nothing has been written; an existing configuration is untouched.")
	pkgs := missingPackages(missing)

	if opts.dryRun {
		if len(pkgs) > 0 {
			switch {
			case !h.canRun("apt-get"):
				fmt.Printf("  Dry run: a real run would stop here; install `%s` manually (apt-get is not available).\n", strings.Join(pkgs, " "))
			case opts.installPackages:
				fmt.Printf("  Dry run: a real run would execute `apt-get update && apt-get install -y %s` (approved by --install-packages).\n", strings.Join(pkgs, " "))
			default:
				fmt.Printf("  Dry run: a real run would offer `apt-get install -y %s` and continue only after an explicit yes.\n", strings.Join(pkgs, " "))
			}
		}
		fmt.Println("  Dry run: no package was installed and nothing was executed.")
		return errDryRunPrerequisites
	}

	for _, req := range missing {
		if req.Key == "root" {
			return errors.New("gateway mode needs root: re-run with `sudo bypath setup --mode gateway ...`; a normal account with sudo is supported")
		}
	}

	if len(pkgs) == 0 {
		return errors.New("the TUN device is missing: run `sudo modprobe tun`, then re-run setup (or use --mode proxy); nothing was changed")
	}
	fmt.Printf("  On Debian/DietPi: `sudo apt install %s`\n", strings.Join(pkgs, " "))

	if !h.canRun("apt-get") {
		return fmt.Errorf("apt-get is not available; install manually with `sudo apt install %s`, then re-run setup; nothing was changed", strings.Join(pkgs, " "))
	}

	approve := opts.installPackages
	if !approve && !opts.nonInteractive {
		ok, err := p.confirm(fmt.Sprintf("Install the missing packages now (apt-get install -y %s)", strings.Join(pkgs, " ")), false)
		if err != nil {
			return err
		}
		approve = ok
	}
	if !approve {
		return fmt.Errorf("install them with `sudo apt install %s`, then re-run setup; nothing was changed", strings.Join(pkgs, " "))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	fmt.Printf("Running: apt-get update && apt-get install -y %s\n", strings.Join(pkgs, " "))
	if err := h.run(ctx, "apt-get", "update", "-qq"); err != nil {
		fmt.Printf("⚠️  apt-get update failed: %v — trying the install anyway\n", err)
	}
	args := append([]string{"install", "-y"}, pkgs...)
	if err := h.run(ctx, "apt-get", args...); err != nil {
		return fmt.Errorf("package installation failed: %v; install manually with `sudo apt install %s`, then re-run setup; nothing was changed", err, strings.Join(pkgs, " "))
	}

	remaining := missingRequirements(gatewayPrerequisites(h))
	if len(remaining) > 0 {
		labels := make([]string, len(remaining))
		for i, req := range remaining {
			labels[i] = req.Label
		}
		return fmt.Errorf("still missing after installation: %s; fix them manually and re-run setup; nothing was changed", strings.Join(labels, ", "))
	}
	fmt.Println("✅ Gateway prerequisites are satisfied now.")
	return nil
}

// addressAssignment is the best evidence the host configuration gives for how
// an interface receives its address.
type addressAssignment int

const (
	assignmentUnknown addressAssignment = iota
	assignmentDHCP
	assignmentStatic
)

// addressChangeRisk reports whether the LAN address is not proven static. A
// lease renewal after activation would silently break every client, so missing
// evidence warns just like an explicit DHCP stanza.
func addressChangeRisk(iface string, files map[string]string) (bool, string) {
	state, source := classifyAddressAssignment(iface, files)
	switch state {
	case assignmentStatic:
		return false, ""
	case assignmentDHCP:
		return true, fmt.Sprintf("%s is configured by DHCP in %s", iface, source)
	default:
		return true, fmt.Sprintf("no static address for %s was found in /etc/network/interfaces, dhcpcd, systemd-networkd or NetworkManager", iface)
	}
}

func classifyAddressAssignment(iface string, files map[string]string) (addressAssignment, string) {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	state, source := assignmentUnknown, ""
	for _, path := range paths {
		kind, found := classifyConfigFile(iface, path, files[path])
		if !found {
			continue
		}
		if kind == assignmentDHCP {
			return assignmentDHCP, path
		}
		if kind == assignmentStatic {
			state, source = assignmentStatic, path
		}
	}
	return state, source
}

func classifyConfigFile(iface, path, content string) (addressAssignment, bool) {
	base := filepath.Base(path)
	switch {
	case base == "interfaces" || strings.HasSuffix(filepath.ToSlash(path), "/interfaces.d/"+base):
		return classifyDebianInterfaces(iface, content)
	case base == "dhcpcd.conf":
		return classifyDHCPCD(iface, content)
	case strings.HasSuffix(base, ".network"):
		return classifyNetworkd(iface, content)
	case strings.HasSuffix(base, ".nmconnection"):
		return classifyNetworkManager(iface, content)
	}
	return assignmentUnknown, false
}

func classifyDebianInterfaces(iface, content string) (addressAssignment, bool) {
	state, found := assignmentUnknown, false
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(stripConfigComment(line))
		if len(fields) < 4 || fields[0] != "iface" || fields[1] != iface {
			continue
		}
		found = true
		switch fields[3] {
		case "dhcp":
			return assignmentDHCP, true
		case "static":
			state = assignmentStatic
		}
	}
	return state, found
}

// classifyDHCPCD reads a dhcpcd.conf block. dhcpcd manages every interface it
// names, so a block without a static assignment is DHCP by definition.
func classifyDHCPCD(iface, content string) (addressAssignment, bool) {
	current, found, static := "", false, false
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(stripConfigComment(line))
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "interface" && len(fields) > 1 {
			current = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(stripConfigComment(line)), "interface"))
			if current == iface {
				found = true
			}
			continue
		}
		if current == iface && strings.HasPrefix(fields[0], "static") {
			static = true
		}
	}
	if !found {
		return assignmentUnknown, false
	}
	if static {
		return assignmentStatic, true
	}
	return assignmentDHCP, true
}

func classifyNetworkd(iface, content string) (addressAssignment, bool) {
	section := ""
	match, dhcp, address := false, false, false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(stripConfigComment(line))
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			section = strings.ToLower(strings.Trim(trimmed, "[]"))
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		switch section + "." + key {
		case "match.name":
			for _, name := range strings.Fields(value) {
				if name == iface {
					match = true
				}
			}
		case "network.dhcp":
			switch strings.ToLower(value) {
			case "yes", "ipv4", "ipv6":
				dhcp = true
			}
		case "network.address":
			if value != "" {
				address = true
			}
		}
	}
	if !match {
		return assignmentUnknown, false
	}
	if dhcp {
		return assignmentDHCP, true
	}
	if address {
		return assignmentStatic, true
	}
	return assignmentUnknown, true
}

func classifyNetworkManager(iface, content string) (addressAssignment, bool) {
	section, matched, method := "", false, ""
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(stripConfigComment(line))
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			section = strings.ToLower(strings.Trim(trimmed, "[]"))
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		switch section + "." + key {
		case "connection.interface-name":
			if value == iface {
				matched = true
			}
		case "ipv4.method":
			method = strings.ToLower(value)
		}
	}
	if !matched {
		return assignmentUnknown, false
	}
	switch method {
	case "manual", "static":
		return assignmentStatic, true
	case "auto", "dhcp":
		return assignmentDHCP, true
	}
	return assignmentUnknown, true
}

func stripConfigComment(line string) string {
	if i := strings.IndexAny(line, "#;"); i >= 0 {
		return line[:i]
	}
	return line
}

// loadAddressConfig reads the common Debian/DietPi address sources. Missing
// files are simply absent evidence, not an error.
func loadAddressConfig() map[string]string {
	files := map[string]string{}
	add := func(path string) {
		if data, err := os.ReadFile(path); err == nil {
			files[path] = string(data)
		}
	}
	add("/etc/network/interfaces")
	add("/etc/dhcpcd.conf")
	for _, pattern := range []string{
		"/etc/network/interfaces.d/*",
		"/etc/systemd/network/*.network",
		"/etc/NetworkManager/system-connections/*.nmconnection",
	} {
		matches, _ := filepath.Glob(pattern)
		for _, match := range matches {
			add(match)
		}
	}
	return files
}

func renderAddressWarning(iface, addr, reason string) string {
	return fmt.Sprintf("⚠️  %s (%s) is not a proven static address: %s.\n"+
		"   If the router assigns it by DHCP, LAN clients lose the gateway when the lease\n"+
		"   changes. Reserve the address in the router (DHCP reservation) or configure it\n"+
		"   statically before relying on gateway mode.",
		iface, addr, reason)
}

// subnetMask renders the IPv4 mask for a CIDR such as 192.168.1.118/24.
func subnetMask(cidr string) (mask, prefix string) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ipnet.IP.To4() == nil {
		return "", ""
	}
	ones, _ := ipnet.Mask.Size()
	m := ipnet.Mask
	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3]), fmt.Sprint(ones)
}

// renderDNSPortNote explains a nonstandard DNS listener in terms a client can
// act on. Client DNS settings and DHCP carry an address only; the gateway's
// LAN intercept (setupDNSIntercept) redirects port 53 to the listener, so
// clients keep the ordinary port.
func renderDNSPortNote(iface string, dnsPort int) string {
	return fmt.Sprintf("   Bypath's own DNS listener uses port %d. Clients still use this gateway's\n"+
		"   address on the ordinary port 53 — client DNS settings and DHCP cannot carry\n"+
		"   a port, and they do not need to: while gateway mode runs, Bypath redirects\n"+
		"   DNS on port 53 arriving from the LAN on %s to port %d.\n", dnsPort, iface, dnsPort)
}

// renderLANClientGuidance is the recipe printed after activation. It never
// proposes a client address: Bypath cannot see the router's DHCP pool or the
// other devices, so only the administrator can confirm an address is free.
func renderLANClientGuidance(ans *answers) string {
	mask, prefix := subnetMask(ans.ifaceCIDR)
	maskLine, linuxPrefix := "the same subnet mask the client has now", "<prefix>"
	if mask != "" {
		maskLine, linuxPrefix = fmt.Sprintf("%s (/%s)", mask, prefix), prefix
	}
	var b strings.Builder
	b.WriteString("\nPoint one LAN client at this gateway (every other device keeps using the router)\n")
	b.WriteString("  1. On the client, note the IPv4 address it has now\n")
	b.WriteString("     (Windows: ipconfig · macOS: ipconfig getifaddr en0 · Linux: ip -4 addr).\n")
	b.WriteString("  2. In the router, reserve that address for this client (DHCP reservation), so\n")
	b.WriteString("     no other device can receive it. Or use an address you have confirmed is\n")
	b.WriteString("     unused and outside the router's DHCP pool. Bypath cannot check this for you.\n")
	b.WriteString("  3. Set the client's IPv4 configuration to manual with that address and:\n")
	fmt.Fprintf(&b, "       Subnet mask:     %s\n", maskLine)
	fmt.Fprintf(&b, "       Default gateway: %s\n", ans.ifaceAddr)
	fmt.Fprintf(&b, "       DNS server:      %s\n", ans.ifaceAddr)
	if ans.dnsPort != 53 {
		b.WriteString(renderDNSPortNote(ans.iface, ans.dnsPort))
	}
	b.WriteString("     Windows: Settings → Network → adapter → IP assignment → Edit → Manual, IPv4.\n")
	b.WriteString("     macOS:   System Settings → Network → Details → TCP/IP → Manually; DNS tab.\n")
	fmt.Fprintf(&b, "     Linux:   nmcli con mod \"<connection>\" ipv4.method manual ipv4.addresses <reserved-address>/%s ipv4.gateway %s ipv4.dns %s\n",
		linuxPrefix, ans.ifaceAddr, ans.ifaceAddr)
	b.WriteString("  4. Verify from the client: open a site, then run `bypath status` on this host.\n")
	b.WriteString("  If the router also hands out IPv6, the client can reach IPv6 sites directly,\n")
	b.WriteString("  outside this gateway; turn IPv6 off on that client for a strict test.\n")
	b.WriteString("  Undo: switch the client back to automatic (DHCP).\n")
	return b.String()
}

// renderPanelAccess explains how to reach a loopback-only panel from another
// computer without exposing it to the LAN. user and host fill the ssh command;
// placeholders are used when they are unknown.
func renderPanelAccess(cfg *config.Config, user, host string) string {
	web := cfg.Server.Web
	if !web.Enabled || !config.IsLoopbackHost(web.Listen) {
		return ""
	}
	if user == "" {
		user = "<user>"
	}
	if host == "" {
		host = "<this-host-address>"
	}
	target := web.Listen
	if strings.Contains(target, ":") {
		target = "[" + target + "]"
	}
	port := web.Port
	codePath := filepath.Join(filepath.Dir(cfg.Profiles.Directory), "web", "setup-code")
	var b strings.Builder
	b.WriteString("\nWeb panel (loopback only; it is not reachable from the LAN)\n")
	fmt.Fprintf(&b, "  On this host:  http://%s:%d\n", target, port)
	b.WriteString("  From another computer, tunnel it over SSH instead of exposing it:\n")
	fmt.Fprintf(&b, "    ssh -N -L %d:%s:%d %s@%s\n", port, target, port, user, host)
	fmt.Fprintf(&b, "    then open http://127.0.0.1:%d on that computer (keep ssh running).\n", port)
	fmt.Fprintf(&b, "  First visit, no administrator yet: the one-time setup code is\n    `sudo cat %s` on this host.\n", codePath)
	return b.String()
}

// panelSSHUser is the account an operator most likely logs in with: the one
// that invoked sudo, not root.
func panelSSHUser() string {
	if u := strings.TrimSpace(os.Getenv("SUDO_USER")); u != "" && u != "root" {
		return u
	}
	if u := strings.TrimSpace(os.Getenv("USER")); u != "" && u != "root" {
		return u
	}
	return ""
}
