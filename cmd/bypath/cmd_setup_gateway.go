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

	for _, req := range missing {
		if req.Key == "root" {
			return errors.New("gateway mode needs root: re-run with `sudo bypath setup --mode gateway ...`; a normal account with sudo is supported")
		}
	}

	pkgs := missingPackages(missing)
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

// clientExample derives a concrete client address from the LAN subnet.
func clientExample(cidr string) (network, client string) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil || ipnet.IP.To4() == nil {
		return "the same LAN subnet", "a free address on the same LAN subnet"
	}
	ip := make(net.IP, net.IPv4len)
	copy(ip, ipnet.IP.To4())
	ip[3] += 50
	if !ipnet.Contains(ip) {
		ip = make(net.IP, net.IPv4len)
		copy(ip, ipnet.IP.To4())
		ip[3] += 2
	}
	return ipnet.String(), ip.String()
}

func cidrPrefix(cidr string) string {
	if _, prefix, ok := strings.Cut(cidr, "/"); ok && prefix != "" {
		return prefix
	}
	return "24"
}

// renderLANClientGuidance is the concrete recipe printed after activation.
func renderLANClientGuidance(ans *answers) string {
	network, client := clientExample(ans.ifaceCIDR)
	var b strings.Builder
	b.WriteString("\nPoint one LAN client at this gateway\n")
	fmt.Fprintf(&b, "  Client address:  %s (any free address in %s)\n", client, network)
	fmt.Fprintf(&b, "  Default gateway: %s\n", ans.ifaceAddr)
	if ans.dnsPort == 53 {
		fmt.Fprintf(&b, "  DNS server:      %s\n", ans.ifaceAddr)
	} else {
		fmt.Fprintf(&b, "  DNS server:      %s, port %d (set the port explicitly; DHCP cannot carry one)\n", ans.ifaceAddr, ans.dnsPort)
	}
	b.WriteString("  Windows: adapter IPv4 properties → Use the following IP address; enter the client address, gateway and DNS above.\n")
	b.WriteString("  macOS:   System Settings → Network → Details → TCP/IP → Manual; enter the same values.\n")
	fmt.Fprintf(&b, "  Linux:   nmcli con mod \"<connection>\" ipv4.method manual ipv4.addresses %s/%s ipv4.gateway %s ipv4.dns %s\n",
		client, cidrPrefix(ans.ifaceCIDR), ans.ifaceAddr, ans.ifaceAddr)
	b.WriteString("  Then verify from the client: reach the gateway, open a site, and check `bypath status` on this host.\n")
	return b.String()
}
