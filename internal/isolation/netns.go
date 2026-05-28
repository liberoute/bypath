// Package isolation provides network namespace management for Linux.
// This replaces firejail for network isolation of tunnel processes.
package isolation

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// Namespace represents a Linux network namespace with its own
// network stack (interfaces, routes, iptables).
type Namespace struct {
	Name      string
	Interface string // host-side veth name
	PeerName  string // namespace-side veth name
	IP        string // IP assigned inside namespace
	PeerIP    string // IP on host side of veth
	Gateway   string // default gateway inside namespace
	DNS       []string
	created   bool
}

// Config for creating a new namespace.
type Config struct {
	Name      string   // namespace name (e.g., "bypath-tun-0")
	HostVeth  string   // host-side veth (e.g., "veth-bp0")
	PeerVeth  string   // peer-side veth (e.g., "veth-bp0-p")
	IP        string   // IP for peer inside namespace (e.g., "10.200.0.2/24")
	HostIP    string   // IP for host side (e.g., "10.200.0.1/24")
	Gateway   string   // default gw inside namespace (e.g., "10.200.0.1")
	DNS       []string // DNS servers
}

// Create sets up a new network namespace with a veth pair.
// Equivalent to:
//
//	ip netns add <name>
//	ip link add <host-veth> type veth peer name <peer-veth>
//	ip link set <peer-veth> netns <name>
//	ip addr add <host-ip> dev <host-veth>
//	ip link set <host-veth> up
//	ip netns exec <name> ip addr add <ip> dev <peer-veth>
//	ip netns exec <name> ip link set <peer-veth> up
//	ip netns exec <name> ip link set lo up
//	ip netns exec <name> ip route add default via <gateway>
func Create(cfg Config) (*Namespace, error) {
	ns := &Namespace{
		Name:      cfg.Name,
		Interface: cfg.HostVeth,
		PeerName:  cfg.PeerVeth,
		IP:        cfg.IP,
		PeerIP:    cfg.HostIP,
		Gateway:   cfg.Gateway,
		DNS:       cfg.DNS,
	}

	commands := [][]string{
		// Create namespace
		{"ip", "netns", "add", cfg.Name},
		// Create veth pair
		{"ip", "link", "add", cfg.HostVeth, "type", "veth", "peer", "name", cfg.PeerVeth},
		// Move peer into namespace
		{"ip", "link", "set", cfg.PeerVeth, "netns", cfg.Name},
		// Configure host side
		{"ip", "addr", "add", cfg.HostIP, "dev", cfg.HostVeth},
		{"ip", "link", "set", cfg.HostVeth, "up"},
		// Configure namespace side
		{"ip", "netns", "exec", cfg.Name, "ip", "addr", "add", cfg.IP, "dev", cfg.PeerVeth},
		{"ip", "netns", "exec", cfg.Name, "ip", "link", "set", cfg.PeerVeth, "up"},
		{"ip", "netns", "exec", cfg.Name, "ip", "link", "set", "lo", "up"},
		// Default route inside namespace
		{"ip", "netns", "exec", cfg.Name, "ip", "route", "add", "default", "via", cfg.Gateway},
	}

	for _, cmd := range commands {
		if err := run(cmd[0], cmd[1:]...); err != nil {
			// Cleanup on failure
			ns.Destroy()
			return nil, fmt.Errorf("netns setup failed at '%s': %w", strings.Join(cmd, " "), err)
		}
	}

	// Enable NAT from namespace to host network
	run("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", cfg.IP, "-j", "MASQUERADE")
	run("iptables", "-A", "FORWARD", "-i", cfg.HostVeth, "-j", "ACCEPT")
	run("iptables", "-A", "FORWARD", "-o", cfg.HostVeth, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")

	// Write resolv.conf inside namespace
	if len(cfg.DNS) > 0 {
		resolvConf := ""
		for _, dns := range cfg.DNS {
			resolvConf += "nameserver " + dns + "\n"
		}
		run("ip", "netns", "exec", cfg.Name, "bash", "-c",
			fmt.Sprintf("mkdir -p /etc/netns/%s && echo '%s' > /etc/netns/%s/resolv.conf", cfg.Name, resolvConf, cfg.Name))
	}

	ns.created = true
	log.Printf("✅ Network namespace '%s' created (IP: %s, GW: %s)", cfg.Name, cfg.IP, cfg.Gateway)
	return ns, nil
}

// Exec runs a command inside the namespace.
func (ns *Namespace) Exec(name string, args ...string) *exec.Cmd {
	fullArgs := append([]string{"netns", "exec", ns.Name, name}, args...)
	return exec.Command("ip", fullArgs...)
}

// Destroy removes the namespace and cleans up.
func (ns *Namespace) Destroy() error {
	if !ns.created {
		return nil
	}

	log.Printf("🧹 Destroying namespace '%s'", ns.Name)

	// Remove iptables rules
	run("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", ns.IP, "-j", "MASQUERADE")
	run("iptables", "-D", "FORWARD", "-i", ns.Interface, "-j", "ACCEPT")
	run("iptables", "-D", "FORWARD", "-o", ns.Interface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")

	// Delete host veth (peer is auto-deleted)
	run("ip", "link", "del", ns.Interface)

	// Delete namespace
	run("ip", "netns", "del", ns.Name)

	// Remove resolv.conf
	run("rm", "-rf", fmt.Sprintf("/etc/netns/%s", ns.Name))

	ns.created = false
	return nil
}

// List returns all bypath-managed namespaces.
func List() ([]string, error) {
	out, err := exec.Command("ip", "netns", "list").Output()
	if err != nil {
		return nil, err
	}

	var namespaces []string
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.Fields(line)
		if len(name) > 0 && strings.HasPrefix(name[0], "bypath-") {
			namespaces = append(namespaces, name[0])
		}
	}
	return namespaces, nil
}

// CleanupAll destroys all bypath-managed namespaces.
func CleanupAll() {
	nsList, err := List()
	if err != nil {
		return
	}
	for _, name := range nsList {
		ns := &Namespace{Name: name, created: true}
		ns.Destroy()
	}
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, string(output))
	}
	return nil
}
