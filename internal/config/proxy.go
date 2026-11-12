package config

import (
	"fmt"
	"net"
	"strings"
)

type LANNetwork struct {
	IP        string
	CIDR      string
	Interface string
}

// LANInterface is one up, non-loopback interface with its IPv4 networks.
type LANInterface struct {
	Name  string
	Flags net.Flags
	Addrs []net.IPNet
}

// ScanLANInterfaces is the live interface source; tests replace it to exercise
// a specific host layout.
var ScanLANInterfaces = func() ([]LANInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]LANInterface, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		var networks []net.IPNet
		for _, addr := range addrs {
			ip, network, err := net.ParseCIDR(addr.String())
			if err != nil || ip.To4() == nil {
				continue
			}
			networks = append(networks, net.IPNet{IP: ip.To4(), Mask: network.Mask})
		}
		out = append(out, LANInterface{Name: iface.Name, Flags: iface.Flags, Addrs: networks})
	}
	return out, nil
}

func lanEligible(iface LANInterface) bool {
	if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
		return false
	}
	for _, prefix := range []string{"tun", "docker", "veth", "br-"} {
		if strings.HasPrefix(iface.Name, prefix) {
			return false
		}
	}
	return true
}

// TrustedLANs returns the narrow source allowlist for a LAN proxy listener.
// Without an explicit interface the derived network must be unambiguous;
// server.socks_trusted_cidrs names the allowlist when the host owns more than
// one LAN. Every explicit entry must be a private IPv4 subnet of an up,
// non-loopback interface, so a reachable-but-unowned network is never trusted.
func TrustedLANs(ifaceName string, explicit []string) ([]LANNetwork, error) {
	all, err := ScanLANInterfaces()
	if err != nil {
		return nil, err
	}
	var lans []LANInterface
	for _, iface := range all {
		if !lanEligible(iface) {
			continue
		}
		if ifaceName != "" && iface.Name != ifaceName {
			continue
		}
		lans = append(lans, iface)
	}
	if ifaceName != "" && len(lans) == 0 {
		return nil, fmt.Errorf("gateway.interface %q is not an up non-loopback interface", ifaceName)
	}
	if len(explicit) == 0 {
		var candidates []LANNetwork
		for _, iface := range lans {
			for _, addr := range iface.Addrs {
				ones, bits := addr.Mask.Size()
				if bits != 32 || ones < 16 || ones > 30 || !addr.IP.IsPrivate() {
					continue
				}
				network := &net.IPNet{IP: addr.IP.Mask(addr.Mask), Mask: addr.Mask}
				candidates = append(candidates, LANNetwork{IP: addr.IP.String(), CIDR: network.String(), Interface: iface.Name})
			}
		}
		if len(candidates) != 1 {
			return nil, fmt.Errorf("cannot derive one trusted private IPv4 LAN CIDR; set gateway.interface to the trusted LAN interface or list them in server.socks_trusted_cidrs")
		}
		return candidates, nil
	}
	out := make([]LANNetwork, 0, len(explicit))
	seen := make(map[string]bool, len(explicit))
	for _, raw := range explicit {
		_, network, err := parseTrustedCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("server.socks_trusted_cidrs entry %q %v", strings.TrimSpace(raw), err)
		}
		entry, err := matchOwnedSubnet(lans, network)
		if err != nil {
			return nil, fmt.Errorf("server.socks_trusted_cidrs entry %q %v", strings.TrimSpace(raw), err)
		}
		key := entry.Interface + " " + entry.CIDR
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, entry)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("server.socks_trusted_cidrs is empty")
	}
	return out, nil
}

func parseTrustedCIDR(raw string) (net.IP, *net.IPNet, error) {
	ip, network, err := net.ParseCIDR(strings.TrimSpace(raw))
	if err != nil || ip.To4() == nil {
		return nil, nil, fmt.Errorf("must be an IPv4 CIDR")
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones < 16 || ones > 32 {
		return nil, nil, fmt.Errorf("prefix must be between /16 and /32")
	}
	if !network.IP.IsPrivate() {
		return nil, nil, fmt.Errorf("must be a private IPv4 range")
	}
	return ip, network, nil
}

func matchOwnedSubnet(lans []LANInterface, network *net.IPNet) (LANNetwork, error) {
	ones, bits := network.Mask.Size()
	for _, iface := range lans {
		for _, addr := range iface.Addrs {
			ifaceOnes, ifaceBits := addr.Mask.Size()
			// The allow-list may name a subnet of the interface's own network, never
			// a supernet of it: 10.20.40.0/24 is not on-link just because the
			// interface carries a /29 inside it.
			if ifaceBits != bits || ifaceOnes > ones || !addr.Contains(network.IP) {
				continue
			}
			return LANNetwork{IP: addr.IP.String(), CIDR: network.String(), Interface: iface.Name}, nil
		}
	}
	return LANNetwork{}, fmt.Errorf("is not a subnet of an up non-loopback interface")
}

func ValidateProxyPort(s ServerConfig) error {
	if s.SOCKSPort < 1 || s.SOCKSPort > 65535 {
		return fmt.Errorf("server.socks_port must be in 1..65535")
	}
	reserved := []int{22, 53, 80, 443, 8443, s.DNSPort, s.APIPort, s.Web.Port}
	for _, port := range reserved {
		if s.SOCKSPort == port {
			return fmt.Errorf("server.socks_port %d is reserved for host management or DNS", port)
		}
	}
	return nil
}
func ProxyEndpoints(s ServerConfig) []string {
	addr := s.SOCKSListenAddress()
	out := []string{net.JoinHostPort(addr, fmt.Sprint(s.SOCKSPort))}
	if addr != "127.0.0.1" && addr != "0.0.0.0" {
		out = append(out, net.JoinHostPort("127.0.0.1", fmt.Sprint(s.SOCKSPort)))
	}
	return out
}
