package config

import (
	"net"
	"testing"
)

func TestProxyReservedPortsAndRange(t *testing.T) {
	for _, port := range []int{-1, 0, 65536, 22, 53, 80, 443, 8443, 9090, 9091, 5353} {
		s := ServerConfig{SOCKSPort: port, APIPort: 9090, DNSPort: 5353, Web: WebConfig{Port: 9091}}
		if err := ValidateProxyPort(s); err == nil {
			t.Fatalf("port %d accepted", port)
		}
	}
	for _, port := range []int{1, 1080, 65535} {
		if err := ValidateProxyPort(ServerConfig{SOCKSPort: port}); err != nil {
			t.Fatalf("valid port %d: %v", port, err)
		}
	}
}
func TestManagementExposureRequiresToken(t *testing.T) {
	s := ServerConfig{Listen: "0.0.0.0", SOCKSPort: 2801}
	if err := ValidateServer(s); err == nil {
		t.Fatal("unauthenticated management exposure accepted")
	}
	s.APIToken = "token"
	if err := ValidateServer(s); err != nil {
		t.Fatal(err)
	}
}
func TestSpecificLANEndpointRetainsLoopback(t *testing.T) {
	got := ProxyEndpoints(ServerConfig{SOCKSListen: "192.168.10.2", SOCKSPort: 1080})
	if len(got) != 2 || got[0] != "192.168.10.2:1080" || got[1] != "127.0.0.1:1080" {
		t.Fatal(got)
	}
	for _, host := range []string{"0.0.0.0", "127.0.0.1"} {
		if len(ProxyEndpoints(ServerConfig{SOCKSListen: host, SOCKSPort: 1080})) != 1 {
			t.Fatal("duplicate loopback bind")
		}
	}
}

// dualLANInterfaces is a two-network host layout: an office LAN on lan0, a
// tagged secondary VLAN on lan0.30, the tun device and a down wlan.
func dualLANInterfaces() []LANInterface {
	return []LANInterface{
		{Name: "lo", Flags: net.FlagUp | net.FlagLoopback, Addrs: []net.IPNet{{IP: net.IPv4(127, 0, 0, 1).To4(), Mask: net.CIDRMask(8, 32)}}},
		{Name: "lan0", Flags: net.FlagUp, Addrs: []net.IPNet{{IP: net.IPv4(10, 20, 30, 10).To4(), Mask: net.CIDRMask(24, 32)}}},
		{Name: "lan0.30", Flags: net.FlagUp, Addrs: []net.IPNet{{IP: net.IPv4(10, 20, 40, 2).To4(), Mask: net.CIDRMask(29, 32)}}},
		{Name: "tun0", Flags: net.FlagUp, Addrs: []net.IPNet{{IP: net.IPv4(10, 0, 0, 1).To4(), Mask: net.CIDRMask(30, 32)}}},
		{Name: "wlan0", Flags: 0, Addrs: nil},
	}
}

func withDualLANInterfaces(t *testing.T) {
	t.Helper()
	old := ScanLANInterfaces
	t.Cleanup(func() { ScanLANInterfaces = old })
	ScanLANInterfaces = func() ([]LANInterface, error) { return dualLANInterfaces(), nil }
}

func TestAmbiguousLANFailsClosed(t *testing.T) {
	withDualLANInterfaces(t)
	if _, err := TrustedLANs("", nil); err == nil {
		t.Fatal("two private networks were silently resolved to one")
	}
}

func TestNamedInterfaceDerivesLAN(t *testing.T) {
	withDualLANInterfaces(t)
	got, err := TrustedLANs("lan0", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].IP != "10.20.30.10" || got[0].CIDR != "10.20.30.0/24" || got[0].Interface != "lan0" {
		t.Fatalf("%+v", got)
	}
	if _, err := TrustedLANs("lan0.30", nil); err != nil {
		t.Fatal("secondary VLAN interface was refused", err)
	}
}

func TestExplicitAllowList(t *testing.T) {
	withDualLANInterfaces(t)
	got, err := TrustedLANs("", []string{"10.20.30.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].IP != "10.20.30.10" || got[0].Interface != "lan0" {
		t.Fatalf("%+v", got)
	}
	got, err = TrustedLANs("", []string{"10.20.30.0/24", "10.20.40.1/32"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 ||
		got[0].CIDR != "10.20.30.0/24" || got[0].Interface != "lan0" ||
		got[1].CIDR != "10.20.40.1/32" || got[1].Interface != "lan0.30" || got[1].IP != "10.20.40.2" {
		t.Fatalf("%+v", got)
	}
	if dedup, err := TrustedLANs("", []string{"10.20.30.0/24", " 10.20.30.0/24 "}); err != nil || len(dedup) != 1 {
		t.Fatalf("duplicate entry not collapsed: %+v %v", dedup, err)
	}
}

func TestExplicitAllowListRejectsUntrusted(t *testing.T) {
	withDualLANInterfaces(t)
	for _, cidr := range []string{
		"192.168.50.0/24",  // not owned by any interface
		"10.20.40.0/24",  // supernet of the on-link /29
		"8.8.8.8/32",       // public
		"10.20.30.10/8",  // prefix outside the accepted range
		"10.0.0.0/30",      // tun device, never a LAN trust anchor
		"10.20.30.10",    // not a CIDR
		"fd00::/64",        // IPv6
		"0.0.0.0/0",        // default route
	} {
		if _, err := TrustedLANs("", []string{cidr}); err == nil {
			t.Fatalf("untrusted allow-list entry %q accepted", cidr)
		}
	}
}

func TestTrustedLANFailsClosedOnUnknownInterface(t *testing.T) {
	withDualLANInterfaces(t)
	if _, err := TrustedLANs("no-such-interface-bypath", nil); err == nil {
		t.Fatal("unowned LAN accepted")
	}
}

func TestSocksTrustedCIDRsValidatedAtLoad(t *testing.T) {
	base := ServerConfig{SOCKSPort: 2801, SOCKSListen: "0.0.0.0", SOCKSAllowLAN: true}
	base.SOCKSAllowCIDRs = []string{"10.20.30.0/24"}
	if err := ValidateServer(base); err != nil {
		t.Fatal(err)
	}
	for _, cidr := range []string{"8.8.8.8/32", "10.20.30.0/8", "not-a-cidr", "0.0.0.0/0"} {
		s := base
		s.SOCKSAllowCIDRs = []string{cidr}
		if err := ValidateServer(s); err == nil {
			t.Fatalf("invalid allow-list entry %q accepted", cidr)
		}
	}
}
