//go:build linux

package app

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/config"
)

func dualLANFixture(t *testing.T) {
	t.Helper()
	old := config.ScanLANInterfaces
	t.Cleanup(func() { config.ScanLANInterfaces = old })
	config.ScanLANInterfaces = func() ([]config.LANInterface, error) {
		return []config.LANInterface{
			{Name: "lo", Flags: net.FlagUp | net.FlagLoopback, Addrs: []net.IPNet{{IP: net.IPv4(127, 0, 0, 1).To4(), Mask: net.CIDRMask(8, 32)}}},
			{Name: "lan0", Flags: net.FlagUp, Addrs: []net.IPNet{{IP: net.IPv4(10, 20, 30, 10).To4(), Mask: net.CIDRMask(24, 32)}}},
			{Name: "lan0.30", Flags: net.FlagUp, Addrs: []net.IPNet{{IP: net.IPv4(10, 20, 40, 2).To4(), Mask: net.CIDRMask(29, 32)}}},
			{Name: "tun0", Flags: net.FlagUp, Addrs: []net.IPNet{{IP: net.IPv4(10, 0, 0, 1).To4(), Mask: net.CIDRMask(30, 32)}}},
			{Name: "wlan0", Flags: 0},
		}, nil
	}
}

// With gateway.interface empty and two private networks present, the
// all-interface bind must be refused until an explicit, validated allow-list
// names the trusted sources.
func TestAllInterfacesApplyWithoutAllowListIsRefused(t *testing.T) {
	dualLANFixture(t)
	svc, _ := newTestLocal(t)
	_, err := svc.ApplyProxy(context.Background(), ProxyApply{
		SOCKSPort: svc.Config().Server.SOCKSPort, SOCKSListen: "0.0.0.0", ConfirmLAN: true, ConfirmAll: true,
	})
	if CodeOf(err) != CodeInvalid || !strings.Contains(err.Error(), "trusted private IPv4 LAN CIDR") {
		t.Fatalf("ambiguous LAN was not refused as expected: %v", err)
	}
}

func TestAllInterfacesApplyAcceptsExplicitAllowList(t *testing.T) {
	dualLANFixture(t)
	svc, _ := newTestLocal(t)
	svc.cfg.Server.SOCKSAllowCIDRs = []string{"10.20.30.0/24"}
	st, err := svc.Settings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(st.TrustedLANCIDRs) != 1 || st.TrustedLANCIDRs[0] != "10.20.30.0/24 via lan0" || st.TrustedLANIP != "10.20.30.10" {
		t.Fatalf("settings do not expose the host allow-list: %+v", st)
	}
	_, err = svc.ApplyProxy(context.Background(), ProxyApply{
		SOCKSPort: svc.Config().Server.SOCKSPort, SOCKSListen: "0.0.0.0", ConfirmLAN: true, ConfirmAll: true,
	})
	if CodeOf(err) == CodeInvalid {
		t.Fatalf("validated allow-list was still rejected: %v", err)
	}
}
