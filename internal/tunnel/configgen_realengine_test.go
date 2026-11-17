//go:build full

package tunnel

import (
	"context"
	"net"
	"os"
	"sync"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singJSON "github.com/sagernet/sing/common/json"

	xray "github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
)

// These tests load generated configurations into the engines themselves, with
// the same constructors internal/engine uses. A generator that emits a field
// the pinned engine does not accept, or a rule_set/geoip reference the running
// engine cannot satisfy, fails here instead of at a gateway start.
//
// sing-box is validated with box.New and not started: every inbound, outbound,
// DNS transport and local rule set is constructed, including the TUN inbound's
// option checks, but no listener or interface is opened. xray has no
// construct-without-start entry point, so it is started on a free loopback port
// and closed immediately.

var singBoxTestContext = sync.OnceValue(func() context.Context {
	return include.Context(context.Background())
})

func validateSingBoxFile(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := singBoxTestContext()
	var opts option.Options
	if err := singJSON.UnmarshalContext(ctx, data, &opts); err != nil {
		t.Fatalf("sing-box rejected the config: %v", err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatalf("sing-box rejected the config: %v", err)
	}
	if err := instance.Close(); err != nil {
		t.Fatalf("sing-box close: %v", err)
	}
}

func validateSingBox(t *testing.T, cg *ConfigGenerator) {
	t.Helper()
	path, err := cg.Generate(&engine.Engine{Name: "sing-box"}, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	validateSingBoxFile(t, path)
}

// freePort returns a loopback port xray can bind for both TCP and UDP. The UDP
// probe matters on Windows: WinNAT reserves UDP ranges that the TCP ephemeral
// allocator still hands out, and xray's SOCKS inbound binds UDP on the same port.
func freePort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 50; i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
		_ = listener.Close()
		if err != nil {
			continue
		}
		_ = udp.Close()
		return port
	}
	t.Fatal("no loopback port bindable as both TCP and UDP")
	return 0
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

func validateXray(t *testing.T, cg *ConfigGenerator) {
	t.Helper()
	cg.SOCKSPort = freePort(t)
	path, err := cg.Generate(&engine.Engine{Name: "xray"}, testVlessLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// xray resolves geoip:/geosite: references from this directory.
	t.Setenv("xray.location.asset", paths.Get().GeoDir)
	instance, err := xray.StartInstance("json", data)
	if err != nil {
		t.Fatalf("xray rejected the config: %v", err)
	}
	if err := instance.Close(); err != nil {
		t.Fatalf("xray close: %v", err)
	}
}

// TestRealEngineSingBox_ProxyOnlyDefault is the shipped default: no routing
// rules, no lists, no split.
func TestRealEngineSingBox_ProxyOnlyDefault(t *testing.T) {
	validateSingBox(t, NewConfigGenerator(t.TempDir()))
}

// TestRealEngineSingBox_AllMatcherKinds loads a rules configuration that uses
// every matcher family the panel offers, including both geo databases.
func TestRealEngineSingBox_AllMatcherKinds(t *testing.T) {
	writeValidGeoRuleSet(t, "geoip", "de")
	writeValidGeoRuleSet(t, "geosite", "de")

	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain:exact.example", Outbound: "direct"},
		{Match: "domain_suffix:corp.example", Outbound: "direct"},
		{Match: "ip_cidr:198.51.100.0/24", Outbound: "direct"},
		{Match: "geoip:de", Outbound: "direct"},
		{Match: "geosite:de", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
	validateSingBox(t, cg)
}

// TestRealEngineSingBox_CountrySplit covers the rule_sets, the resolve actions
// and the DNS rules the split adds.
func TestRealEngineSingBox_CountrySplit(t *testing.T) {
	writeValidGeoRuleSet(t, "geosite", "ir")
	writeValidGeoRuleSet(t, "geoip", "ir")

	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:internal.example", Outbound: "proxy"},
		{Match: "default", Outbound: "proxy"},
	}
	cg.CountrySplit = "ir"
	validateSingBox(t, cg)
}

// TestRealEngineSingBox_GatewayMode loads the TUN inbound and the DNS listener
// configuration the gateway uses.
func TestRealEngineSingBox_GatewayMode(t *testing.T) {
	writeValidGeoRuleSet(t, "geosite", "ir")
	writeValidGeoRuleSet(t, "geoip", "ir")

	cg := NewConfigGenerator(t.TempDir())
	cg.GatewayMode = true
	cg.DNSPort = freePort(t)
	cg.CountrySplit = "ir"
	validateSingBox(t, cg)
}

// TestRealEngineSingBox_LocalDNS covers the local DNS server rules and the
// DIRECT routing they imply.
func TestRealEngineSingBox_LocalDNS(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.LocalDNSRules = []LocalDNSRule{{Server: "192.0.2.53", Domains: []string{"home", "lan"}}}
	validateSingBox(t, cg)
}

// TestRealEngineSingBox_FailClosedAssets proves the missing-asset path still
// loads: an unusable category must drop the rule and leave no dangling
// rule_set definition, which the engine would reject.
func TestRealEngineSingBox_FailClosedAssets(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "geosite:zz", Outbound: "direct"},
		{Match: "geoip:zz", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
	cg.CountrySplit = "qq"
	validateSingBox(t, cg)
}

// TestRealEngineSingBox_Chain loads a two-hop chain config, whose route and DNS
// are built from the same plan with the exit hop in the proxy role.
func TestRealEngineSingBox_Chain(t *testing.T) {
	entry := &profile.Link{
		Protocol: "vless", Address: "entry.example.com", Port: 443,
		UUID: "11111111-1111-1111-1111-111111111111", TLS: true, SNI: "entry.example.com",
	}
	exit := &profile.Link{
		Protocol: "trojan", Address: "exit.example.com", Port: 443,
		UUID: "exit-password", TLS: true, SNI: "exit.example.com",
	}
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:corp.example", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
	path, err := cg.GenerateChainConfig("chain-a", []*profile.Link{entry, exit})
	if err != nil {
		t.Fatalf("GenerateChainConfig: %v", err)
	}
	validateSingBoxFile(t, path)
}

// TestRealEngineXray_RulesWithGeoAssets loads the xray route with the geo
// databases and the pinned resolver rule. xray aborts instance startup when a
// rule names a category its .dat files do not carry, so this also proves the
// gates agree with the deployed assets.
func TestRealEngineXray_RulesWithGeoAssets(t *testing.T) {
	writeXrayGeoDat(t, "geoip.dat", []string{"IR"})
	writeXrayGeoDat(t, "geosite.dat", []string{"CATEGORY-IR", "CATEGORY-DE"})

	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{
		{Match: "geosite:de", Outbound: "direct"},
		{Match: "domain_suffix:corp.example", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
	validateXray(t, cg)
}

// TestRealEngineXray_SplitRefused pins the engine gate rather than a generated
// config: xray cannot route the split's resolver through the tunnel, so no
// config may exist for that policy.
func TestRealEngineXray_SplitRefused(t *testing.T) {
	writeXrayGeoDat(t, "geoip.dat", []string{"IR"})
	writeXrayGeoDat(t, "geosite.dat", []string{"CATEGORY-IR"})

	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{{Match: "default", Outbound: "proxy"}}
	cg.CountrySplit = "ir"
	if _, err := cg.Generate(&engine.Engine{Name: "xray"}, testVlessLink()); err == nil {
		t.Fatal("xray generated a config for the country split")
	}
}

// TestRealEngineXray_ProxyOnlyDefault is the shipped default on the fallback
// engine: no routing section is emitted at all.
func TestRealEngineXray_ProxyOnlyDefault(t *testing.T) {
	validateXray(t, NewConfigGenerator(t.TempDir()))
}

// TestRealEngineXray_DirectFinal keeps the default-outbound path loadable: with
// a direct final the generator emits an all-addresses rule, which xray must
// accept. The condition is evaluated in the second IPIfNonMatch pass.
func TestRealEngineXray_DirectFinal(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.RoutingRules = []RoutingRule{{Match: "default", Outbound: "direct"}}
	validateXray(t, cg)
}

// TestRealEngineSingBox_ProbeInboundScoped loads the daemon probe inbound and
// its two scoped rules into the pinned engine, so an unsupported rule field
// fails here instead of at gateway start.
func TestRealEngineSingBox_ProbeInboundScoped(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	// box.New constructs inbounds without binding them, so a TCP port is enough.
	cg.ProbePort = freeTCPPort(t)
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:example.com", Outbound: "block"},
		{Match: "default", Outbound: "direct"},
	}
	validateSingBox(t, cg)
}

// TestRealEngineXray_ProbeInboundScoped covers the tagged probe inbound and the
// inboundTag-scoped proxy/blackhole rules xray has to accept.
func TestRealEngineXray_ProbeInboundScoped(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.ProbePort = freePort(t)
	cg.RoutingRules = []RoutingRule{
		{Match: "domain_suffix:example.com", Outbound: "block"},
		{Match: "default", Outbound: "direct"},
	}
	validateXray(t, cg)
}
