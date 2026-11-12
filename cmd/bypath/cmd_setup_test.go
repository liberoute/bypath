package main

import (
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/config"
)

func TestRedactConfigYAML(t *testing.T) {
	in := "server:\n  api_token: \"secret-value\"\n  api_port: 8080\n"
	out := redactConfigYAML(in)
	if strings.Contains(out, "secret-value") {
		t.Fatalf("token leaked into dry-run output: %q", out)
	}
	if !strings.Contains(out, "api_port: 8080") {
		t.Fatalf("unrelated fields must survive: %q", out)
	}
}

func TestApplyAnswersKeepsGatewayOffUnlessAsked(t *testing.T) {
	cfg, err := config.Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	ans := &answers{
		gatewayMode: false,
		listenAddr:  "127.0.0.1",
		socksPort:   2801,
		webEnabled:  true,
		webListen:   "127.0.0.1",
		webPort:     8081,
		group:       "default",
	}
	if err := applyAnswers(cfg, ans); err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway.Enabled {
		t.Fatal("proxy-only setup must not enable the gateway")
	}
	if cfg.Server.SOCKSAllowLAN || len(cfg.Server.SOCKSAllowCIDRs) != 0 {
		t.Fatal("loopback setup must not trust a LAN")
	}
	if cfg.Server.Web.Enabled != true || cfg.Server.Web.AllowLAN {
		t.Fatalf("panel should be enabled on loopback only: %+v", cfg.Server.Web)
	}
	if len(cfg.Routing.Rules) != 1 || cfg.Routing.Rules[0].Match != "default" || cfg.Routing.Rules[0].Outbound != "proxy" {
		t.Fatalf("fresh routing must be a single tunnel catch-all: %+v", cfg.Routing.Rules)
	}
}

func TestApplyAnswersEnablesGatewayOnlyWhenRequested(t *testing.T) {
	cfg, err := config.Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	ans := &answers{
		gatewayMode: true,
		enableNow:   true,
		iface:       "lan0",
		listenAddr:  "127.0.0.1",
		socksPort:   2801,
		dnsPort:     5335,
		upstreams:   []string{"1.1.1.1"},
		webListen:   "127.0.0.1",
		group:       "default",
	}
	if err := applyAnswers(cfg, ans); err != nil {
		t.Fatal(err)
	}
	if !cfg.Gateway.Enabled || cfg.Gateway.Interface != "lan0" || cfg.Server.DNSPort != 5335 {
		t.Fatalf("gateway answers not applied: %+v", cfg.Gateway)
	}
	if cfg.Gateway.DNSMode != "strict" || !cfg.Gateway.NativeTUN {
		t.Fatalf("gateway must default to strict DNS and native TUN: %+v", cfg.Gateway)
	}
}

func TestGatewayActivationRequiresConnection(t *testing.T) {
	cfg, err := config.Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Profiles.Directory = t.TempDir()
	ans := &answers{gatewayMode: true, enableNow: true}
	if !gatewayNeedsConnection(ans, cfg) {
		t.Fatal("activating a gateway with no connection must be refused")
	}
	ans.uris = []string{"vless://example"}
	if gatewayNeedsConnection(ans, cfg) {
		t.Fatal("an imported connection must satisfy the activation guard")
	}
	ans.uris = nil
	ans.enableNow = false
	if gatewayNeedsConnection(ans, cfg) {
		t.Fatal("a staged gateway is allowed without a connection")
	}
}

func TestApplyAnswersDefersGatewayActivation(t *testing.T) {
	cfg, err := config.Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	ans := &answers{
		gatewayMode:     true,
		enableNow:       true,
		deferActivation: true,
		iface:           "lan0",
		listenAddr:      "127.0.0.1",
		socksPort:       2801,
		dnsPort:         5335,
		upstreams:       []string{"1.1.1.1"},
		webListen:       "127.0.0.1",
		group:           "default",
	}
	if err := applyAnswers(cfg, ans); err != nil {
		t.Fatal(err)
	}
	if cfg.Gateway.Enabled {
		t.Fatal("a deferred activation must not write gateway.enabled: true")
	}
}
