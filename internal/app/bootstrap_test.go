package app

import (
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/config"
)

func TestTestBootstrapResolverDefaultsToHost(t *testing.T) {
	resolver, label := testBootstrapResolver(nil)
	if resolver != nil || label != "host" {
		t.Fatalf("nil config = %v, %q; want nil, host", resolver, label)
	}
	resolver, label = testBootstrapResolver(&config.Config{})
	if resolver != nil || label != "host" {
		t.Fatalf("empty list = %v, %q; want nil, host", resolver, label)
	}
}

func TestTestBootstrapResolverUsesConfiguredLAN(t *testing.T) {
	cfg := &config.Config{}
	cfg.Tests.BootstrapDNS = []string{"172.16.11.1", "192.168.1.53:5353"}
	resolver, label := testBootstrapResolver(cfg)
	if resolver == nil {
		t.Fatal("configured bootstrap produced no resolver")
	}
	if label != "lan:172.16.11.1,192.168.1.53:5353" {
		t.Fatalf("label = %q", label)
	}
}

func TestCategoryDetailCoversSeparatedStages(t *testing.T) {
	for _, category := range []string{CategoryDNSBootstrap, CategoryTCP, CategoryHandshake, CategoryHTTPS} {
		if strings.TrimSpace(categoryDetail[category]) == "" {
			t.Fatalf("no explanation for %q", category)
		}
	}
	if CategoryDNSBootstrap == CategoryTCP || CategoryTCP == CategoryHTTPS {
		t.Fatal("stage categories must stay distinct")
	}
}
