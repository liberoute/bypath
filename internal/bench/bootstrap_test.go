package bench

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/profile"
)

func writeResolv(t *testing.T, root, name, body string) {
	t.Helper()
	etc := filepath.Join(root, "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(etc, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHostBootstrapConfigFallsBackToBackup(t *testing.T) {
	root := t.TempDir()
	writeResolv(t, root, "resolv.conf", "nameserver 127.0.0.1\n")
	writeResolv(t, root, "resolv.conf.bypath-backup", "nameserver 192.0.2.53\n")

	config, ok := hostBootstrapConfig(root)
	if !ok || !strings.Contains(config, "192.0.2.53") {
		t.Fatalf("hostBootstrapConfig = %q, %v; want backup resolver", config, ok)
	}
	if _, err := hostBootstrapResolver(root); err != nil {
		t.Fatalf("hostBootstrapResolver: %v", err)
	}
}

func TestHostBootstrapConfigPrefersPrimary(t *testing.T) {
	root := t.TempDir()
	writeResolv(t, root, "resolv.conf", "nameserver 192.0.2.1\n")
	writeResolv(t, root, "resolv.conf.bypath-backup", "nameserver 192.0.2.53\n")

	config, ok := hostBootstrapConfig(root)
	if !ok || !strings.Contains(config, "192.0.2.1") {
		t.Fatalf("hostBootstrapConfig = %q, %v; want primary resolver", config, ok)
	}
}

func TestHostBootstrapConfigRejectsGatewayOnlyResolver(t *testing.T) {
	root := t.TempDir()
	writeResolv(t, root, "resolv.conf", "nameserver 127.0.0.1\n")

	if config, ok := hostBootstrapConfig(root); ok {
		t.Fatalf("gateway-only resolver accepted: %q", config)
	}
	if _, err := hostBootstrapResolver(root); err == nil {
		t.Fatal("hostBootstrapResolver accepted a gateway-only resolver")
	}
}

func TestEndpointResolverSkipsIPLiteral(t *testing.T) {
	orig := bootstrapResolver
	t.Cleanup(func() { bootstrapResolver = orig })
	bootstrapResolver = func() (*net.Resolver, error) {
		return nil, fmt.Errorf("bootstrap must not run for an IP literal")
	}

	resolver, err := endpointResolver(&profile.Link{Address: "198.51.100.7"}, Options{})
	if err != nil || resolver != nil {
		t.Fatalf("endpointResolver(ip) = %v, %v; want nil, nil", resolver, err)
	}
}

func TestEndpointResolverUsesBootstrapForHostname(t *testing.T) {
	want := &net.Resolver{PreferGo: true}
	orig := bootstrapResolver
	t.Cleanup(func() { bootstrapResolver = orig })
	bootstrapResolver = func() (*net.Resolver, error) { return want, nil }

	resolver, err := endpointResolver(&profile.Link{Address: "example.com"}, Options{})
	if err != nil || resolver != want {
		t.Fatalf("endpointResolver(hostname) = %v, %v; want the bootstrap resolver", resolver, err)
	}

	explicit := &net.Resolver{PreferGo: true}
	resolver, err = endpointResolver(&profile.Link{Address: "example.com"}, Options{EndpointResolver: explicit})
	if err != nil || resolver != explicit {
		t.Fatalf("endpointResolver ignored the explicit resolver: %v, %v", resolver, err)
	}
}

func TestPinServerIPLiteralNeedsNoLookup(t *testing.T) {
	pinned, err := PinServer(context.Background(), "198.51.100.7", nil)
	if err != nil {
		t.Fatalf("PinServer(ip, nil): %v", err)
	}
	if pinned["198.51.100.7"] != "198.51.100.7" {
		t.Fatalf("PinServer map = %v", pinned)
	}
}

func TestPinServerHostnameWithoutLookupFails(t *testing.T) {
	if _, err := PinServer(context.Background(), "example.com", nil); err == nil {
		t.Fatal("PinServer accepted a hostname with no lookup")
	}
}

func TestPinServerPrefersIPv4(t *testing.T) {
	lookup := func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}, {IP: net.ParseIP("198.51.100.9")}}, nil
	}
	pinned, err := PinServer(context.Background(), "example.com", lookup)
	if err != nil {
		t.Fatal(err)
	}
	if pinned["example.com"] != "198.51.100.9" {
		t.Fatalf("PinServer = %v, want the IPv4 address", pinned)
	}
}
