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

// fakeDNS answers every A question with one fixed address. It exists to prove
// the configured bootstrap reaches the exact server it names.
func fakeDNS(t *testing.T, answer net.IP) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			req := append([]byte(nil), buf[:n]...)
			if len(req) < 12 {
				continue
			}
			resp := append([]byte(nil), req...)
			resp[2], resp[3] = 0x81, 0x80 // response, recursion available
			resp[6], resp[7] = 0, 1       // one answer
			resp[8], resp[9] = 0, 0       // no authority records
			resp[10], resp[11] = 0, 0     // no additional records
			resp = resp[:12]
			offset := 12
			for offset < len(req) && req[offset] != 0 {
				offset += int(req[offset]) + 1
			}
			if offset+5 > len(req) {
				continue
			}
			question := req[12 : offset+5]
			resp = append(resp, question...)
			resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
			resp = append(resp, answer.To4()...)
			pc.WriteTo(resp, addr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestResolverFromServersQueriesTheConfiguredServer(t *testing.T) {
	server := fakeDNS(t, net.IPv4(203, 0, 113, 9))
	resolver, err := ResolverFromServers([]string{server})
	if err != nil {
		t.Fatal(err)
	}
	addrs, err := resolver.LookupIPAddr(context.Background(), "pinned.example")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(addrs) != 1 || addrs[0].IP.String() != "203.0.113.9" {
		t.Fatalf("lookup = %v, want the fake answer", addrs)
	}
}

func TestResolverFromServersRejectsUnusableEntries(t *testing.T) {
	for _, entry := range []string{"", "dns.lan", "0.0.0.0", "1.2.3.4:0"} {
		if _, err := ResolverFromServers([]string{entry}); err == nil {
			t.Fatalf("entry %q accepted", entry)
		}
	}
	if _, err := ResolverFromServers(nil); err == nil {
		t.Fatal("an empty server list was accepted")
	}
}

func TestPinServerBootstrapFailureIsItsOwnCategory(t *testing.T) {
	if _, err := PinServer(context.Background(), "pinned.example", func(context.Context, string) ([]net.IPAddr, error) {
		return nil, fmt.Errorf("no answer")
	}); err == nil {
		t.Fatal("PinServer accepted a failing lookup")
	}
	resolver, err := ResolverFromServers([]string{"127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	link := &profile.Link{Protocol: "vless", Address: "pinned.example", Port: 443, Security: "none"}
	_, err = Open(context.Background(), link, Options{EndpointResolver: resolver, TmpDir: t.TempDir()})
	if got := categoryOf(err); got != CategoryDNSBootstrap {
		t.Fatalf("category = %q (%v), want %q", got, err, CategoryDNSBootstrap)
	}
}
