package config

import (
	"strings"
	"testing"
)

func validateBootstrap(t *testing.T, entries ...string) error {
	t.Helper()
	cfg, err := Parse([]byte("server:\n  listen: 127.0.0.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Tests.BootstrapDNS = entries
	return cfg.NormalizeAndValidate()
}

func TestBootstrapDNSAcceptsLANResolvers(t *testing.T) {
	for _, entry := range []string{"172.16.11.1", "192.168.1.1:5353", "10.0.0.53", "fd00::53", "[fd00::53]:53"} {
		if err := validateBootstrap(t, entry); err != nil {
			t.Fatalf("entry %q rejected: %v", entry, err)
		}
	}
}

func TestBootstrapDNSRejectsLoopback(t *testing.T) {
	for _, entry := range []string{"127.0.0.1", "127.0.0.53:53", "::1", "[::1]:53"} {
		err := validateBootstrap(t, entry)
		if err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Fatalf("entry %q: got %v, want a loopback rejection", entry, err)
		}
	}
}

func TestBootstrapDNSRejectsPublicAndUnspecified(t *testing.T) {
	for _, entry := range []string{"8.8.8.8", "1.1.1.1:53", "0.0.0.0", "2606:4700:4700::1111"} {
		if err := validateBootstrap(t, entry); err == nil {
			t.Fatalf("entry %q accepted, want a private-LAN rejection", entry)
		}
	}
}

func TestBootstrapDNSRejectsNamesAndBadPorts(t *testing.T) {
	for _, entry := range []string{"dns.lan", "172.16.11.1:0", "172.16.11.1:70000", "172.16.11.1:abc", "", "172.16.11.1 53"} {
		if err := validateBootstrap(t, entry); err == nil {
			t.Fatalf("entry %q accepted, want a rejection", entry)
		}
	}
}

func TestBootstrapDNSRejectsDuplicatesAndTooMany(t *testing.T) {
	if err := validateBootstrap(t, "172.16.11.1", "172.16.11.1:53"); err == nil {
		t.Fatal("the same resolver listed twice was accepted")
	}
	if err := validateBootstrap(t, "172.16.11.1", "172.16.11.2", "172.16.11.3", "172.16.11.4", "172.16.11.5"); err == nil {
		t.Fatal("five resolvers were accepted")
	}
}

func TestBootstrapDNSEmptyKeepsHostBehaviour(t *testing.T) {
	if err := validateBootstrap(t); err != nil {
		t.Fatalf("an empty list must keep the host bootstrap: %v", err)
	}
}
