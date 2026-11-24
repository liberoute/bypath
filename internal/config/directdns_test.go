package config

import (
	"strings"
	"testing"
)

// TestValidateDirectDNS keeps gateway.direct_dns to endpoints that resolve
// without the tunnel and never disclose queries in plaintext over HTTP.
func TestValidateDirectDNS(t *testing.T) {
	good := []string{
		"",
		"1.1.1.1",
		"192.0.2.53:5353",
		"2001:db8::1",
		"[2001:db8::1]:5353",
		"https://1.1.1.1/dns-query",
		"https://[2001:db8::1]/dns-query",
	}
	for _, raw := range good {
		cfg := &Config{}
		cfg.Gateway.DirectDNS = raw
		if err := validateDirectDNS(cfg); err != nil {
			t.Errorf("direct_dns %q rejected: %v", raw, err)
		}
	}

	bad := []string{
		"dns.example.com",
		"http://1.1.1.1/dns-query",
		"https://dns.example.com/dns-query",
		"1.1.1.1 53",
		"https://",
		"https://1.1.1.1:notaport/dns-query",
	}
	for _, raw := range bad {
		cfg := &Config{}
		cfg.Gateway.DirectDNS = raw
		err := validateDirectDNS(cfg)
		if err == nil {
			t.Errorf("direct_dns %q accepted", raw)
			continue
		}
		if !strings.Contains(err.Error(), "gateway.direct_dns") {
			t.Errorf("direct_dns %q error does not name the field: %v", raw, err)
		}
	}
}

// TestDirectDNSRoundTrip proves the field survives YAML load, where the
// gateway's DNS policy is configured.
func TestDirectDNSRoundTrip(t *testing.T) {
	cfg, err := Parse([]byte("gateway:\n  enabled: true\n  direct_dns: \"192.0.2.53\"\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := cfg.NormalizeAndValidate(); err != nil {
		t.Fatalf("NormalizeAndValidate: %v", err)
	}
	if cfg.Gateway.DirectDNS != "192.0.2.53" {
		t.Fatalf("direct_dns = %q", cfg.Gateway.DirectDNS)
	}
}
