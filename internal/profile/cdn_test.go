package profile

import (
	"testing"

	"pgregory.net/rapid"
)

// Feature: cdn-https-detection, Property 4: CDN classification requires all four conditions
//
// For any Link, IsCDNPattern returns true if and only if:
// port == 443 AND network == "ws" AND TLS == true AND host != "" AND host != address AND security != "reality"
//
// **Validates: Requirements 1.1, 1.2**
func TestProperty4_CDNClassificationRequiresAllConditions(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := rapid.StringMatching(`[a-z0-9]{1,20}\.[a-z]{2,5}`).Draw(t, "address")

		// Generate a host that may or may not equal address
		host := rapid.OneOf(
			rapid.Just(""),                                                    // empty host
			rapid.Just(address),                                               // host == address
			rapid.StringMatching(`[a-z0-9]{1,20}\.[a-z]{2,5}`).Filter(func(s string) bool { return s != "" && s != address }), // host != address
		).Draw(t, "host")

		port := rapid.OneOf(
			rapid.Just(443),
			rapid.IntRange(1, 65535),
		).Draw(t, "port")

		network := rapid.SampledFrom([]string{"ws", "tcp", "grpc", "h2", "quic"}).Draw(t, "network")
		tls := rapid.Bool().Draw(t, "tls")
		security := rapid.SampledFrom([]string{"", "reality", "tls", "none"}).Draw(t, "security")

		link := &Link{
			Address:  address,
			Host:     host,
			Port:     port,
			Network:  network,
			TLS:      tls,
			Security: security,
		}

		got := IsCDNPattern(link)

		// Expected: all conditions must hold simultaneously
		expected := port == 443 &&
			network == "ws" &&
			tls == true &&
			host != "" &&
			host != address &&
			security != "reality"

		if got != expected {
			t.Fatalf("IsCDNPattern mismatch: got %v, expected %v for link: port=%d, network=%q, tls=%v, host=%q, address=%q, security=%q",
				got, expected, port, network, tls, host, address, security)
		}
	})
}

// Feature: cdn-https-detection, Property 2: Reality links are never classified as CDN
//
// For any Link with Security == "reality", IsCDNPattern returns false regardless of other fields.
//
// **Validates: Requirements 1.3**
func TestProperty2_RealityLinksNeverCDN(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := rapid.StringMatching(`[a-z0-9]{1,20}\.[a-z]{2,5}`).Draw(t, "address")

		// Generate a host that would otherwise satisfy CDN conditions
		host := rapid.StringMatching(`[a-z0-9]{1,20}\.[a-z]{2,5}`).Filter(func(s string) bool {
			return s != "" && s != address
		}).Draw(t, "host")

		port := rapid.OneOf(
			rapid.Just(443),
			rapid.IntRange(1, 65535),
		).Draw(t, "port")

		network := rapid.SampledFrom([]string{"ws", "tcp", "grpc", "h2", "quic"}).Draw(t, "network")
		tls := rapid.Bool().Draw(t, "tls")

		link := &Link{
			Address:  address,
			Host:     host,
			Port:     port,
			Network:  network,
			TLS:      tls,
			Security: "reality", // Always reality
		}

		got := IsCDNPattern(link)
		if got {
			t.Fatalf("IsCDNPattern should return false for reality links, got true for: port=%d, network=%q, tls=%v, host=%q, address=%q",
				port, network, tls, host, address)
		}
	})
}

// Feature: cdn-https-detection, Property 3: Non-WebSocket links are never classified as CDN
//
// For any Link with Network != "ws", IsCDNPattern returns false regardless of other fields.
//
// **Validates: Requirements 1.4**
func TestProperty3_NonWebSocketNeverCDN(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		address := rapid.StringMatching(`[a-z0-9]{1,20}\.[a-z]{2,5}`).Draw(t, "address")

		// Generate a host that would otherwise satisfy CDN conditions
		host := rapid.StringMatching(`[a-z0-9]{1,20}\.[a-z]{2,5}`).Filter(func(s string) bool {
			return s != "" && s != address
		}).Draw(t, "host")

		port := rapid.OneOf(
			rapid.Just(443),
			rapid.IntRange(1, 65535),
		).Draw(t, "port")

		// Network is anything except "ws"
		network := rapid.SampledFrom([]string{"tcp", "grpc", "h2", "quic", "kcp"}).Draw(t, "network")
		tls := rapid.Bool().Draw(t, "tls")
		security := rapid.SampledFrom([]string{"", "tls", "none"}).Draw(t, "security")

		link := &Link{
			Address:  address,
			Host:     host,
			Port:     port,
			Network:  network,
			TLS:      tls,
			Security: security,
		}

		got := IsCDNPattern(link)
		if got {
			t.Fatalf("IsCDNPattern should return false for non-ws links, got true for: port=%d, network=%q, tls=%v, host=%q, address=%q, security=%q",
				port, network, tls, host, address, security)
		}
	})
}
