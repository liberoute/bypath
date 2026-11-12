package bench

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/liberoute/bypath/internal/profile"
)

// DiagnoseEndpoint explains why an isolated session could not carry HTTPS.
// It only inspects reachability and, for TLS links, the endpoint handshake;
// it never sends link credentials and never touches the serving tunnel.
// A nil return means both looked healthy, so the failure is elsewhere.
func DiagnoseEndpoint(ctx context.Context, link *profile.Link, opts Options) error {
	if link == nil || !Benchable(link) {
		return nil
	}
	resolver, err := endpointResolver(link, opts)
	if err != nil {
		return &AttemptError{Category: "test_infrastructure_failure", Err: err}
	}
	var lookup func(context.Context, string) ([]net.IPAddr, error)
	if resolver != nil {
		lookup = resolver.LookupIPAddr
	}
	pinned, err := PinServer(ctx, link.Address, lookup)
	if err != nil {
		return &AttemptError{Category: "unreachable_server", Err: err}
	}
	address := pinned[link.Address]
	if address == "" {
		address = link.Address
	}
	endpoint := net.JoinHostPort(address, strconv.Itoa(link.Port))

	dial := &net.Dialer{Timeout: 6 * time.Second}
	raw, err := dial.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return &AttemptError{Category: "unreachable_server", Err: err}
	}
	defer raw.Close()
	if link.Security != "tls" {
		return nil
	}

	sni := link.SNI
	if sni == "" {
		sni = link.Address
	}
	conf := &tls.Config{ServerName: sni, InsecureSkipVerify: link.Insecure, MinVersion: tls.VersionTLS12}
	if len(link.ALPN) > 0 {
		conf.NextProtos = link.ALPN
	}
	_ = raw.SetDeadline(time.Now().Add(6 * time.Second))
	conn := tls.Client(raw, conf)
	if err := conn.HandshakeContext(ctx); err != nil {
		return &AttemptError{Category: "handshake_failure", Err: fmt.Errorf("TLS handshake with %s failed: %w", sni, err)}
	}
	state := conn.ConnectionState()
	if len(link.ALPN) > 0 && !contains(state.NegotiatedProtocol, link.ALPN) {
		return &AttemptError{Category: "handshake_failure",
			Err: fmt.Errorf("the endpoint did not negotiate a required ALPN protocol (got %q)", state.NegotiatedProtocol)}
	}
	return nil
}

func contains(value string, allowed []string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
