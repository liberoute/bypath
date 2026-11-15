package gateway

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/liberoute/bypath/internal/tunnel"
	"github.com/miekg/dns"
)

// directResolver sends a DNS query straight out of the host. It exists so a
// name the routing plan sends DIRECT can still be resolved when the tunnel is
// down; it is never used for a name the plan proxies.
type directResolver struct {
	udpClient *dns.Client
	udpAddr   string
	http      *http.Client
	dohURL    string
}

// newDirectResolver validates gateway.direct_dns and builds the client for it.
// The transport deliberately carries no proxy: the point of a direct resolver is
// that it does not depend on the tunnel.
func newDirectResolver(raw string) (*directResolver, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "http://") {
		return nil, fmt.Errorf("gateway.direct_dns must use https, not http")
	}
	if strings.HasPrefix(lower, "https://") {
		return &directResolver{
			dohURL: raw,
			http: &http.Client{
				Timeout: dohRequestTimeout,
				Transport: &http.Transport{
					DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
					TLSHandshakeTimeout: 5 * time.Second,
				},
			},
		}, nil
	}
	return &directResolver{
		udpClient: &dns.Client{Net: "udp", Timeout: udpQueryTimeout},
		udpAddr:   dnsServerAddr(raw),
	}, nil
}

// exchange runs one query over the configured direct path.
func (d *directResolver) exchange(ctx context.Context, r *dns.Msg) (*dns.Msg, error) {
	if d.dohURL == "" {
		resp, _, err := d.udpClient.ExchangeContext(ctx, r, d.udpAddr)
		return resp, err
	}
	packed, err := r.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.dohURL, bytes.NewReader(packed))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := d.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("direct DoH answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	if err := m.Unpack(body); err != nil {
		return nil, err
	}
	return m, nil
}

// endpoint describes the direct resolver for logs without exposing a URL path.
func (d *directResolver) endpoint() string {
	if d.dohURL != "" {
		return d.dohURL
	}
	return d.udpAddr
}

// splitDNS is the split-aware half of the LAN forwarder: the trusted direct
// resolver and the plan-order classifier that decides which names may use it.
type splitDNS struct {
	direct   *directResolver
	classify *tunnel.NameClassifier
}

func (s splitDNS) enabled() bool { return s.direct != nil }

// class reports where the plan sends host. Without a classifier every name
// keeps the tunnel path.
func (s splitDNS) class(host string) tunnel.NameClass {
	if s.classify == nil {
		return tunnel.NameClassProxy
	}
	return s.classify.Classify(host)
}
