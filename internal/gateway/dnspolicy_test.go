package gateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseDNSMode(t *testing.T) {
	cases := map[string]struct {
		want    dnsPolicy
		wantErr bool
	}{
		"":        {want: dnsPolicyStrict},
		"strict":  {want: dnsPolicyStrict},
		"STRICT":  {want: dnsPolicyStrict},
		"local":   {want: dnsPolicyLocal},
		" local ": {want: dnsPolicyLocal},
		"off":     {wantErr: true},
		"direct":  {wantErr: true},
	}
	for mode, tc := range cases {
		got, err := parseDNSMode(mode)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseDNSMode(%q) succeeded, want error", mode)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDNSMode(%q): %v", mode, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseDNSMode(%q) = %v, want %v", mode, got, tc.want)
		}
	}
}

func TestDNSServerAddr(t *testing.T) {
	cases := map[string]string{
		"1.1.1.1":       "1.1.1.1:53",
		"1.1.1.1:5353":  "1.1.1.1:5353",
		"2001:db8::1":   "[2001:db8::1]:53",
		"[2001:db8::1]": "[2001:db8::1]:53",
	}
	for in, want := range cases {
		if got := dnsServerAddr(in); got != want {
			t.Errorf("dnsServerAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func dohAnswer(t *testing.T, r *http.Request) (*http.Response, error) {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("reading DoH request: %v", err)
	}
	query := new(dns.Msg)
	if err := query.Unpack(body); err != nil {
		t.Fatalf("unpacking DoH query: %v", err)
	}
	resp := new(dns.Msg)
	resp.SetReply(query)
	rr, err := dns.NewRR("example.com. 60 IN A 198.51.100.7")
	if err != nil {
		t.Fatalf("building answer: %v", err)
	}
	resp.Answer = append(resp.Answer, rr)
	packed, err := resp.Pack()
	if err != nil {
		t.Fatalf("packing DoH answer: %v", err)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(packed)),
	}, nil
}

func failingDoH(*http.Request) (*http.Response, error) {
	return nil, errors.New("proxy unavailable")
}

// startTestDNSServer runs a UDP DNS server that answers every A query with
// 203.0.113.9 and counts the queries it receives.
func startTestDNSServer(t *testing.T) (string, *int32) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for test DNS: %v", err)
	}
	var count int32
	srv := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			atomic.AddInt32(&count, 1)
			m := new(dns.Msg)
			m.SetReply(req)
			if len(req.Question) > 0 {
				rr, rrErr := dns.NewRR(req.Question[0].Name + " 60 IN A 203.0.113.9")
				if rrErr == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String(), &count
}

func TestForwardDNSStrictNeverFallsBackToDirect(t *testing.T) {
	directAddr, directQueries := startTestDNSServer(t)
	udpClient := &dns.Client{Net: "udp"}
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	t.Run("DoH healthy", func(t *testing.T) {
		atomic.StoreInt32(directQueries, 0)
		client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return dohAnswer(t, r)
		})}
		resp := forwardDNS(context.Background(), query, client, udpClient,
			[]string{"https://doh.example/dns-query"}, []string{directAddr}, nil, dnsPolicyStrict)
		if resp == nil || len(resp.Answer) == 0 {
			t.Fatalf("DoH response not used: %+v", resp)
		}
		if got := atomic.LoadInt32(directQueries); got != 0 {
			t.Fatalf("strict policy sent %d direct queries", got)
		}
	})

	t.Run("DoH down", func(t *testing.T) {
		atomic.StoreInt32(directQueries, 0)
		client := &http.Client{Transport: roundTripFunc(failingDoH)}
		resp := forwardDNS(context.Background(), query, client, udpClient,
			[]string{"https://doh.example/dns-query"}, []string{directAddr}, nil, dnsPolicyStrict)
		if resp != nil {
			t.Fatalf("strict policy fell back to direct DNS: %+v", resp)
		}
		if got := atomic.LoadInt32(directQueries); got != 0 {
			t.Fatalf("strict policy sent %d direct queries", got)
		}
	})
}

func TestForwardDNSLocalPolicyAllowsExplicitDirectFallback(t *testing.T) {
	directAddr, directQueries := startTestDNSServer(t)
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	client := &http.Client{Transport: roundTripFunc(failingDoH)}
	resp := forwardDNS(context.Background(), query, client, &dns.Client{Net: "udp"},
		[]string{"https://doh.example/dns-query"}, []string{directAddr}, nil, dnsPolicyLocal)
	if resp == nil || len(resp.Answer) == 0 {
		t.Fatalf("local policy did not use direct DNS: %+v", resp)
	}
	if got := atomic.LoadInt32(directQueries); got != 1 {
		t.Fatalf("direct queries = %d, want 1", got)
	}
}

func TestForwardDNSLocalSuffixUsesDeclaredServer(t *testing.T) {
	localAddr, localQueries := startTestDNSServer(t)
	client := &http.Client{Transport: roundTripFunc(failingDoH)}
	query := new(dns.Msg)
	query.SetQuestion("printer.home.", dns.TypeA)

	resp := forwardDNS(context.Background(), query, client, &dns.Client{Net: "udp"},
		nil, nil, []localDNSEntry{{suffixes: []string{"home"}, server: localAddr}}, dnsPolicyStrict)
	if resp == nil || len(resp.Answer) == 0 {
		t.Fatalf("declared local suffix was not resolved: %+v", resp)
	}
	if got := atomic.LoadInt32(localQueries); got != 1 {
		t.Fatalf("local DNS queries = %d, want 1", got)
	}
}

func TestForwardDNSUnreachableLocalSuffixReturnsNXDomain(t *testing.T) {
	// Grab a free port and close it so the query fails.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving port: %v", err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()

	query := new(dns.Msg)
	query.SetQuestion("printer.home.", dns.TypeA)
	resp := forwardDNS(context.Background(), query, &http.Client{Transport: roundTripFunc(failingDoH)},
		&dns.Client{Net: "udp", Timeout: 200 * time.Millisecond},
		nil, nil, []localDNSEntry{{suffixes: []string{"home"}, server: addr}}, dnsPolicyStrict)
	if resp == nil || resp.Rcode != dns.RcodeNameError {
		t.Fatalf("unreachable local DNS = %+v, want NXDOMAIN", resp)
	}
}

func TestDoHURLValidation(t *testing.T) {
	bad := []string{"", "   ", "https://", "http://[::1"}
	for _, in := range bad {
		if _, err := dohURLFor(in); err == nil {
			t.Errorf("dohURLFor(%q) accepted a malformed endpoint", in)
		}
	}
	good := map[string]string{
		"1.1.1.1":                       "https://1.1.1.1/dns-query",
		"1.1.1.1:8443":                  "https://1.1.1.1:8443/dns-query",
		"1.1.1.1:443":                   "https://1.1.1.1/dns-query",
		"2001:db8::1":                   "https://[2001:db8::1]/dns-query",
		"https://doh.example/dns-query": "https://doh.example/dns-query",
	}
	for in, want := range good {
		got, err := dohURLFor(in)
		if err != nil {
			t.Errorf("dohURLFor(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("dohURLFor(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := buildDoHURLs([]string{"1.1.1.1", "https://"}); err == nil {
		t.Error("buildDoHURLs accepted one malformed endpoint in a valid set")
	}
}

// TestForwardDNSMalformedEndpointNeverPanicsOrLeaks proves an invalid DoH URL
// is skipped as a controlled configuration error. The strict policy must answer
// SERVFAIL (nil here) and must never fall back to direct DNS.
func TestForwardDNSMalformedEndpointNeverPanicsOrLeaks(t *testing.T) {
	directAddr, directQueries := startTestDNSServer(t)
	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	resp := forwardDNS(context.Background(), query, &http.Client{Transport: roundTripFunc(failingDoH)},
		&dns.Client{Net: "udp"}, []string{"://missing-scheme"}, []string{directAddr}, nil, dnsPolicyStrict)
	if resp != nil {
		t.Fatalf("strict policy resolved through an invalid endpoint: %+v", resp)
	}
	if got := atomic.LoadInt32(directQueries); got != 0 {
		t.Fatalf("strict policy sent %d direct queries after an invalid endpoint", got)
	}

	// A malformed first endpoint must not prevent a later valid one from being
	// used.
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "doh.example" {
			t.Fatalf("request reached unexpected host %q", r.URL.Host)
		}
		return dohAnswer(t, r)
	})}
	resp = forwardDNS(context.Background(), query, client,
		&dns.Client{Net: "udp"}, []string{"://missing-scheme", "https://doh.example/dns-query"},
		[]string{directAddr}, nil, dnsPolicyStrict)
	if resp == nil || len(resp.Answer) == 0 {
		t.Fatalf("valid endpoint after a malformed one was not used: %+v", resp)
	}
}
