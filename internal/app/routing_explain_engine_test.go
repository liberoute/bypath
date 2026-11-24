package app

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/config"
)

// startFakeDNS answers every A query with ip and every AAAA query with an empty
// answer, so the explainer's gateway-resolver path can run without a tunnel.
func startFakeDNS(t *testing.T, ip net.IP) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			query := append([]byte(nil), buf[:n]...)
			if len(query) < 12 {
				continue
			}
			// Walk the QNAME labels to find the end of the question section.
			i := 12
			for i < len(query) && query[i] != 0 {
				i += int(query[i]) + 1
			}
			if i+5 > len(query) {
				continue
			}
			qtype := binary.BigEndian.Uint16(query[i+1 : i+3])
			question := query[12 : i+5]
			answerCount := byte(0)
			if qtype == 1 { // A
				answerCount = 1
			}
			resp := []byte{query[0], query[1], 0x81, 0x80, 0, 1, 0, answerCount, 0, 0, 0, 0}
			resp = append(resp, question...)
			if answerCount == 1 {
				// Compression pointer to the question name, A/IN, TTL 60, 4 bytes.
				resp = append(resp, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
				resp = append(resp, ip.To4()...)
			}
			_, _ = conn.WriteTo(resp, addr)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// TestExplainRouteMatchesEngineSemantics pins F-004 with a case where the two
// engines genuinely disagree: the name is covered by a domain rule that appears
// after an address rule, and resolves into that earlier address range.
//   - sing-box evaluates one ordered pass after resolving, so the address rule
//     wins (DIRECT).
//   - xray checks every domain rule first, so the domain rule wins (PROXY).
func TestExplainRouteMatchesEngineSemantics(t *testing.T) {
	rules := []config.RoutingRule{
		{Match: "ip_cidr:203.0.113.0/24", Outbound: "direct"},
		{Match: "domain_suffix:example.test", Outbound: "proxy"},
		{Match: "default", Outbound: "proxy"},
	}
	svc := newRoutingLocal(t, rules, &fakeRuntime{state: "CONNECTED"})
	svc.cfg.Server.DNSPort = startFakeDNS(t, net.IPv4(203, 0, 113, 9))
	svc.cfg.Engines.PreferredEngine = "sing-box"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	singbox, err := svc.ExplainRoute(ctx, "news.example.test")
	if err != nil {
		t.Fatalf("explain (sing-box): %v", err)
	}
	if singbox.Outcome != "DIRECT" {
		t.Fatalf("sing-box outcome = %s, want DIRECT via the earlier ip_cidr rule: %+v", singbox.Outcome, singbox)
	}
	if singbox.DecidedBy == nil || singbox.DecidedBy.Kind != "ip_cidr" {
		t.Fatalf("sing-box decided by %+v, want ip_cidr", singbox.DecidedBy)
	}
	if singbox.DNS != "gateway" || !singbox.Certain {
		t.Fatalf("sing-box explanation = DNS %q certain=%v, want gateway/true", singbox.DNS, singbox.Certain)
	}

	svc.cfg.Engines.PreferredEngine = "xray"
	xray, err := svc.ExplainRoute(ctx, "news.example.test")
	if err != nil {
		t.Fatalf("explain (xray): %v", err)
	}
	if xray.Outcome != "PROXY" {
		t.Fatalf("xray outcome = %s, want PROXY via the domain pass: %+v", xray.Outcome, xray)
	}
	if xray.DecidedBy == nil || xray.DecidedBy.Kind != "domain_suffix" {
		t.Fatalf("xray decided by %+v, want domain_suffix", xray.DecidedBy)
	}
	if xray.DNS != "not_needed" || !xray.Certain {
		t.Fatalf("xray explanation = DNS %q certain=%v, want not_needed/true", xray.DNS, xray.Certain)
	}
}

// TestExplainRouteUncheckedIPRuleIsUncertain: if the address rules ahead of a
// domain match could not be evaluated, the panel must not present the result as
// proven.
func TestExplainRouteUncheckedIPRuleIsUncertain(t *testing.T) {
	rules := []config.RoutingRule{
		{Match: "ip_cidr:203.0.113.0/24", Outbound: "direct"},
		{Match: "domain_suffix:example.test", Outbound: "proxy"},
		{Match: "default", Outbound: "proxy"},
	}
	svc := newRoutingLocal(t, rules, &fakeRuntime{state: "CONNECTED"})
	svc.cfg.Server.DNSPort = closedUDPPort(t)
	svc.cfg.Engines.PreferredEngine = "sing-box"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := svc.ExplainRoute(ctx, "news.example.test")
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	if out.Outcome != "PROXY" {
		t.Fatalf("outcome = %s, want PROXY from the domain rule: %+v", out.Outcome, out)
	}
	if out.Certain {
		t.Fatalf("an unchecked address rule still produced a certain answer: %+v", out)
	}
	if out.DNS != "failed" {
		t.Fatalf("DNS = %q, want failed", out.DNS)
	}
}
