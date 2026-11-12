package app

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/liberoute/bypath/internal/geo"
	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/tunnel"
)

// RouteStep is one rule the router examined for a destination.
type RouteStep struct {
	Position int    `json:"position,omitempty"`
	Label    string `json:"label"`
	Verdict  string `json:"verdict"` // match, no_match, skipped, needs_ip, resolved, unresolved
	Routed   string `json:"routed,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// RouteExplanation answers "why does this destination use DIRECT or PROXY".
// It evaluates the same ordered plan the xray generator emits, in the same two
// passes xray performs with domainStrategy IPIfNonMatch: domain rules first,
// then IP rules against the resolved address.
type RouteExplanation struct {
	Target          string           `json:"target"`
	Kind            string           `json:"kind"` // domain or ip
	Outcome         string           `json:"outcome"`
	Outbound        string           `json:"outbound"`
	DefaultOutbound string           `json:"default_outbound"`
	DecidedBy       *RoutingRuleView `json:"decided_by,omitempty"`
	Steps           []RouteStep      `json:"steps"`
	Addresses       []string         `json:"addresses,omitempty"`
	DNS             string           `json:"dns"` // not_needed, gateway, unavailable, failed
	Certain         bool             `json:"certain"`
	Warnings        []string         `json:"warnings,omitempty"`
	Summary         string           `json:"summary"`
}

// nextHop describes what an outbound means in plain language.
func nextHop(outbound string) string {
	switch tunnel.EffectiveOutbound(outbound) {
	case "direct":
		return "DIRECT"
	case "proxy":
		return "PROXY"
	case "block":
		return "BLOCK"
	default:
		return "PROXY via " + outbound
	}
}

func outcomeMeaning(outcome string) string {
	switch outcome {
	case "DIRECT":
		return "Traffic leaves this network directly, without the tunnel."
	case "PROXY":
		return "Traffic is carried by the tunnel and leaves from the tunnel's exit address."
	case "BLOCK":
		return "Traffic is blocked: the gateway refuses the connection on purpose."
	default:
		return "Traffic is sent through the named external outbound."
	}
}

// ExplainRoute evaluates one destination against the live policy. It performs
// no writes and never contacts the destination; the only network activity is a
// DNS lookup through the gateway's own resolver when the name has to be
// resolved to check IP rules.
func (s *Local) ExplainRoute(ctx context.Context, target string) (RouteExplanation, error) {
	cfg := s.Config()
	plan := routingPlan(cfg)
	assets := s.routingAssets()

	host, isIP, err := parseTarget(target)
	if err != nil {
		return RouteExplanation{}, err
	}
	out := RouteExplanation{
		Target:          host,
		Outbound:        "",
		DefaultOutbound: tunnel.EffectiveOutbound(defaultOutbound(plan)),
		DNS:             "not_needed",
	}
	if isIP {
		out.Kind = "ip"
	} else {
		out.Kind = "domain"
		if strings.HasPrefix(host, "xn--") || strings.Contains(host, ".xn--") {
			out.Warnings = append(out.Warnings, "Internationalised names are matched in their punycode form; this is the form shown.")
		} else if !isASCII(host) {
			out.Warnings = append(out.Warnings, "This name contains non-ASCII characters. The engine matches the punycode (xn--) form, so enter that form for an exact answer.")
		}
	}

	var addresses []net.IP
	if isIP {
		addresses = []net.IP{net.ParseIP(host)}
	} else {
		if entry, position, ok := s.matchDomainPass(plan, assets, host, &out); ok {
			s.finishExplanation(&out, entry, position)
			return out, nil
		}
		addresses, out.DNS = s.resolveForRouting(ctx, host)
		switch out.DNS {
		case "gateway":
			for _, ip := range addresses {
				out.Addresses = append(out.Addresses, ip.String())
			}
			out.Steps = append(out.Steps, RouteStep{
				Verdict: "resolved",
				Label:   "DNS lookup through the gateway",
				Detail:  "The name resolves to " + strings.Join(out.Addresses, ", ") + ". IP rules are checked against that address.",
			})
		case "failed":
			out.Steps = append(out.Steps, RouteStep{
				Verdict: "unresolved",
				Label:   "DNS lookup through the gateway",
				Detail:  "The name could not be resolved right now, so IP rules could not be checked.",
			})
			out.Warnings = append(out.Warnings, "The domain could not be resolved. Check the spelling, or check the tunnel and DNS. If the engine also cannot resolve it, the default policy applies.")
		case "unavailable":
			out.Steps = append(out.Steps, RouteStep{
				Verdict: "unresolved",
				Label:   "DNS lookup through the gateway",
				Detail:  "The tunnel is not connected, so the name could not be resolved through it and IP rules were not checked.",
			})
			out.Warnings = append(out.Warnings, "Without a connected tunnel the address of this domain is unknown, so only domain rules were checked. Start the gateway to test the full decision.")
		}
	}

	if entry, position, ok := s.matchIPPass(plan, assets, addresses, &out); ok {
		s.finishExplanation(&out, entry, position)
		return out, nil
	}
	if entry, position, ok := defaultPlanEntry(plan); ok {
		s.finishExplanation(&out, entry, position)
		return out, nil
	}
	s.finishExplanation(&out, tunnel.PlanEntry{Scope: "default", Kind: "default", Outbound: out.DefaultOutbound}, len(plan)+1)
	return out, nil
}

// matchDomainPass applies the first pass: every rule that can be decided from
// the name alone, in plan order.
func (s *Local) matchDomainPass(plan []tunnel.PlanEntry, assets RoutingAssets, host string, out *RouteExplanation) (tunnel.PlanEntry, int, bool) {
	for i, entry := range plan {
		if !isDomainRule(entry.Kind) {
			continue
		}
		step := RouteStep{Position: i + 1, Label: entryMatchLabel(entry)}
		if entry.Skip != "" {
			step.Verdict = "skipped"
			step.Detail = entry.Skip
			out.Steps = append(out.Steps, step)
			continue
		}
		matched, detail := domainRuleMatches(entry, assets, host)
		if !matched {
			step.Verdict = "no_match"
			out.Steps = append(out.Steps, step)
			continue
		}
		step.Verdict = "match"
		step.Routed = nextHop(entry.Outbound)
		step.Detail = detail
		out.Steps = append(out.Steps, step)
		return entry, i + 1, true
	}
	return tunnel.PlanEntry{}, 0, false
}

// matchIPPass applies the second pass: private, geoip and ip_cidr rules against
// every address the name resolved to. The first matching rule wins, exactly as
// the engine behaves.
func (s *Local) matchIPPass(plan []tunnel.PlanEntry, assets RoutingAssets, addresses []net.IP, out *RouteExplanation) (tunnel.PlanEntry, int, bool) {
	if len(addresses) == 0 {
		return tunnel.PlanEntry{}, 0, false
	}
	for i, entry := range plan {
		switch entry.Kind {
		case "private", "geoip", "ip_cidr":
		default:
			continue
		}
		step := RouteStep{Position: i + 1, Label: entryMatchLabel(entry)}
		if entry.Skip != "" {
			step.Verdict = "skipped"
			step.Detail = entry.Skip
			out.Steps = append(out.Steps, step)
			continue
		}
		var evidence []string
		for _, ip := range addresses {
			matched, detail := ipRuleMatches(entry, assets, ip)
			if matched {
				evidence = append(evidence, detail)
			}
		}
		if len(evidence) == 0 {
			step.Verdict = "no_match"
			out.Steps = append(out.Steps, step)
			continue
		}
		step.Verdict = "match"
		step.Routed = nextHop(entry.Outbound)
		step.Detail = strings.Join(evidence, "; ")
		out.Steps = append(out.Steps, step)
		return entry, i + 1, true
	}
	return tunnel.PlanEntry{}, 0, false
}

func (s *Local) finishExplanation(out *RouteExplanation, entry tunnel.PlanEntry, position int) {
	out.Outbound = tunnel.EffectiveOutbound(entry.Outbound)
	out.Outcome = nextHop(entry.Outbound)
	view := RoutingRuleView{
		Position: position,
		Scope:    planEntryScope(entry),
		Source:   scopeLabel(planEntryScope(entry)),
		Kind:     entry.Kind,
		Match:    entryMatchLabel(entry),
		Outbound: out.Outbound,
		Effect:   out.Outcome,
	}
	out.DecidedBy = &view
	out.Certain = out.Kind == "ip" || out.DNS == "not_needed" || out.DNS == "gateway"
	if entry.Kind == "default" {
		out.Summary = "No rule matched this destination, so the default policy applies: everything else goes " + out.Outcome + ". " + outcomeMeaning(out.Outcome)
		return
	}
	out.Summary = entryMatchLabel(entry) + " sends this destination " + out.Outcome + ". " + outcomeMeaning(out.Outcome)
}

func isDomainRule(kind string) bool {
	switch kind {
	case "domain", "domain_suffix", "domain_suffix_list", "geosite":
		return true
	}
	return false
}

func domainRuleMatches(entry tunnel.PlanEntry, assets RoutingAssets, host string) (bool, string) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	switch entry.Kind {
	case "domain":
		if host == strings.ToLower(strings.TrimSuffix(entry.Value, ".")) {
			return true, "the name is exactly " + entry.Value
		}
	case "domain_suffix":
		if suffixMatch(host, entry.Value) {
			return true, "the name ends with " + entry.Value
		}
	case "domain_suffix_list":
		for _, suffix := range entry.Domains {
			if suffixMatch(host, suffix) {
				return true, "the name ends with " + suffix
			}
		}
	case "geosite":
		if assets.GeoSitePath == "" {
			return false, ""
		}
		matched, found := geo.LookupGeoSite(assets.GeoSitePath, entry.Value, host)
		if !found {
			return false, ""
		}
		if matched {
			return true, "the name is in the published " + entry.Value + " list"
		}
	}
	return false, ""
}

func ipRuleMatches(entry tunnel.PlanEntry, assets RoutingAssets, ip net.IP) (bool, string) {
	switch entry.Kind {
	case "private":
		if isNonPublicIP(ip) {
			return true, ip.String() + " is a private or local address"
		}
	case "ip_cidr":
		_, network, err := net.ParseCIDR(entry.Value)
		if err == nil && network.Contains(ip) {
			return true, ip.String() + " is inside " + entry.Value
		}
	case "geoip":
		if assets.GeoIPPath == "" {
			return false, ""
		}
		matched, found := geo.LookupGeoIP(assets.GeoIPPath, entry.Value, ip)
		if found && matched {
			return true, ip.String() + " is registered in " + strings.ToUpper(entry.Value)
		}
	}
	return false, ""
}

func suffixMatch(host, suffix string) bool {
	suffix = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(suffix), "."))
	suffix = strings.TrimPrefix(suffix, ".")
	if host == "" || suffix == "" {
		return false
	}
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

func isNonPublicIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast()
}

// resolveForRouting asks the gateway's own resolver, which is the resolver the
// engine uses. It deliberately never falls back to the host resolver: a
// poisoned local answer would produce a confident but wrong explanation.
func (s *Local) resolveForRouting(ctx context.Context, host string) ([]net.IP, string) {
	cfg := s.Config()
	if s.runtime == nil || s.runtime.Status().State != "CONNECTED" {
		return nil, "unavailable"
	}
	port := cfg.Server.DNSPort
	if port == 0 {
		return nil, "unavailable"
	}
	queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 2 * time.Second}
			return dialer.DialContext(ctx, "udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		},
	}
	ips, err := resolver.LookupIP(queryCtx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, "failed"
	}
	return ips, "gateway"
}

func parseTarget(raw string) (string, bool, error) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return "", false, errorf(CodeInvalid, "enter a domain name or an IP address")
	}
	if strings.ContainsAny(target, " \t\r\n\x00") {
		return "", false, errorf(CodeInvalid, "%q is not a domain name or an IP address", raw)
	}
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			target = u.Host
		}
	}
	target = strings.TrimSuffix(target, "/")
	if i := strings.IndexAny(target, "/?#"); i >= 0 {
		target = target[:i]
	}
	// A bracketed IPv6 literal may carry a port.
	if strings.HasPrefix(target, "[") {
		if host, _, err := net.SplitHostPort(target); err == nil {
			target = host
		} else {
			target = strings.Trim(target, "[]")
		}
	} else if ip := net.ParseIP(target); ip == nil {
		if host, _, err := net.SplitHostPort(target); err == nil {
			target = host
		}
	}
	// A fully-qualified name may carry one trailing dot; the engine matches it
	// without the dot, so accept the form operators paste from dig output.
	target = strings.TrimSuffix(target, ".")
	if ip := net.ParseIP(target); ip != nil {
		return ip.String(), true, nil
	}
	if len(target) > 253 || !validDomainName(target) {
		return "", false, errorf(CodeInvalid, "%q does not look like a domain name or an IP address", raw)
	}
	return strings.ToLower(target), false, nil
}

func validDomainName(name string) bool {
	if name == "" || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r > 127 {
				continue
			}
			return false
		}
	}
	return true
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return false
		}
	}
	return true
}

// --- route test -------------------------------------------------------------

// RouteTestResult reports what happened when one destination was actually
// contacted through the tunnel. The verdict separates routing decisions from
// connection, DNS and HTTP outcomes so a beginner can tell them apart.
type RouteTestResult struct {
	Target      string           `json:"target"`
	Port        int              `json:"port"`
	Outcome     string           `json:"outcome"`
	Verdict     string           `json:"verdict"`
	VerdictText string           `json:"verdict_text"`
	LatencyMS   int64            `json:"latency_ms,omitempty"`
	HTTPStatus  int              `json:"http_status,omitempty"`
	Detail      string           `json:"detail,omitempty"`
	Explanation RouteExplanation `json:"explanation"`
}

// TestRoute connects to one destination through the gateway's SOCKS listener,
// so the connection follows the same rules as the LAN clients, and reports a
// single honest verdict.
func (s *Local) TestRoute(ctx context.Context, raw string, port int) (RouteTestResult, error) {
	explanation, err := s.ExplainRoute(ctx, raw)
	if err != nil {
		return RouteTestResult{}, err
	}
	if port == 0 {
		port = 443
	}
	if port < 1 || port > 65535 {
		return RouteTestResult{}, errorf(CodeInvalid, "port must be between 1 and 65535")
	}
	result := RouteTestResult{Target: explanation.Target, Port: port, Outcome: explanation.Outcome, Explanation: explanation}

	if explanation.Outcome == "BLOCK" {
		result.Verdict = "blocked_by_rule"
		result.VerdictText = "The routing policy blocks this destination; no connection was attempted."
		return result, nil
	}
	if s.runtime == nil || s.runtime.Status().State != "CONNECTED" {
		result.Verdict = "gateway_offline"
		result.VerdictText = "The gateway is not connected, so this destination cannot be tested through the tunnel."
		return result, nil
	}
	if explanation.Kind == "domain" && explanation.DNS == "failed" {
		result.Verdict = "dns_failure"
		result.VerdictText = "The domain name could not be resolved, so no connection was attempted."
		return result, nil
	}
	if explanation.Kind == "domain" && explanation.DNS == "unavailable" {
		result.Verdict = "dns_failure"
		result.VerdictText = "The domain name could not be resolved through the tunnel, so no connection was attempted."
		return result, nil
	}

	proxyAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Config().Server.SOCKSPort))
	start := time.Now()
	conn, err := profile.DialSOCKS5(ctx, proxyAddr, explanation.Target, port, 6*time.Second)
	if err != nil {
		result.LatencyMS = time.Since(start).Milliseconds()
		result.Verdict = "connection_failed"
		result.VerdictText = "The tunnel could not open a connection to this destination. The site may be down, the port may be closed, or the proxy may be blocking it."
		result.Detail = Redact(err.Error())
		return result, nil
	}
	defer conn.Close()

	if port != 80 && port != 443 {
		result.LatencyMS = time.Since(start).Milliseconds()
		result.Verdict = "tcp_connected"
		result.VerdictText = "A TCP connection was opened through the tunnel. Only connectivity was checked for this port."
		return result, nil
	}
	if port == 443 && explanation.Kind == "ip" {
		result.LatencyMS = time.Since(start).Milliseconds()
		result.Verdict = "tcp_connected"
		result.VerdictText = "A TCP connection was opened through the tunnel. HTTPS was not verified because an IP address has no certificate name to check."
		return result, nil
	}

	var stream io.ReadWriter = conn
	if port == 443 {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: explanation.Target, MinVersion: tls.VersionTLS12})
		_ = tlsConn.SetDeadline(time.Now().Add(6 * time.Second))
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			result.LatencyMS = time.Since(start).Milliseconds()
			result.Verdict = "tls_failure"
			result.VerdictText = "The connection reached the destination but the HTTPS handshake failed. Something between the gateway and the site may be blocking or intercepting it."
			result.Detail = Redact(err.Error())
			return result, nil
		}
		stream = tlsConn
	}
	result.LatencyMS = time.Since(start).Milliseconds()

	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	request := "GET / HTTP/1.1\r\nHost: " + explanation.Target + "\r\nUser-Agent: bypath-panel\r\nAccept: */*\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(stream, request); err != nil {
		result.Verdict = "http_error"
		result.VerdictText = "The connection was established but the request failed to complete."
		result.Detail = Redact(err.Error())
		return result, nil
	}
	line, err := bufio.NewReader(io.LimitReader(stream, 8192)).ReadString('\n')
	if err != nil {
		result.Verdict = "http_error"
		result.VerdictText = "The connection was established but no HTTP response arrived."
		result.Detail = Redact(err.Error())
		return result, nil
	}
	status, statusText := parseStatusLine(line)
	if status == 0 {
		result.Verdict = "http_error"
		result.VerdictText = "The destination answered with something that is not HTTP."
		result.Detail = strings.TrimSpace(line)
		return result, nil
	}
	result.HTTPStatus = status
	if status >= 200 && status < 400 {
		result.Verdict = "reachable"
		result.VerdictText = "The tunnel connected and the site answered over HTTPS."
		if port != 443 {
			result.VerdictText = "The tunnel connected and the site answered over HTTP (not encrypted)."
		}
		return result, nil
	}
	result.Verdict = "http_error"
	result.VerdictText = fmt.Sprintf("The route works, but the site answered HTTP %d %s. The destination is reachable; the site itself refused this request.", status, statusText)
	return result, nil
}

func parseStatusLine(line string) (int, string) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return 0, ""
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil || status < 100 || status > 599 {
		return 0, ""
	}
	return status, strings.Join(fields[2:], " ")
}

// --- egress check -----------------------------------------------------------

// EgressCheck shows which public address the tunnel exit and this gateway
// process use. The two rows answer different questions: the tunnel row is what
// the LAN clients look like to the world, the direct row is this process.
type EgressCheck struct {
	TunnelExit  string `json:"tunnel_exit,omitempty"`
	TunnelError string `json:"tunnel_error,omitempty"`
	DirectIP    string `json:"direct_ip,omitempty"`
	DirectError string `json:"direct_error,omitempty"`
	Same        bool   `json:"same"`
	Country     string `json:"country,omitempty"`
	Colo        string `json:"colo,omitempty"`
	Note        string `json:"note,omitempty"`
}

// CheckEgress resolves the public address of the tunnel and of this process.
// Both probes are bounded and neither result is presented as a secret.
func (s *Local) CheckEgress(ctx context.Context) (EgressCheck, error) {
	check := EgressCheck{}
	if s.runtime != nil && s.runtime.Status().State == "CONNECTED" {
		probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		exit, err := s.ProbeExitIP(probeCtx)
		cancel()
		if err != nil {
			check.TunnelError = Redact(err.Error())
		} else {
			check.TunnelExit = exit
		}
	} else {
		check.TunnelError = "the tunnel is not connected, so it has no exit address"
	}

	probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	direct, trace, err := directEgress(probeCtx)
	cancel()
	if err != nil {
		check.DirectError = Redact(err.Error())
	} else {
		check.DirectIP = direct
		if v, ok := trace["loc"]; ok {
			check.Country = v
		}
		if v, ok := trace["colo"]; ok {
			check.Colo = v
		}
	}

	if check.TunnelExit != "" && check.DirectIP != "" {
		check.Same = check.TunnelExit == check.DirectIP
	}
	switch {
	case check.Same:
		check.Note = "Both checks reported the same address. This gateway's own traffic is also going through the tunnel, so the DIRECT row cannot show the network's real address from here. A device on the LAN may still go DIRECT."
	case check.TunnelExit == "" && check.DirectIP == "":
		check.Note = "Neither address could be determined. Check the tunnel and this gateway's internet access."
	case check.TunnelExit == "":
		check.Note = "The tunnel exit address is unknown because the tunnel is not connected. The other row shows this gateway process."
	}
	return check, nil
}

// DirectPublicIP reports the public address this process uses without the
// tunnel. It is used to prove that a verified exit differs from the host's own.
func DirectPublicIP(ctx context.Context) (string, error) {
	ip, _, err := directEgress(ctx)
	return ip, err
}

func directEgress(ctx context.Context) (string, map[string]string, error) {	client := &http.Client{Timeout: 6 * time.Second}
	ip, err := directGet(ctx, client, "https://api.ipify.org", 128)
	if err != nil {
		return "", nil, err
	}
	traceValues := map[string]string{}
	trace, err := directGet(ctx, client, "https://www.cloudflare.com/cdn-cgi/trace", 16<<10)
	if err == nil {
		for _, line := range strings.Split(trace, "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok {
				continue
			}
			traceValues[key] = value
		}
	}
	if traceIP := traceValues["ip"]; traceIP != "" && net.ParseIP(traceIP) != nil {
		ip = traceIP
	}
	if net.ParseIP(ip) == nil {
		return "", nil, errors.New("the address check returned an unexpected response")
	}
	return ip, traceValues, nil
}

func directGet(ctx context.Context, client *http.Client, target string, limit int64) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "bypath-panel")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("%s answered HTTP %d", target, resp.StatusCode)
	}
	return strings.TrimSpace(string(body)), nil
}
