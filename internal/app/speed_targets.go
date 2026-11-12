package app

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/layer"
	"github.com/liberoute/bypath/internal/profile"
)

// Speed-target policy. A target URL is attacker-influenced input on a gateway
// that runs as root, so only registered targets are accepted, every run
// re-resolves the name through the tested path, every address is checked
// against the deny list, and the connection is pinned to the validated address.
const (
	maxSpeedTargets   = 10
	speedTargetMaxURL = 512
	// defaultSpeedTargetHost was validated from the Pi's own network in S0.7
	// (HTTP 206, Range honoured). Cloudflare-hosted targets are never defaults.
	defaultSpeedTargetHost = "dl.google.com"
	defaultSpeedTargetPath = "/linux/direct/google-chrome-stable_current_amd64.deb"
	dohResolverURL         = "https://1.1.1.1/dns-query"
	maxResolvedAddresses   = 8
)

// SpeedTarget is one registered download target. Stored validation is
// informational: every run re-validates.
type SpeedTarget struct {
	ID              string   `json:"id"`
	Host            string   `json:"host"`
	Path            string   `json:"path"`
	URL             string   `json:"url"`
	BuiltIn         bool     `json:"built_in,omitempty"`
	ValidatedAt     string   `json:"validated_at,omitempty"`
	SupportsRange   bool     `json:"supports_range"`
	LastResolvedIPs []string `json:"last_resolved_ips,omitempty"`
	LastRoute       string   `json:"last_route,omitempty"`
	LastStatus      string   `json:"last_status,omitempty"`
	LastCheckedAt   string   `json:"last_checked_at,omitempty"`
}

// TargetCheck is the outcome of the stage-0 target validation for one run.
type TargetCheck struct {
	OK            bool     `json:"ok"`
	Reason        string   `json:"reason,omitempty"`
	Host          string   `json:"host"`
	Path          string   `json:"path"`
	ResolvedIPs   []string `json:"resolved_ips,omitempty"`
	Route         string   `json:"route,omitempty"`
	SupportsRange bool     `json:"supports_range"`
}

// budgetError marks a refusal caused by the traffic budget rather than by the
// link; the runner reports it as "budget reached".
var errBudgetReached = errors.New("traffic budget reached")

// ---------------------------------------------------------------------------
// URL syntax (SPEED_TARGET_SECURITY §3)

var numericHost = regexp.MustCompile(`^[0-9.]+$`)

// validateSpeedTargetURL applies the syntactic rules and returns the host and
// path. It never resolves anything.
func validateSpeedTargetURL(raw string) (host, path string, err error) {
	if raw == "" {
		return "", "", errors.New("the target URL is empty")
	}
	if len(raw) > speedTargetMaxURL {
		return "", "", fmt.Errorf("the target URL is longer than %d bytes", speedTargetMaxURL)
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x21 || raw[i] > 0x7e {
			return "", "", errors.New("the target URL contains whitespace or control characters")
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", errors.New("the target URL cannot be parsed")
	}
	if u.Scheme != "https" {
		return "", "", errors.New("the target must use https")
	}
	if u.User != nil {
		return "", "", errors.New("the target URL must not contain credentials")
	}
	if u.Fragment != "" {
		return "", "", errors.New("the target URL must not contain a fragment")
	}
	if u.Port() != "" && u.Port() != "443" {
		return "", "", errors.New("the target must use port 443")
	}
	h := strings.ToLower(u.Hostname())
	if h == "" {
		return "", "", errors.New("the target URL has no hostname")
	}
	if strings.HasSuffix(h, ".") {
		return "", "", errors.New("the target hostname must not end with a dot")
	}
	if net.ParseIP(h) != nil || numericHost.MatchString(h) || strings.HasPrefix(h, "0x") || strings.Contains(h, "\\") {
		return "", "", errors.New("the target must be a DNS name, not an IP address")
	}
	if !strings.Contains(h, ".") {
		return "", "", errors.New("the target must be a fully qualified DNS name")
	}
	switch {
	case h == "localhost", strings.HasSuffix(h, ".localhost"):
		return "", "", errors.New("the target must not be localhost")
	}
	for _, suffix := range []string{".local", ".internal", ".lan", ".home", ".localdomain", ".intranet", ".corp", ".arpa"} {
		if strings.HasSuffix(h, suffix) {
			return "", "", fmt.Errorf("the target must not be a private name (%s)", suffix)
		}
	}
	if !isASCIIHost(h) {
		return "", "", errors.New("the target hostname must be ASCII (use the punycode form)")
	}
	path = u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	return h, path, nil
}

func isASCIIHost(h string) bool {
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c >= 0x80 {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Address deny list (SPEED_TARGET_SECURITY §5)

var deniedNets = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
		"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "64:ff9b::/96", "2001::/32", "2001:db8::/32",
		"2002::/16", "fc00::/7", "fe80::/10", "ff00::/8",
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// unwrapIP strips IPv4-in-IPv6 wrappers before the deny check. NAT64 and 6to4
// carry a public-looking prefix over a private address.
func unwrapIP(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	if len(ip) != net.IPv6len {
		return ip
	}
	// NAT64 64:ff9b::/96
	if ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xff && ip[3] == 0x9b &&
		ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 && ip[8] == 0 && ip[9] == 0 && ip[10] == 0 && ip[11] == 0 {
		return net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4()
	}
	// 6to4 2002::/16 embeds the IPv4 address in bytes 2..5.
	if ip[0] == 0x20 && ip[1] == 0x02 {
		return net.IPv4(ip[2], ip[3], ip[4], ip[5]).To4()
	}
	return ip
}

// deniedAddress reports why an address may not be contacted, or "" when it is
// acceptable. dynamic holds this host's own interface addresses.
func deniedAddress(ip net.IP, dynamic []*net.IPNet) string {
	if ip == nil {
		return "unparseable address"
	}
	u := unwrapIP(ip)
	for _, n := range deniedNets {
		if n.Contains(u) {
			return "a private, reserved or non-routable address"
		}
	}
	for _, n := range dynamic {
		if n.Contains(u) {
			return "an address of this gateway"
		}
	}
	if u.IsMulticast() {
		return "a multicast address"
	}
	return ""
}

// localDeniedNets collects the addresses of the host's own interfaces. A test
// must never be able to reach the gateway, its LAN or its management services
// through the tunnel.
func localDeniedNets() []*net.IPNet {
	var out []*net.IPNet
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				out = append(out, n)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Resolution through the tested path

// dohAnswer is the JSON shape of a DNS-over-HTTPS answer.
type dohAnswer struct {
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

// resolveThroughPath resolves a name through the tested SOCKS path using a
// fixed public resolver reached by IP literal. The system resolver is never
// consulted, so a name cannot resolve differently for the test and the system.
func resolveThroughPath(ctx context.Context, socksPort int, host string) ([]net.IP, error) {
	var ips []net.IP
	var lastErr error
	for _, qtype := range []string{"A", "AAAA"} {
		target := fmt.Sprintf("%s?name=%s&type=%s", dohResolverURL, url.QueryEscape(host), qtype)
		body, _, err := profile.GetThroughProxy(ctx, socksPort, target,
			map[string]string{"Accept": "application/dns-json"}, 8192)
		if err != nil {
			lastErr = err
			continue
		}
		var ans dohAnswer
		if err := json.Unmarshal(body, &ans); err != nil {
			lastErr = fmt.Errorf("unreadable resolver answer")
			continue
		}
		for _, a := range ans.Answer {
			if ip := net.ParseIP(strings.TrimSpace(a.Data)); ip != nil {
				ips = append(ips, ip)
				if len(ips) >= maxResolvedAddresses {
					break
				}
			}
		}
		if len(ips) >= maxResolvedAddresses {
			break
		}
	}
	if len(ips) == 0 {
		if lastErr == nil {
			lastErr = errors.New("the name did not resolve through the tested path")
		}
		return nil, lastErr
	}
	return ips, nil
}

// checkTargetThroughPath performs stage 0: resolve through the path, validate
// every address, and (live path only) require the policy to route the host and
// each address through the tunnel. Any refused address refuses the whole name.
func (s *Local) checkTargetThroughPath(ctx context.Context, socksPort int, t SpeedTarget, live bool) TargetCheck {
	check := TargetCheck{Host: t.Host, Path: t.Path}
	ips, err := resolveThroughPath(ctx, socksPort, t.Host)
	if err != nil {
		check.Reason = "the target name could not be resolved through the tested path"
		return check
	}
	dynamic := localDeniedNets()
	for _, ip := range ips {
		if why := deniedAddress(ip, dynamic); why != "" {
			check.Reason = fmt.Sprintf("target resolves to %s — blocked", why)
			check.ResolvedIPs = ipStrings(ips)
			return check
		}
	}
	check.ResolvedIPs = ipStrings(ips)

	if live {
		exp, err := s.ExplainRoute(ctx, t.Host)
		if err != nil || !exp.Certain {
			check.Reason = "the routing policy could not be evaluated for the target"
			return check
		}
		if exp.Outcome != "PROXY" {
			check.Route = exp.Outcome
			check.Reason = fmt.Sprintf("target would go %s — choose another", exp.Outcome)
			return check
		}
		for _, ip := range ips {
			exp, err := s.ExplainRoute(ctx, ip.String())
			if err != nil || !exp.Certain {
				check.Reason = "the routing policy could not be evaluated for the target address"
				return check
			}
			if exp.Outcome != "PROXY" {
				check.Route = exp.Outcome
				check.Reason = "target address would go " + exp.Outcome + " — choose another"
				return check
			}
		}
		check.Route = "PROXY"
	} else {
		// An isolated instance is built with no routing rules, so the policy
		// decision for the hostname is not applicable; the identity proof is.
		check.Route = "isolated"
	}
	check.OK = true
	return check
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// Pinned, redirect-free download

// pinnedClient returns a client that connects to exactly one validated address
// while verifying the certificate for the hostname. There is no second
// resolution and redirects are not followed.
func pinnedClient(socksPort int, host string, ip net.IP) *http.Client {
	proxyAddr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", socksPort))
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return profile.DialSOCKS5(ctx, proxyAddr, ip.String(), 443, 8*time.Second)
	}
	transport := &http.Transport{
		Proxy:               nil,
		DialContext:         dial,
		TLSClientConfig:     &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 8 * time.Second,
		DisableKeepAlives:   true,
		DisableCompression:  true,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// downloadResult is the counted outcome of one bounded transfer.
type downloadResult struct {
	Bytes         int64
	Duration      time.Duration
	Mbps          float64
	SupportsRange bool
	// Spent is every payload byte observed across the attempts of one
	// measurement, including attempts that failed or were cancelled. It is
	// what the monthly counter charges; Bytes is only the ranked transfer.
	Spent int64
}

// errRedirected reports that the target answered with a redirect. Redirects are
// never followed: a redirect to an internal host would defeat the deny list.
var errRedirected = errors.New("this target redirected to another host — blocked")

// downloadBounded performs one Range-capped GET against a pinned address and
// counts payload bytes locally. It stops at whichever cap is reached first and
// never parses the body. Counting is at the body reader, so the number is what
// Bypath actually received, not an estimate.
func downloadBounded(ctx context.Context, client *http.Client, rawurl string, capBytes int64, durationCap time.Duration) (downloadResult, error) {
	var res downloadResult
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return res, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=0-%d", capBytes-1))
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "Bypath-speedtest")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return res, errRedirected
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return res, fmt.Errorf("this target answered HTTP %d", resp.StatusCode)
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		return res, errors.New("this target compressed the response despite an identity request")
	}
	res.SupportsRange = resp.StatusCode == http.StatusPartialContent
	deadline := start.Add(durationCap)
	buf := make([]byte, 32<<10)
	for res.Bytes < capBytes {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if durationCap > 0 && time.Now().After(deadline) {
			break
		}
		window := int64(len(buf))
		if left := capBytes - res.Bytes; left < window {
			window = left
		}
		n, err := resp.Body.Read(buf[:window])
		res.Bytes += int64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			return res, err
		}
	}
	res.Duration = time.Since(start)
	if res.Duration > 0 {
		res.Mbps = float64(res.Bytes) * 8 / res.Duration.Seconds() / 1e6
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// Registry

// listSpeedTargets returns the registry with the built-in default when the user
// has not registered any target.
func (s *Local) listSpeedTargets() ([]SpeedTarget, error) {
	if s.layer != nil {
		raw, err := s.layer.Targets()
		if err != nil {
			return nil, asAppError(err, CodeInternal, "reading speed targets")
		}
		out := make([]SpeedTarget, 0, len(raw))
		for _, item := range raw {
			var t SpeedTarget
			if err := json.Unmarshal(item, &t); err != nil {
				continue
			}
			out = append(out, t)
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	return []SpeedTarget{builtInSpeedTarget()}, nil
}

func builtInSpeedTarget() SpeedTarget {
	return SpeedTarget{
		ID:            "default",
		Host:          defaultSpeedTargetHost,
		Path:          defaultSpeedTargetPath,
		URL:           "https://" + defaultSpeedTargetHost + defaultSpeedTargetPath,
		BuiltIn:       true,
		SupportsRange: true,
	}
}

// speedTargetID derives a stable id from the validated host and path.
func speedTargetID(host, path string) string {
	sum := sha256.Sum256([]byte(host + path))
	return "t_" + hex.EncodeToString(sum[:6])
}

// AddSpeedTarget validates and stores one target. IDs are assigned by the
// daemon; the caller never supplies one.
func (s *Local) AddSpeedTarget(ctx context.Context, rawURL string) (SpeedTarget, error) {
	host, path, err := validateSpeedTargetURL(strings.TrimSpace(rawURL))
	if err != nil {
		return SpeedTarget{}, errorf(CodeInvalid, "%s", err.Error())
	}
	if s.layer == nil {
		return SpeedTarget{}, errorf(CodeUnavailable, "the target registry is unavailable")
	}
	current, err := s.listSpeedTargets()
	if err != nil {
		return SpeedTarget{}, err
	}
	stored := make([]SpeedTarget, 0, len(current))
	for _, t := range current {
		if t.BuiltIn {
			continue
		}
		if t.Host == host && t.Path == path {
			return SpeedTarget{}, errorf(CodeConflict, "this target is already registered")
		}
		stored = append(stored, t)
	}
	if len(stored) >= maxSpeedTargets {
		return SpeedTarget{}, errorf(CodeConflict, "at most %d speed targets can be registered", maxSpeedTargets)
	}
	target := SpeedTarget{
		ID:         speedTargetID(host, path),
		Host:       host,
		Path:       path,
		URL:        "https://" + host + path,
		LastStatus: "unchecked",
	}
	items, err := marshalTargets(append(stored, target))
	if err != nil {
		return SpeedTarget{}, errorf(CodeInternal, "encoding the target registry")
	}
	if err := s.layer.SaveTargets(items); err != nil {
		return SpeedTarget{}, asAppError(err, CodeInternal, "saving speed targets")
	}
	return target, nil
}

// DeleteSpeedTarget removes a registered target. The built-in target cannot be
// deleted because it is the validated default.
func (s *Local) DeleteSpeedTarget(ctx context.Context, id string) error {
	if s.layer == nil {
		return errorf(CodeUnavailable, "the target registry is unavailable")
	}
	current, err := s.listSpeedTargets()
	if err != nil {
		return err
	}
	var kept []SpeedTarget
	found := false
	for _, t := range current {
		if t.BuiltIn {
			continue
		}
		if t.ID == id {
			found = true
			continue
		}
		kept = append(kept, t)
	}
	if !found {
		return errorf(CodeNotFound, "no registered target %q", id)
	}
	items, err := marshalTargets(kept)
	if err != nil {
		return errorf(CodeInternal, "encoding the target registry")
	}
	if err := s.layer.SaveTargets(items); err != nil {
		return asAppError(err, CodeInternal, "saving speed targets")
	}
	return nil
}

// ValidateSpeedTarget runs the stage-0 checks now and records the outcome. It
// needs a tested path: the live SOCKS port when connected. It is informational;
// every run validates again.
func (s *Local) ValidateSpeedTarget(ctx context.Context, id string) (SpeedTarget, error) {
	targets, err := s.listSpeedTargets()
	if err != nil {
		return SpeedTarget{}, err
	}
	idx := -1
	for i, t := range targets {
		if t.ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return SpeedTarget{}, errorf(CodeNotFound, "no target %q", id)
	}
	cfg := s.Config()
	if cfg == nil || cfg.Server.SOCKSPort <= 0 {
		return SpeedTarget{}, errorf(CodeUnavailable, "a tested path is required to validate a target")
	}
	live := s.servingNow()
	check := s.checkTargetThroughPath(ctx, cfg.Server.SOCKSPort, targets[idx], live)
	t := targets[idx]
	t.LastCheckedAt = time.Now().UTC().Format(time.RFC3339)
	t.LastResolvedIPs = check.ResolvedIPs
	t.LastRoute = check.Route
	if check.OK {
		t.ValidatedAt = t.LastCheckedAt
		t.LastStatus = "valid"
		if !live {
			t.LastStatus = "valid (isolated path)"
		}
	} else {
		t.LastStatus = check.Reason
	}
	if !t.BuiltIn {
		targets[idx] = t
		items, err := marshalTargets(targets)
		if err != nil {
			return SpeedTarget{}, errorf(CodeInternal, "encoding the target registry")
		}
		if err := s.layer.SaveTargets(items); err != nil {
			return SpeedTarget{}, asAppError(err, CodeInternal, "saving speed targets")
		}
	}
	return t, nil
}

func marshalTargets(targets []SpeedTarget) ([]json.RawMessage, error) {
	stored := make([]SpeedTarget, 0, len(targets))
	for _, t := range targets {
		if !t.BuiltIn {
			stored = append(stored, t)
		}
	}
	out := make([]json.RawMessage, 0, len(stored))
	for _, t := range stored {
		data, err := json.Marshal(t)
		if err != nil {
			return nil, err
		}
		out = append(out, json.RawMessage(data))
	}
	return out, nil
}

// servingNow reports whether a tunnel is connected; the live path is the only
// path that applies the routing policy.
func (s *Local) servingNow() bool {
	if s.runtime == nil {
		return false
	}
	return s.runtime.Status().State == "CONNECTED"
}

// speedBudget resolves the configured limits with the hard maxima.
func speedBudget(cfg *config.Config) (perLink, perBatch, monthly int64) {
	perLink = 10 << 20
	perBatch = 40 << 20
	if cfg != nil {
		if cfg.Tests.SpeedPerLinkMB > 0 {
			perLink = int64(cfg.Tests.SpeedPerLinkMB) << 20
		}
		if cfg.Tests.SpeedPerBatchMB > 0 {
			perBatch = int64(cfg.Tests.SpeedPerBatchMB) << 20
		}
		if cfg.Tests.MonthlyBudgetMB > 0 {
			monthly = int64(cfg.Tests.MonthlyBudgetMB) << 20
		}
	}
	const maxLink, maxBatch = 100 << 20, 300 << 20
	if perLink > maxLink {
		perLink = maxLink
	}
	if perBatch > maxBatch {
		perBatch = maxBatch
	}
	if perBatch < perLink {
		perBatch = perLink
	}
	return perLink, perBatch, monthly
}

// budgetLinkCount is how many links a serial throughput batch may start. The
// rest are reported Skipped ("budget reached"), never Failed.
func budgetLinkCount(links int, perLink, perBatch int64) int {
	if perLink <= 0 {
		return links
	}
	allowed := int(perBatch / perLink)
	if allowed > links {
		allowed = links
	}
	if allowed < 0 {
		allowed = 0
	}
	return allowed
}

// addCountedBytes records locally counted payload bytes in the monthly counter.
func (s *Local) addCountedBytes(bytes int64) layer.Usage {
	if s.layer == nil || bytes <= 0 {
		return layer.Usage{}
	}
	usage, err := s.layer.AddUsage(time.Now().UTC().Format("2006-01"), bytes)
	if err != nil {
		return layer.Usage{}
	}
	return usage
}

// BudgetFor describes the traffic a run would use before it starts.
func (s *Local) BudgetFor(ctx context.Context, req TestRequest) (TestBudget, error) {
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	if kind == "" {
		kind = TestKindLatency
	}
	if kind != TestKindLatency && kind != TestKindSpeed {
		return TestBudget{}, errorf(CodeInvalid, "unsupported test kind %q", req.Kind)
	}
	targets, _, err := s.resolveTestTargets(req)
	if err != nil {
		return TestBudget{}, err
	}
	perLink, perBatch, monthly := speedBudget(s.Config())
	links := len(targets)
	out := TestBudget{
		Kind:          kind,
		Links:         links,
		PerLinkMB:     int(perLink >> 20),
		PerBatchMB:    int(perBatch >> 20),
		MonthlyCapMB:  int(monthly >> 20),
		UploadEnabled: false,
		CheckNote:     "the target is checked again when the test starts",
	}
	if s.layer != nil {
		if usage, err := s.layer.Usage(); err == nil && usage.Month == time.Now().UTC().Format("2006-01") {
			out.MonthUsedMB = int(usage.Bytes >> 20)
		}
	}
	if kind == TestKindSpeed {
		list, err := s.listSpeedTargets()
		if err != nil {
			return TestBudget{}, err
		}
		if len(list) > 0 {
			out.Target = list[0].Host
			out.TargetURL = list[0].URL
			out.RouteCheck = list[0].LastRoute
		}
		worst := int64(links) * perLink
		if worst > perBatch {
			worst = perBatch
		}
		out.WorstCaseMB = int(worst >> 20)
	} else {
		// Latency runs are small: five requests per link.
		out.WorstCaseMB = 0
		out.CheckNote = "latency runs use a few small requests per connection"
	}
	return out, nil
}

// UsageInfo returns the counted-byte counter with the wording that keeps it
// honest.
func (s *Local) UsageInfo(ctx context.Context) (SpeedUsage, error) {
	_, _, monthly := speedBudget(s.Config())
	out := SpeedUsage{
		Month:        time.Now().UTC().Format("2006-01"),
		MonthlyCapMB: int(monthly >> 20),
		Label:        "payload bytes counted by Bypath; protocol overhead and retransmits are not included",
	}
	if s.layer == nil {
		return out, nil
	}
	usage, err := s.layer.Usage()
	if err != nil {
		return out, asAppError(err, CodeInternal, "reading the byte counter")
	}
	if usage.Month == out.Month {
		out.Bytes = usage.Bytes
	}
	return out, nil
}

// SpeedTargets lists the registry for the frontends.
func (s *Local) SpeedTargets(ctx context.Context) ([]SpeedTarget, error) {
	return s.listSpeedTargets()
}

// TestBudget exposes BudgetFor under the contract name.
func (s *Local) TestBudget(ctx context.Context, req TestRequest) (TestBudget, error) {
	return s.BudgetFor(ctx, req)
}
