package gateway

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/liberoute/bypath/internal/profile"
)

// Health evidence codes separate two questions the dashboard used to blur:
// is the tunnel carrying traffic, and could the exit identity be proven. A
// failed identity lookup is not a dead tunnel, and a DIRECT-routed response
// never proves the tunnel carried anything.
const (
	HealthVerified         = "VERIFIED"
	HealthTunnelDown       = "TUNNEL_DOWN"
	HealthDataPathDown     = "DATA_PATH_DOWN"
	HealthExitUnknown      = "EXIT_UNKNOWN"
	HealthUplinkUnverified = "UPLINK_UNVERIFIED"
	HealthExitIsUplink     = "EXIT_IS_UPLINK"
)

// healthIdentityOracles is the set of independent address-echo services used
// to observe both the tunnel exit and the direct uplink. One oracle is not
// enough: a hostname that resolves to several addresses can be reached only
// through some of them, and treating that as "the uplink is unknowable" made a
// healthy tunnel flap between CONNECTED and DEGRADED.
var healthIdentityOracles = []string{
	"https://api.ipify.org",
	"https://ifconfig.me/ip",
	"https://icanhazip.com",
	"https://checkip.amazonaws.com",
}

const (
	healthUserAgent            = "bypath-health-check/1.0"
	healthIdentityTimeout      = 8 * time.Second
	healthIdentityRequestLimit = 6 * time.Second
	healthBodyLimit            = 128
)

// HealthObservation is the raw evidence one health check produced. It is kept
// separate from the verdict so the classification can be tested without a
// network or a live gateway.
type HealthObservation struct {
	DataPathOK     bool
	DataPathDetail string
	Answered       bool
	TargetCount    int
	Exits          []string
	Uplink         []string
	UplinkAttempts int
}

// HealthEvidence is the classified verdict plus the evidence behind it. Code
// is the stable identifier the UI explains; Detail is the operator-facing
// sentence. TunnelAnswered records that the probe endpoints replied through
// the SOCKS port, independently of whether the exit could be identified.
type HealthEvidence struct {
	Code           string
	Detail         string
	TunnelAnswered bool
	ExitIPs        []string
	Uplink         []string
	UplinkAttempts int
}

// Healthy reports whether the evidence certifies the tunnel end to end.
func (ev HealthEvidence) Healthy() bool { return ev.Code == HealthVerified }

// classifyHealth turns observations into one stable code. The ordering is the
// proof chain: a dead data path or an unanswered tunnel is a forwarding
// failure; an answered tunnel with an unknown exit or an unverifiable uplink is
// only an identity-verification failure. Both are reported honestly, and
// neither is ever labelled Healthy.
func classifyHealth(obs HealthObservation) HealthEvidence {
	exits := knownIPs(obs.Exits)
	uplink := knownIPs(obs.Uplink)
	ev := HealthEvidence{
		TunnelAnswered: obs.Answered,
		ExitIPs:        exits,
		Uplink:         uplink,
		UplinkAttempts: obs.UplinkAttempts,
	}
	if !obs.DataPathOK {
		ev.Code = HealthDataPathDown
		ev.Detail = "the local data path is unhealthy"
		if obs.DataPathDetail != "" {
			ev.Detail = "data path unhealthy: " + obs.DataPathDetail
		}
		return ev
	}
	if !obs.Answered {
		ev.Code = HealthTunnelDown
		ev.Detail = fmt.Sprintf("none of %d endpoints responded through the tunnel", obs.TargetCount)
		return ev
	}
	if len(exits) == 0 {
		ev.Code = HealthExitUnknown
		ev.Detail = "the endpoints answered but the tunnel exit could not be verified"
		return ev
	}
	if len(uplink) == 0 {
		ev.Code = HealthUplinkUnverified
		ev.Detail = fmt.Sprintf("the endpoints answered but the direct uplink could not be verified by any of %d identity services", obs.UplinkAttempts)
		return ev
	}
	known := make(map[string]bool, len(uplink))
	for _, ip := range uplink {
		known[ip] = true
	}
	for _, exit := range exits {
		if known[exit] {
			ev.Code = HealthExitIsUplink
			ev.Detail = "the endpoints answered but the exit equals the direct uplink"
			return ev
		}
	}
	ev.Code = HealthVerified
	ev.Detail = ""
	return ev
}

// healthVerdict is the proof rule used by callers that only hold a single exit
// and a direct sample set: a probe response only certifies the tunnel when the
// exit differs from every direct observation. It delegates to classifyHealth
// so the rule lives in exactly one place.
func healthVerdict(answered bool, exit string, direct []string) (bool, string) {
	obs := HealthObservation{
		DataPathOK:     true,
		Answered:       answered,
		TargetCount:    1,
		Uplink:         direct,
		UplinkAttempts: len(direct),
	}
	if answered && exit != "" {
		obs.Exits = []string{exit}
	}
	ev := classifyHealth(obs)
	return ev.Healthy(), ev.Detail
}

// ipFetcher is the internal spelling of IdentityFetcher.
type ipFetcher = IdentityFetcher

// sampleIPs probes every oracle concurrently and returns the answers in oracle
// order. Missing answers stay empty so callers can count attempts and wins.
func sampleIPs(ctx context.Context, targets []string, fetch ipFetcher) []string {
	out := make([]string, len(targets))
	var wg sync.WaitGroup
	for i := range targets {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if ip, err := fetch(ctx, targets[i]); err == nil {
				out[i] = ip
			}
		}(i)
	}
	wg.Wait()
	return out
}

// knownIPs keeps the distinct non-empty answers in oracle order. A rotating
// CGNAT uplink can present several addresses within one check, so the result
// is a set, not a single value.
func knownIPs(samples []string) []string {
	seen := make(map[string]bool, len(samples))
	out := make([]string, 0, len(samples))
	for _, ip := range samples {
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	return out
}

// collectIdentity observes the exit through the SOCKS port and the direct
// uplink at the same time. Both sides use every oracle: identity endpoints
// fail independently, and requiring one specific hostname to answer is what
// produced false DEGRADED states.
func collectIdentity(ctx context.Context, through, direct ipFetcher) (exits, uplink []string, attempts int) {
	ctx, cancel := context.WithTimeout(ctx, healthIdentityTimeout)
	defer cancel()

	var throughSamples, directSamples []string
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		throughSamples = sampleIPs(ctx, healthIdentityOracles, through)
	}()
	go func() {
		defer wg.Done()
		directSamples = sampleIPs(ctx, healthIdentityOracles, direct)
	}()
	wg.Wait()
	return knownIPs(throughSamples), knownIPs(directSamples), len(healthIdentityOracles)
}

// IdentityFetcher asks one oracle for the address it observes. Either side may
// fail without invalidating the other side's evidence.
type IdentityFetcher func(ctx context.Context, target string) (string, error)

// ExitIdentityEvidence is the raw multi-oracle observation used outside the
// periodic health loop, for example before a first-run gateway activation.
// Connectivity is proven separately there, so an empty exit set is evidence
// about identity, not about forwarding.
type ExitIdentityEvidence struct {
	Exits    []string
	Uplink   []string
	Attempts int
}

// CollectExitIdentity samples the tunnel and direct sides concurrently within
// one bounded budget. Attempts counts the oracles offered, not the answers.
func CollectExitIdentity(ctx context.Context, through, direct IdentityFetcher) ExitIdentityEvidence {
	exits, uplink, attempts := collectIdentity(ctx, ipFetcher(through), ipFetcher(direct))
	return ExitIdentityEvidence{Exits: exits, Uplink: uplink, Attempts: attempts}
}

// FetchExitIPThroughProxy observes the address the tunnel exit presents.
func FetchExitIPThroughProxy(ctx context.Context, socksPort int, target string) (string, error) {
	return fetchIPThroughProxy(ctx, socksPort, target)
}

// FetchExitIPDirect observes this host's address without the tunnel.
func FetchExitIPDirect(ctx context.Context, target string) (string, error) {
	return fetchIPDirect(ctx, target)
}

// ClassifyExitIdentity answers only the identity question. Because tunnel
// connectivity is established by the caller, a blocked oracle set is
// EXIT_UNKNOWN rather than TUNNEL_DOWN, and only an observed exit that differs
// from every direct sample is VERIFIED.
func ClassifyExitIdentity(id ExitIdentityEvidence) HealthEvidence {
	exits := knownIPs(id.Exits)
	uplink := knownIPs(id.Uplink)
	ev := HealthEvidence{
		TunnelAnswered: len(exits) > 0,
		ExitIPs:        exits,
		Uplink:         uplink,
		UplinkAttempts: id.Attempts,
	}
	if len(exits) == 0 {
		ev.Code = HealthExitUnknown
		ev.Detail = fmt.Sprintf("no identity service answered through the tunnel (%d tried)", id.Attempts)
		return ev
	}
	if len(uplink) == 0 {
		ev.Code = HealthUplinkUnverified
		ev.Detail = fmt.Sprintf("the tunnel exit was observed but this host's direct address could not be verified by any of %d identity services", id.Attempts)
		return ev
	}
	known := make(map[string]bool, len(uplink))
	for _, ip := range uplink {
		known[ip] = true
	}
	for _, exit := range exits {
		if known[exit] {
			ev.Code = HealthExitIsUplink
			ev.Detail = "the observed exit equals this host's direct address"
			return ev
		}
	}
	ev.Code = HealthVerified
	return ev
}

// observeIdentity runs the real fetchers against this gateway's SOCKS port.
func (gw *Gateway) observeIdentity(ctx context.Context) (exits, uplink []string, attempts int) {
	through := func(ctx context.Context, target string) (string, error) {
		return fetchIPThroughProxy(ctx, gw.socksPort, target)
	}
	direct := fetchIPDirect
	return collectIdentity(ctx, through, direct)
}

func fetchIPThroughProxy(ctx context.Context, socksPort int, target string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, healthIdentityRequestLimit)
	defer cancel()
	body, _, err := profile.GetThroughProxy(ctx, socksPort, target, map[string]string{"User-Agent": healthUserAgent}, healthBodyLimit)
	if err != nil {
		return "", err
	}
	return parseIPBody(body)
}

func fetchIPDirect(ctx context.Context, target string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, healthIdentityRequestLimit)
	defer cancel()
	client := &http.Client{
		Timeout:   healthIdentityRequestLimit,
		Transport: &http.Transport{Proxy: nil},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", healthUserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s answered HTTP %d", target, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, healthBodyLimit))
	if err != nil {
		return "", err
	}
	return parseIPBody(body)
}

func parseIPBody(body []byte) (string, error) {
	value := strings.TrimSpace(string(body))
	ip := net.ParseIP(value)
	if ip == nil {
		return "", fmt.Errorf("the oracle answered %q, not an address", truncate(value, 40))
	}
	return ip.String(), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
