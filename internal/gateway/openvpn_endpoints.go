package gateway

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/liberoute/bypath/internal/openvpn"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/tunnel"
)

// openVPNProbeTimeout bounds the TCP reachability check for one endpoint.
// It only has to distinguish "answers" from "blackholed", so it stays short:
// the real validation is the HTTPS probe the engine readiness check performs
// through the finished tunnel.
const openVPNProbeTimeout = 4 * time.Second

// lookupServerAddresses is a seam for tests: endpoint validation must not
// depend on the lab's DNS or the public internet.
var lookupServerAddresses = (*Gateway).resolveHostDirectAll

// lookupServerAddressesFrom queries one specific upstream. It backs the
// alternate-endpoint sample: every configured resolver can be handed a
// different OpenVPN round-robin entry.
var lookupServerAddressesFrom = (*Gateway).resolveHostFromUpstream

// probeOpenVPNEndpoint is a seam for tests: a TCP connect to the candidate
// proves the address answers at all.
var probeOpenVPNEndpoint = func(ctx context.Context, addr string, timeout time.Duration) error {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// endpointCandidate is one dialable address for an OpenVPN remote. Network is
// the remote's transport (tcp/udp); UDP candidates carry no probe result
// because a TCP connect says nothing about them.
type endpointCandidate struct {
	Host      string
	IP        string
	Port      int
	Network   string
	Probed    bool
	Reachable bool
	Probe     string
}

func (c endpointCandidate) String() string {
	if c.Port > 0 {
		return fmt.Sprintf("%s %s:%d", c.IP, c.Network, c.Port)
	}
	return fmt.Sprintf("%s %s", c.IP, c.Network)
}

// profilesDirectory is where packaged .ovpn files live. The configured path
// wins; installed mode falls back to the paths package.
func (gw *Gateway) profilesDirectory() string {
	if gw.config != nil && gw.config.Profiles.Directory != "" {
		return gw.config.Profiles.Directory
	}
	return paths.Get().ProfileDir
}

// pinnedHostSetsFor resolves the server addresses the engine must dial. Most
// links have exactly one pin set; an OpenVPN link returns the primary set plus
// one alternate per additional validated address, because a TCP-reachable
// endpoint can still never complete an OpenVPN handshake.
func (gw *Gateway) pinnedHostSetsFor(ctx context.Context, link *profile.Link) []map[string]string {
	if link.Protocol == "openvpn" {
		return gw.openVPNPinSets(ctx, link)
	}
	pins := map[string]string{}
	if link.Address != "" {
		if ip := gw.resolveHostDirect(ctx, link.Address); ip != "" {
			pins[link.Address] = ip
		}
	}
	return []map[string]string{pins}
}

// openVPNPinSets prepares the ordered pin maps for an OpenVPN link. Set 0 is
// the validated primary; later sets swap in the next address for one remote so
// the caller can retry the link without regenerating a bad endpoint forever.
// When the profile cannot be read the pins are empty and the engine resolves
// the remotes itself; the failure then surfaces from config generation with
// the profile path in the message.
func (gw *Gateway) openVPNPinSets(ctx context.Context, link *profile.Link) []map[string]string {
	cands, err := gw.openVPNEndpointCandidates(ctx, link)
	if err != nil {
		log.Printf("⚠️  OpenVPN endpoint preflight for %q failed: %v — the engine will resolve its remotes", link.Remark, err)
		return []map[string]string{nil}
	}
	var hosts []string
	byHost := map[string][]string{}
	for _, c := range cands {
		if _, ok := byHost[c.Host]; !ok {
			hosts = append(hosts, c.Host)
		}
		byHost[c.Host] = append(byHost[c.Host], c.IP)
	}
	maxSets := 1
	for _, host := range hosts {
		if n := len(byHost[host]); n > maxSets {
			maxSets = n
		}
	}
	if maxSets > openVPNMaxEndpointCandidates {
		maxSets = openVPNMaxEndpointCandidates
	}

	// A link address that is not a profile remote (imports record whichever
	// host the URI carried) still needs to resolve without the host resolver.
	extraHost, extraIP := "", ""
	if link.Address != "" {
		if _, ok := byHost[link.Address]; !ok && net.ParseIP(link.Address) == nil {
			if ip := gw.resolveHostDirect(ctx, link.Address); ip != "" {
				extraHost, extraIP = link.Address, ip
			}
		}
	}

	sets := make([]map[string]string, 0, maxSets)
	for i := 0; i < maxSets; i++ {
		pins := map[string]string{}
		for _, host := range hosts {
			ips := byHost[host]
			idx := i
			if idx >= len(ips) {
				idx = len(ips) - 1
			}
			pins[host] = ips[idx]
		}
		if extraHost != "" {
			pins[extraHost] = extraIP
		}
		sets = append(sets, pins)
	}
	gw.logOpenVPNPins(cands, sets[0])
	if len(sets) > 1 {
		log.Printf("  🔁 OpenVPN endpoint failover armed with %d candidates", len(sets))
	}
	return sets
}

// openVPNMaxEndpointCandidates caps how many endpoint addresses per remote are
// collected. Each retry gets a full handshake window, so a larger fan-out
// would consume the whole startup budget on one link.
const openVPNMaxEndpointCandidates = 3

// openVPNMaxEndpointAttempts caps engine starts per OpenVPN link: the primary
// candidate plus one retry. Two windows plus probes fit the link budget.
const openVPNMaxEndpointAttempts = 2

// openVPNServerAddresses gathers endpoint candidates from every configured
// upstream. OpenVPN hands each resolver a different round-robin entry, so a
// second resolver is an independent sample. The primary answer is still
// pinned first; extra samples are only ever alternates.
func (gw *Gateway) openVPNServerAddresses(ctx context.Context, host string) []string {
	primary := lookupServerAddresses(gw, ctx, host)
	out := append([]string{}, primary...)
	seen := make(map[string]bool, len(out))
	for _, ip := range primary {
		seen[ip] = true
	}
	for _, ns := range gw.dnsUpstreams() {
		if len(out) >= openVPNMaxEndpointCandidates || ctx.Err() != nil {
			break
		}
		for _, ip := range lookupServerAddressesFrom(gw, ctx, host, ns) {
			if seen[ip] {
				continue
			}
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}

// pinSetKey identifies one candidate combination so a retry cannot repeat it.
func pinSetKey(pins map[string]string) string {
	keys := make([]string, 0, len(pins))
	for host, ip := range pins {
		keys = append(keys, host+"="+ip)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}

// describePinSet renders a candidate combination for the startup log.
func describePinSet(pins map[string]string) string {
	if len(pins) == 0 {
		return "(engine-resolved)"
	}
	keys := make([]string, 0, len(pins))
	for host, ip := range pins {
		keys = append(keys, host+"="+ip)
	}
	sort.Strings(keys)
	return strings.Join(keys, " ")
}

func (gw *Gateway) logOpenVPNPins(cands []endpointCandidate, primary map[string]string) {
	for _, c := range cands {
		switch {
		case primary[c.Host] == c.IP && c.Probed && c.Reachable:
			log.Printf("  🔎 OpenVPN endpoint %s validated for %s", c, c.Host)
		case primary[c.Host] == c.IP && c.Probed:
			log.Printf("  ⚠️  OpenVPN endpoint %s did not answer (%s) — pinning it anyway", c, probeReason(c))
		case primary[c.Host] != c.IP && c.Probed && !c.Reachable:
			log.Printf("  ⚠️  OpenVPN endpoint %s kept as alternate (%s)", c, probeReason(c))
		}
	}
}

func probeReason(c endpointCandidate) string {
	if c.Probe != "" {
		return c.Probe
	}
	return fmt.Sprintf("no TCP answer on :%d within %s", c.Port, openVPNProbeTimeout)
}

// openVPNEndpointCandidates resolves every remote in the link's packaged
// profile and probes TCP remotes. Reachable candidates come first so the pin
// never lands on an address this host cannot even open a socket to.
func (gw *Gateway) openVPNEndpointCandidates(ctx context.Context, link *profile.Link) ([]endpointCandidate, error) {
	path, err := tunnel.OpenVPNProfilePath(gw.profilesDirectory(), link)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("link %q has no OpenVPN profile reference", link.Remark)
	}
	prof, err := openvpn.ParseFile(path)
	if err != nil {
		return nil, fmt.Errorf("OpenVPN profile for %q: %w", link.Remark, err)
	}

	var cands []endpointCandidate
	seen := map[string]bool{}
	for _, remote := range prof.Remotes {
		host := strings.TrimSpace(remote.Host)
		if host == "" {
			continue
		}
		network := strings.ToLower(strings.TrimSpace(remote.Network))
		if network == "" {
			network = strings.ToLower(strings.TrimSpace(prof.Proto))
		}
		ips := []string{host}
		if net.ParseIP(host) == nil {
			ips = gw.openVPNServerAddresses(ctx, host)
			if len(ips) == 0 {
				log.Printf("  ⚠️  OpenVPN remote %s has no usable address", host)
				continue
			}
		}
		for _, ip := range ips {
			key := fmt.Sprintf("%s|%s|%d", host, ip, remote.Port)
			if seen[key] {
				continue
			}
			seen[key] = true
			cands = append(cands, endpointCandidate{
				Host:    host,
				IP:      ip,
				Port:    remote.Port,
				Network: network,
			})
		}
	}

	gw.probeOpenVPNCandidates(ctx, cands)
	orderOpenVPNCandidates(cands)
	return cands, nil
}

// probeOpenVPNCandidates fills the probe result for TCP remotes. Probes run
// concurrently and in place, so ordering stays deterministic for tests and
// logs while a dead address does not delay the healthy ones.
func (gw *Gateway) probeOpenVPNCandidates(ctx context.Context, cands []endpointCandidate) {
	var wg sync.WaitGroup
	for i := range cands {
		if cands[i].Network != "tcp" || cands[i].Port <= 0 {
			continue
		}
		wg.Add(1)
		go func(c *endpointCandidate) {
			defer wg.Done()
			dialCtx, cancel := context.WithTimeout(ctx, openVPNProbeTimeout)
			defer cancel()
			err := probeOpenVPNEndpoint(dialCtx, net.JoinHostPort(c.IP, strconv.Itoa(c.Port)), openVPNProbeTimeout)
			c.Probed = true
			c.Reachable = err == nil
			if err != nil {
				c.Probe = err.Error()
			}
		}(&cands[i])
	}
	wg.Wait()
}

// orderOpenVPNCandidates is a stable partition: validated addresses first,
// then IPv4 before IPv6, both in resolver order.
func orderOpenVPNCandidates(cands []endpointCandidate) {
	rank := func(c endpointCandidate) int {
		r := 0
		if c.Probed && !c.Reachable {
			r += 2
		}
		if ip := net.ParseIP(c.IP); ip != nil && ip.To4() == nil {
			r++
		}
		return r
	}
	for i := 1; i < len(cands); i++ {
		for j := i; j > 0 && rank(cands[j]) < rank(cands[j-1]); j-- {
			cands[j], cands[j-1] = cands[j-1], cands[j]
		}
	}
}

// usableServerIPs drops addresses that cannot be a real tunnel server and
// orders IPv4 first. A round-robin record that answers with a private or
// loopback address is intercepted DNS, not a server.
func usableServerIPs(addrs []string) []string {
	seen := map[string]bool{}
	var v4, v6 []string
	for _, addr := range addrs {
		addr = strings.TrimSpace(addr)
		if addr == "" || seen[addr] {
			continue
		}
		seen[addr] = true
		ip := net.ParseIP(addr)
		if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() {
			continue
		}
		if ip.To4() != nil {
			v4 = append(v4, addr)
		} else {
			v6 = append(v6, addr)
		}
	}
	return append(v4, v6...)
}
