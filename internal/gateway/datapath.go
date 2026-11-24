package gateway

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
)

// dataPathSpec is a lock-free snapshot of the routing contract the watchdog
// verifies. It is copied under mu so the check never races Start/Stop/Reload.
type dataPathSpec struct {
	enabled bool
	native  bool
	iface   string
	subnet  string
}

const dataPathCheckEvery = 2 // watchdog ticks (1 s each)

func (gw *Gateway) dataPathSpecLocked() dataPathSpec {
	spec := dataPathSpec{iface: gw.iface, subnet: gw.subnet}
	if gw.config != nil {
		spec.enabled = gw.config.Gateway.Enabled
	}
	spec.native = gw.nativeTUN
	return spec
}

func (gw *Gateway) dataPathSpec() dataPathSpec {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	return gw.dataPathSpecLocked()
}

// probeDataPath verifies the local forwarding contract, not an upstream HTTP
// endpoint: interface, policy table, fwmark rule and the fail-closed filter
// rule. A live engine alone does not prove that client traffic can flow.
func (gw *Gateway) probeDataPath() (bool, string) {
	return evaluateDataPath(gw.dataPathSpec())
}

func evaluateDataPath(spec dataPathSpec) (bool, string) {
	if !hostFirewallAvailable() || !spec.enabled {
		return true, ""
	}

	link, err := commandOutput("ip", "-brief", "link", "show", "tun0")
	if err != nil {
		return false, "tun0 is missing"
	}
	if !tunLinkUp(link) {
		return false, "tun0 is down"
	}

	// Containment is verified independently of the engine mode. A live tun0
	// proves nothing about forwarded traffic: the chain can be flushed, the jump
	// demoted behind a foreign ACCEPT, or the LAN rule widened to the uplink.
	if ok, detail := verifyForwardContainment(spec); !ok {
		return false, detail
	}
	if ok, detail := verifyIPv6Containment(spec); !ok {
		return false, detail
	}

	if spec.native {
		// sing-box owns the policy table in native mode; the forwarding contract
		// above is what bypath installs and can verify without duplicating the
		// engine's routing.
		return true, ""
	}

	routes, err := commandOutput("ip", "route", "show", "table", "100")
	if err != nil {
		return false, fmt.Sprintf("reading route table 100: %v", err)
	}
	if !hasTunnelDefault(routes, spec.iface) {
		return false, "table 100 has no tunnel default route"
	}
	if !hasBlackholeDefault(routes) {
		return false, "table 100 has no fail-closed blackhole"
	}
	if !hasLANRoute(routes, spec.subnet, spec.iface) {
		return false, "table 100 has no LAN route"
	}

	rules, err := commandOutput("ip", "rule", "show")
	if err != nil {
		return false, fmt.Sprintf("reading policy rules: %v", err)
	}
	if !fwmarkRulePresent(rules) {
		return false, "the fwmark 0x1 policy rule is missing"
	}
	return true, ""
}

// chainRule is one effective rule of a bypath chain, reduced to the match keys
// the forwarding contract depends on.
type chainRule struct {
	iface  string
	out    string
	dest   string
	target string
}

// parseChainRules parses "iptables -S <chain>" output. A negated match ("! -d")
// is skipped so it can never be mistaken for the positive form.
func parseChainRules(out, chain string) []chainRule {
	var rules []chainRule
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || f[0] != "-A" || f[1] != chain {
			continue
		}
		var r chainRule
		for i := 2; i+1 < len(f); i++ {
			if f[i] == "!" {
				i++
				continue
			}
			switch f[i] {
			case "-i":
				r.iface = f[i+1]
			case "-o":
				r.out = f[i+1]
			case "-d":
				r.dest = f[i+1]
			case "-j":
				r.target = f[i+1]
			}
		}
		rules = append(rules, r)
	}
	return rules
}

func sameSubnet(a, b string) bool {
	_, na, errA := net.ParseCIDR(strings.TrimSpace(a))
	_, nb, errB := net.ParseCIDR(strings.TrimSpace(b))
	if errA != nil || errB != nil {
		return false
	}
	return na.String() == nb.String()
}

// verifyForwardContainment proves the effective IPv4 forwarding policy, not the
// command strings that were generated. It fails when the chain, the catch-all
// DROP, the destination-scoped LAN allowance or the tun0 allowance is missing,
// when the chain is not first in FORWARD, or when a same-interface ACCEPT is
// present: on a single-NIC router that rule accepts LAN-to-WAN traffic, which is
// the exact path a dead tunnel must leave closed.
func verifyForwardContainment(spec dataPathSpec) (bool, string) {
	exists, err := chainExists("filter", chainForward)
	if err != nil {
		return false, fmt.Sprintf("inspecting %s: %v", chainForward, err)
	}
	if !exists {
		return false, fmt.Sprintf("the %s chain is missing", chainForward)
	}
	out, err := commandOutput("iptables", "-t", "filter", "-S", chainForward)
	if err != nil {
		return false, fmt.Sprintf("reading %s: %v", chainForward, err)
	}
	var tunnelAccept, lanAccept, drop bool
	for _, r := range parseChainRules(out, chainForward) {
		if spec.iface != "" && r.iface != spec.iface {
			continue
		}
		switch {
		case r.target == "ACCEPT" && spec.iface != "" && r.out == spec.iface:
			return false, "the FORWARD chain accepts same-interface traffic, which on a single-NIC router leaves through the WAN"
		case r.target == "ACCEPT" && r.out == "tun0":
			tunnelAccept = true
		case r.target == "ACCEPT" && r.dest != "" && sameSubnet(r.dest, spec.subnet):
			lanAccept = true
		case r.target == "DROP" && r.out == "":
			drop = true
		}
	}
	if !drop {
		return false, "the fail-closed FORWARD drop rule is missing"
	}
	if !lanAccept {
		return false, "the LAN-scoped forwarding rule is missing"
	}
	if !tunnelAccept {
		return false, "the tunnel forwarding rule is missing"
	}
	if err := verifyJumpFirst("iptables", "filter", "FORWARD", chainForward); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// verifyIPv6Containment proves forwarded IPv6 from the LAN is still dropped.
// Without it a dual-stack client bypasses the IPv4-only tunnel entirely.
func verifyIPv6Containment(spec dataPathSpec) (bool, string) {
	exists, err := chainExists6("filter", chainV6Drop)
	if err != nil {
		return false, fmt.Sprintf("inspecting %s: %v", chainV6Drop, err)
	}
	if !exists {
		return false, fmt.Sprintf("the %s chain is missing", chainV6Drop)
	}
	out, err := commandOutput("ip6tables", "-t", "filter", "-S", chainV6Drop)
	if err != nil {
		return false, fmt.Sprintf("reading %s: %v", chainV6Drop, err)
	}
	drop := false
	for _, r := range parseChainRules(out, chainV6Drop) {
		if spec.iface != "" && r.iface != spec.iface {
			continue
		}
		if r.target == "DROP" && r.out == "" {
			drop = true
		}
	}
	if !drop {
		return false, "the IPv6 containment drop rule is missing"
	}
	if err := verifyJump6First("filter", "FORWARD", chainV6Drop); err != nil {
		return false, err.Error()
	}
	return true, ""
}

func tunLinkUp(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "tun0") && !strings.Contains(line, " tun0") {
			continue
		}
		if strings.Contains(line, "DOWN") || strings.Contains(line, "NO-CARRIER") {
			return false
		}
		return true
	}
	return false
}

func hasTunnelDefault(routes, iface string) bool {
	for _, line := range strings.Split(routes, "\n") {
		f := strings.Fields(line)
		// A plain added route prints as "default via 10.0.0.1 dev tun0" (five
		// fields); attributes such as proto/metric only add more.
		if len(f) < 5 || f[0] != "default" {
			continue
		}
		via, dev := "", ""
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "via":
				via = f[i+1]
			case "dev":
				dev = f[i+1]
			}
		}
		if via == "10.0.0.1" && dev == "tun0" {
			return true
		}
	}
	return false
}

func hasBlackholeDefault(routes string) bool {
	for _, line := range strings.Split(routes, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "blackhole" && f[1] == "default" {
			return true
		}
	}
	return false
}

func hasLANRoute(routes, subnet, iface string) bool {
	for _, line := range strings.Split(routes, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || (f[0] != subnet && !strings.HasPrefix(f[0], subnet)) {
			continue
		}
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "dev" && f[i+1] == iface {
				return true
			}
		}
	}
	return false
}

// repairDataPath restores only state bypath owns. Fail-closed is re-asserted
// first, so a repair that cannot finish still leaves marked traffic dropped.
func (gw *Gateway) repairDataPath() (bool, error) {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	return gw.repairDataPathLocked()
}

func (gw *Gateway) repairDataPathLocked() (bool, error) {
	if gw.isStopping() {
		return false, context.Canceled
	}
	spec := gw.dataPathSpecLocked()
	ensureFailClosed(spec)

	healthy, _ := evaluateDataPath(spec)
	if healthy {
		return false, nil
	}
	if spec.native {
		// In native mode the engine owns the device; a second tun2socks on the
		// same name would fight sing-box for it. Let recovery restart the engine.
		return false, fmt.Errorf("native TUN interface is unhealthy")
	}

	restarted := false
	link, linkErr := commandOutput("ip", "-brief", "link", "show", "tun0")
	if linkErr != nil || !tunLinkUp(link) {
		log.Printf("🔄 Recreating tun0 and tun2socks...")
		if err := gw.restartTunPathLocked(); err != nil {
			return false, err
		}
		restarted = true
	}
	if err := gw.restoreLegacyRoutes(); err != nil {
		return restarted, err
	}
	// The device, the routes and the rule are separate pieces of host state;
	// any of them can be removed independently, so all are re-asserted.
	st, err := gw.ensureRunState("legacy")
	if err != nil {
		return restarted, err
	}
	if err := gw.applyFwmarkRule(st); err != nil {
		return restarted, err
	}
	ensureFailClosed(spec)
	return restarted, nil
}

// ensureFailClosed re-asserts the forwarding contract in both engine modes.
// The blackhole route is legacy-only because sing-box owns the policy table in
// native mode, but the IPv4 chain, its head jump and the IPv6 containment are
// bypath's in either mode and are restored first, so a repair that cannot
// finish still leaves forwarded traffic dropped. All operations are idempotent.
func ensureFailClosed(spec dataPathSpec) {
	if !hostFirewallAvailable() || !spec.enabled {
		return
	}
	if !spec.native {
		if err := run("ip", "route", "replace", "blackhole", "default", "metric", "4096", "table", "100"); err != nil {
			log.Printf("⚠️  Could not re-assert the fail-closed blackhole: %v", err)
		}
	}
	restoreForwardContainment(spec)
	restoreIPv6Containment(spec)
}

// restoreForwardContainment re-adds only the missing rules of the bypath chain,
// in their original order: tunnel allowance, LAN allowance, catch-all DROP last.
// An existing rule is never rewritten, so a correct chain is left untouched.
func restoreForwardContainment(spec dataPathSpec) {
	if strings.TrimSpace(spec.iface) == "" {
		log.Printf("⚠️  Could not re-assert fail-closed forwarding: the LAN interface is unknown")
		return
	}
	if err := ensureChainE("filter", chainForward); err != nil {
		log.Printf("⚠️  Could not re-assert the fail-closed FORWARD chain: %v", err)
		return
	}
	out, err := commandOutput("iptables", "-t", "filter", "-S", chainForward)
	if err != nil {
		log.Printf("⚠️  Could not inspect the fail-closed FORWARD chain: %v", err)
		return
	}
	var tunnelAccept, lanAccept, drop bool
	for _, r := range parseChainRules(out, chainForward) {
		if r.iface != spec.iface {
			continue
		}
		switch r.target {
		case "ACCEPT":
			if r.out == "tun0" {
				tunnelAccept = true
			}
			if r.out == "" && r.dest != "" && sameSubnet(r.dest, spec.subnet) {
				lanAccept = true
			}
		case "DROP":
			if r.out == "" {
				drop = true
			}
		}
	}
	if !tunnelAccept {
		if err := run("iptables", "-A", chainForward, "-i", spec.iface, "-o", "tun0", "-j", "ACCEPT"); err != nil {
			log.Printf("⚠️  Could not re-assert the tunnel forwarding rule: %v", err)
		}
	}
	if !lanAccept {
		if args, err := lanForwardArgs(spec.iface, spec.subnet); err != nil {
			log.Printf("⚠️  Could not re-assert the LAN forwarding rule: %v", err)
		} else if err := run("iptables", append([]string{"-A", chainForward}, args...)...); err != nil {
			log.Printf("⚠️  Could not re-assert the LAN forwarding rule: %v", err)
		}
	}
	if !drop {
		if err := run("iptables", "-A", chainForward, "-i", spec.iface, "-j", "DROP"); err != nil {
			log.Printf("⚠️  Could not re-assert the fail-closed FORWARD rule: %v", err)
		}
	}
	if err := ensureJumpFirst("iptables", "filter", "FORWARD", chainForward); err != nil {
		log.Printf("⚠️  Could not re-assert the fail-closed FORWARD jump: %v", err)
	}
}

// restoreIPv6Containment re-asserts the dual-stack block. A missing chain would
// otherwise let forwarded IPv6 leave through the host route, which is a bypass
// rather than a degraded tunnel.
func restoreIPv6Containment(spec dataPathSpec) {
	if strings.TrimSpace(spec.iface) == "" {
		return
	}
	if err := ensureChain6E("filter", chainV6Drop); err != nil {
		log.Printf("⚠️  Could not re-assert the IPv6 containment chain: %v", err)
		return
	}
	out, err := commandOutput("ip6tables", "-t", "filter", "-S", chainV6Drop)
	if err != nil {
		log.Printf("⚠️  Could not inspect the IPv6 containment chain: %v", err)
		return
	}
	present := false
	for _, r := range parseChainRules(out, chainV6Drop) {
		if r.iface == spec.iface && r.target == "DROP" && r.out == "" {
			present = true
		}
	}
	if !present {
		for _, rule := range ipv6IsolationRules(spec.iface) {
			if err := run(rule[0], rule[1:]...); err != nil {
				log.Printf("⚠️  Could not re-assert the IPv6 containment rule: %v", err)
				return
			}
		}
	}
	if err := ensureJumpFirst("ip6tables", "filter", "FORWARD", chainV6Drop); err != nil {
		log.Printf("⚠️  Could not re-assert the IPv6 containment jump: %v", err)
	}
}

// recoverDataPath repairs the local forwarding chain with a bounded number of
// attempts. A data-path-only failure never restarts the engine until the local
// attempts are exhausted.
func (gw *Gateway) recoverDataPath(reason string) bool {
	for attempt := 1; attempt <= maxTunRecoveryAttempts; attempt++ {
		if attempt > 1 && !gw.sleepRecovery(recoveryBackoff(attempt-1)) {
			return false
		}
		if gw.isStopping() {
			return false
		}
		gw.setRuntimeAttempt(StateRecovering, attempt, reason)
		log.Printf("🔄 Restoring the gateway data path (attempt %d/%d): %s", attempt, maxTunRecoveryAttempts, reason)

		restarted, err := callRepairDataPath(gw)
		if err == nil {
			if healthy, detail := callDataPathProbe(gw); !healthy {
				err = fmt.Errorf("data path still unhealthy: %s", detail)
			}
		}
		if err == nil {
			if restarted {
				gw.rtMu.Lock()
				gw.runtime.TunRestarts++
				gw.rtMu.Unlock()
			}
			gw.setRuntimeState(StateConnected, "")
			log.Printf("✅ Gateway data path restored")
			return true
		}
		log.Printf("  ❌ Data-path repair failed: %v", err)
	}
	log.Printf("⚠️  Data-path recovery exhausted — restarting the tunnel engine")
	return callEngineRecovery(gw, reason)
}
