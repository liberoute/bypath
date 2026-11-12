package gateway

import (
	"context"
	"fmt"
	"log"
	"runtime"
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
	if runtime.GOOS != "linux" || !spec.enabled {
		return true, ""
	}

	link, err := commandOutput("ip", "-brief", "link", "show", "tun0")
	if err != nil {
		return false, "tun0 is missing"
	}
	if !tunLinkUp(link) {
		return false, "tun0 is down"
	}
	if spec.native {
		// sing-box owns the policy table in native mode; the interface is the
		// contract bypath can verify without duplicating the engine's routing.
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

	present, err := iptablesQuery("iptables", "-C", chainForward, "-i", spec.iface, "-j", "DROP")
	if err != nil {
		return false, fmt.Sprintf("inspecting the fail-closed FORWARD rule: %v", err)
	}
	if !present {
		return false, "the fail-closed FORWARD drop rule is missing"
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

// ensureFailClosed re-asserts the blackhole route and the filter catch-all.
// Both operations are idempotent and never touch traffic bypath does not own.
func ensureFailClosed(spec dataPathSpec) {
	if runtime.GOOS != "linux" || !spec.enabled || spec.native {
		return
	}
	if err := run("ip", "route", "replace", "blackhole", "default", "metric", "4096", "table", "100"); err != nil {
		log.Printf("⚠️  Could not re-assert the fail-closed blackhole: %v", err)
	}
	present, err := iptablesQuery("iptables", "-C", chainForward, "-i", spec.iface, "-j", "DROP")
	if err != nil || present {
		return
	}
	if err := run("iptables", "-A", chainForward, "-i", spec.iface, "-j", "DROP"); err != nil {
		log.Printf("⚠️  Could not re-assert the fail-closed FORWARD rule: %v", err)
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
