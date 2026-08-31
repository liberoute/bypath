package gateway

import (
	"log"
	"os/exec"
	"strings"
)

// dnsmasqPriorState records whether systemd's dnsmasq.service existed and was
// ACTIVE before this Gateway instance took port 53. Restoration on Stop must
// use this captured runtime state, never is-enabled / boot policy.
type dnsmasqPriorState struct {
	captured  bool
	exists    bool
	wasActive bool
}

func (s *dnsmasqPriorState) observe(exists, active bool) {
	if s.captured {
		return
	}
	s.captured = true
	s.exists = exists
	s.wasActive = exists && active
}

func (s *dnsmasqPriorState) shouldStop() bool {
	return s.exists && s.wasActive
}

func (s *dnsmasqPriorState) shouldRestore() bool {
	return s.exists && s.wasActive
}

// systemctlOutput / systemctlRun are overridable so tests do not invoke the host systemd.
var systemctlOutput = func(args ...string) ([]byte, error) {
	return exec.Command("systemctl", args...).CombinedOutput()
}

var systemctlRun = func(args ...string) error {
	return exec.Command("systemctl", args...).Run()
}

func dnsmasqServiceExists() bool {
	return systemctlRun("cat", "dnsmasq") == nil
}

func dnsmasqIsActive() bool {
	out, err := systemctlOutput("is-active", "dnsmasq")
	status := strings.TrimSpace(string(out))
	if status == "active" {
		return true
	}
	_ = err // inactive/failed/unknown return non-zero; that is not a fatal error
	return false
}

// stopDnsmasq captures prior runtime state once, then stops dnsmasq only if it
// was ACTIVE. Boot enablement is never changed.
func (gw *Gateway) stopDnsmasq() {
	exists := dnsmasqServiceExists()
	active := false
	if exists {
		active = dnsmasqIsActive()
	}
	gw.dnsmasq.observe(exists, active)

	if !gw.dnsmasq.shouldStop() {
		return
	}
	log.Printf("  ⚠️  dnsmasq is active (conflicts with port 53) — stopping temporarily...")
	_ = systemctlRun("stop", "dnsmasq")
	log.Printf("  ✅ dnsmasq stopped (will restore on bypath stop if it was previously active)")
}

// restoreDnsmasq starts dnsmasq only when this instance observed it ACTIVE
// before taking control. Inactive or absent units are left alone.
func (gw *Gateway) restoreDnsmasq() {
	if !gw.dnsmasq.shouldRestore() {
		return
	}
	_ = systemctlRun("start", "dnsmasq")
	log.Printf("🔀 dnsmasq restored (was active before bypath)")
}
