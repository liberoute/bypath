package gateway

import (
	"fmt"
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
// was ACTIVE. Boot enablement is never changed. Ownership is persisted before
// the service is touched; a persistence failure leaves dnsmasq running.
func (gw *Gateway) stopDnsmasq() error {
	// A private network namespace has its own port 53; the host dnsmasq cannot
	// conflict and must not be stopped.
	if networkNamespaceIsolated() {
		return nil
	}
	// A nonstandard listener port does not conflict with dnsmasq's port 53;
	// stopping it anyway would be a silent change to a host DNS service.
	if port := gw.dnsPort; port != 0 && port != 53 {
		return nil
	}
	exists := dnsmasqServiceExists()
	active := false
	if exists {
		active = dnsmasqIsActive()
	}
	gw.dnsmasq.observe(exists, active)

	if !gw.dnsmasq.shouldStop() {
		return nil
	}
	// Record ownership durably before stopping the service so a crash still
	// lets the next run restore exactly what bypath changed.
	st, err := gw.ensureRunState("pending")
	if err != nil {
		log.Printf("  ⚠️  could not record dnsmasq ownership (%v) — leaving dnsmasq running", err)
		return err
	}
	st.DnsmasqStopped = true
	if err := saveGatewayState(st); err != nil {
		st.DnsmasqStopped = false
		log.Printf("  ⚠️  could not record dnsmasq ownership (%v) — leaving dnsmasq running", err)
		return fmt.Errorf("recording dnsmasq ownership: %w", err)
	}
	log.Printf("  ⚠️  dnsmasq is active (conflicts with port 53) — stopping temporarily...")
	if err := systemctlRun("stop", "dnsmasq"); err != nil {
		// The record keeps the ownership flag so recovery retries the restore.
		return fmt.Errorf("stopping dnsmasq: %w", err)
	}
	log.Printf("  ✅ dnsmasq stopped (will restore on bypath stop if it was previously active)")
	return nil
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
