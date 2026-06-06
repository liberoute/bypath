package whitelist

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"

	"github.com/liberoute/bypath/internal/config"
)

// Manager handles country-based IP whitelisting.
// Note: Primary whitelist routing is now handled inside sing-box via geoip rule_set.
// This manager is kept for legacy ipset-based routing and API stats.
type Manager struct {
	config     config.WhitelistConfig
	networks   map[string][]*net.IPNet
	customNets []*net.IPNet
	mu         sync.RWMutex
}

// NewManager creates a new whitelist manager.
func NewManager(cfg config.WhitelistConfig) (*Manager, error) {
	return &Manager{
		config:   cfg,
		networks: make(map[string][]*net.IPNet),
	}, nil
}

// IsWhitelisted checks if an IP is in the whitelist.
func (m *Manager) IsWhitelisted(ip net.IP) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, nets := range m.networks {
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
	}

	for _, n := range m.customNets {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}

// UpdateConfig replaces the whitelist config at runtime (hot-reload).
func (m *Manager) UpdateConfig(cfg config.WhitelistConfig) {
	m.mu.Lock()
	m.config = cfg
	m.mu.Unlock()
}

// GetStats returns whitelist statistics.
func (m *Manager) GetStats() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := make(map[string]int)
	for country, nets := range m.networks {
		stats[country] = len(nets)
	}
	if len(m.customNets) > 0 {
		stats["custom"] = len(m.customNets)
	}
	return stats
}

// ApplyRouting applies whitelist-based routing rules using iptables + ipset.
// Legacy method — primary whitelist is now in sing-box geoip route rules.
func (m *Manager) ApplyRouting(iface string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if len(m.networks) == 0 {
		return nil
	}

	for country, nets := range m.networks {
		setName := fmt.Sprintf("%s-whitelist", country)

		runQuiet("ipset", "destroy", setName)
		if err := runQuiet("ipset", "create", setName, "hash:net"); err != nil {
			return fmt.Errorf("creating ipset %s: %w", setName, err)
		}

		for _, n := range nets {
			runQuiet("ipset", "add", setName, n.String())
		}

		log.Printf("  ✅ Whitelist routing applied for %s (%d CIDRs)", country, len(nets))
	}

	gateway := detectGateway()
	if gateway != "" {
		runQuiet("ip", "rule", "del", "prio", "90")
		runQuiet("ip", "rule", "add", "prio", "90", "fwmark", "0x66/0xff", "lookup", "200")
		runQuiet("ip", "route", "flush", "table", "200")
		runQuiet("ip", "route", "add", "default", "via", gateway, "dev", iface, "table", "200")
	}

	return nil
}

// --- Helpers ---

func detectGateway() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func runQuiet(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	_, err := cmd.CombinedOutput()
	return err
}
