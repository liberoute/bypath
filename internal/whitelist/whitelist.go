package whitelist

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/liberoute/bypath/internal/config"
)

// Manager handles country-based IP whitelisting.
// Whitelisted IPs are routed directly (bypass tunnel).
type Manager struct {
	config    config.WhitelistConfig
	networks  map[string][]*net.IPNet // country code -> list of CIDRs
	customNets []*net.IPNet
	mu        sync.RWMutex
}

// NewManager creates a new whitelist manager.
func NewManager(cfg config.WhitelistConfig) (*Manager, error) {
	return &Manager{
		config:   cfg,
		networks: make(map[string][]*net.IPNet),
	}, nil
}

// Load reads IP lists from disk for configured countries.
func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	dataDir := filepath.Dir(m.config.CustomFile) // ./data/ips
	if dataDir == "." {
		dataDir = "./data/ips"
	}

	totalLoaded := 0

	for _, country := range m.config.Countries {
		country = strings.TrimSpace(strings.ToLower(country))
		if country == "" {
			continue
		}

		// Look for ipv4_<country>_*.txt files
		pattern := filepath.Join(dataDir, fmt.Sprintf("ipv4_%s_*.txt", country))
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			log.Printf("  ⚠️  No IP list found for country: %s", country)
			continue
		}

		// Use the most recent file (sorted by name, last = newest)
		file := matches[len(matches)-1]
		nets, err := loadCIDRFile(file)
		if err != nil {
			log.Printf("  ⚠️  Error loading %s: %v", file, err)
			continue
		}

		m.networks[country] = nets
		totalLoaded += len(nets)
		log.Printf("  📦 Loaded %d CIDRs for %s from %s", len(nets), country, filepath.Base(file))
	}

	// Load custom whitelist
	if m.config.CustomFile != "" {
		if nets, err := loadCIDRFile(m.config.CustomFile); err == nil {
			m.customNets = nets
			totalLoaded += len(nets)
			log.Printf("  📦 Loaded %d custom CIDRs", len(nets))
		}
	}

	log.Printf("  ✅ Total whitelist CIDRs loaded: %d", totalLoaded)
	return nil
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

// ApplyRouting applies whitelist-based routing rules using iptables + ipset.
// This is Linux-specific.
func (m *Manager) ApplyRouting(iface string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for country, nets := range m.networks {
		setName := fmt.Sprintf("%s-whitelist", country)

		// Create ipset
		runQuiet("ipset", "destroy", setName)
		if err := runQuiet("ipset", "create", setName, "hash:net"); err != nil {
			return fmt.Errorf("creating ipset %s: %w", setName, err)
		}

		// Add CIDRs to ipset
		for _, n := range nets {
			runQuiet("ipset", "add", setName, n.String())
		}

		// Add iptables rules for marking
		markHex := "0x66"
		rules := [][]string{
			// Mark packets destined for whitelisted IPs
			{"iptables", "-t", "mangle", "-A", "PREROUTING", "-i", iface,
				"-m", "set", "--match-set", setName, "dst",
				"-j", "MARK", "--set-xmark", markHex + "/0xff"},
			// Save the mark to connection
			{"iptables", "-t", "mangle", "-A", "PREROUTING", "-i", iface,
				"-m", "set", "--match-set", setName, "dst",
				"-j", "CONNMARK", "--save-mark"},
			// Allow forwarding for whitelisted
			{"iptables", "-I", "FORWARD", "1", "-m", "set", "--match-set", setName, "dst", "-j", "ACCEPT"},
			// Skip NAT for whitelisted
			{"iptables", "-t", "nat", "-I", "PREROUTING", "1", "-i", iface,
				"-m", "set", "--match-set", setName, "dst", "-j", "RETURN"},
		}

		for _, rule := range rules {
			if err := runQuiet(rule[0], rule[1:]...); err != nil {
				log.Printf("  ⚠️  Rule failed: %v", err)
			}
		}

		log.Printf("  ✅ Whitelist routing applied for %s (%d CIDRs)", country, len(nets))
	}

	// Setup policy routing table (use table 200 to not conflict with tun routing on table 100)
	gateway := detectGateway()
	if gateway != "" {
		runQuiet("ip", "rule", "del", "prio", "90")
		runQuiet("ip", "rule", "add", "prio", "90", "fwmark", "0x66/0xff", "lookup", "200")
		runQuiet("ip", "route", "flush", "table", "200")
		runQuiet("ip", "route", "add", "default", "via", gateway, "dev", iface, "table", "200")
		log.Printf("  ✅ Policy routing: fwmark 0x66 → table 200 → via %s", gateway)
	}

	return nil
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

// --- Helpers ---

func loadCIDRFile(path string) ([]*net.IPNet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var nets []*net.IPNet
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Ensure CIDR notation
		if !strings.Contains(line, "/") {
			line += "/32"
		}

		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		nets = append(nets, ipNet)
	}

	return nets, scanner.Err()
}

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
