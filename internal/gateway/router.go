package gateway

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/whitelist"
)

// Router handles traffic routing and NAT setup.
// On Linux: uses iptables + ip rule + ipset
// On Windows: uses WinDivert or netsh (future)
type Router struct {
	config    *config.Config
	whitelist *whitelist.Manager
	platform  string
}

// NewRouter creates a new router.
func NewRouter(cfg *config.Config, wl *whitelist.Manager) *Router {
	return &Router{
		config:    cfg,
		whitelist: wl,
		platform:  runtime.GOOS,
	}
}

// Setup configures the system routing.
func (r *Router) Setup() error {
	switch r.platform {
	case "linux":
		return r.setupLinux()
	case "windows":
		return r.setupWindows()
	default:
		return fmt.Errorf("unsupported platform for routing: %s", r.platform)
	}
}

// Cleanup removes routing rules.
func (r *Router) Cleanup() {
	switch r.platform {
	case "linux":
		r.cleanupLinux()
	case "windows":
		r.cleanupWindows()
	}
}

// --- Linux Implementation ---

func (r *Router) setupLinux() error {
	log.Println("  🐧 Setting up Linux routing...")

	// Enable IP forwarding
	if err := runCmd("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return fmt.Errorf("enabling IP forwarding: %w", err)
	}

	iface := r.config.Gateway.Interface
	if iface == "" {
		// Auto-detect default interface
		iface = detectDefaultInterface()
	}

	if iface == "" {
		return fmt.Errorf("could not detect network interface")
	}

	log.Printf("  🌐 Using interface: %s", iface)

	// Setup NAT (masquerade outgoing traffic)
	cmds := [][]string{
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-o", iface, "-j", "MASQUERADE"},
		{"iptables", "-A", "FORWARD", "-i", iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		{"iptables", "-A", "FORWARD", "-j", "ACCEPT"},
	}

	for _, cmd := range cmds {
		if err := runCmd(cmd[0], cmd[1:]...); err != nil {
			log.Printf("  ⚠️  iptables command failed (may already exist): %v", err)
		}
	}

	// Apply whitelist rules if configured
	if len(r.config.Whitelist.Countries) > 0 {
		if err := r.whitelist.ApplyRouting(iface); err != nil {
			log.Printf("  ⚠️  Whitelist routing: %v", err)
		}
	}

	return nil
}

func (r *Router) cleanupLinux() {
	log.Println("  🧹 Cleaning up Linux routing rules...")
	runCmd("iptables", "-t", "nat", "-F")
	runCmd("iptables", "-F", "FORWARD")
}

// --- Windows Implementation ---

func (r *Router) setupWindows() error {
	log.Println("  🪟 Setting up Windows routing...")

	// Enable IP routing via registry
	if err := runCmd("reg", "add",
		`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`,
		"/v", "IPEnableRouter", "/t", "REG_DWORD", "/d", "1", "/f"); err != nil {
		log.Printf("  ⚠️  Could not enable IP routing: %v", err)
	}

	// Enable ICS (Internet Connection Sharing) or use netsh for routing
	// This is a simplified version - full implementation would use WinDivert
	log.Println("  ℹ️  Windows gateway mode requires manual ICS setup or WinDivert driver")

	return nil
}

func (r *Router) cleanupWindows() {
	// Windows cleanup is minimal since we don't flush system rules
	log.Println("  🧹 Windows routing cleanup (no-op)")
}

// --- Helpers ---

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %s (%w)", name, args, string(output), err)
	}
	return nil
}

func detectDefaultInterface() string {
	// Try to detect the default route interface
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return ""
	}

	// Parse "default via X.X.X.X dev ethX ..."
	fields := splitFields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func splitFields(s string) []string {
	var fields []string
	current := ""
	for _, ch := range s {
		if ch == ' ' || ch == '\t' || ch == '\n' {
			if current != "" {
				fields = append(fields, current)
				current = ""
			}
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		fields = append(fields, current)
	}
	return fields
}
