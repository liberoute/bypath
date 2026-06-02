package gateway

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/tunnel"
	"github.com/liberoute/bypath/internal/whitelist"
)

// Gateway is the main orchestrator. When Start() is called it:
// 1. Starts the tunnel engine (sing-box/xray) with generated config
// 2. Starts DNS proxy (dns2socks or built-in) on port 53
// 3. Starts tun2socks to create a TUN device routed through the SOCKS proxy
// 4. Configures iptables so LAN clients' traffic goes through the TUN
// 5. Applies country whitelist (bypass tunnel for whitelisted IPs)
type Gateway struct {
	config     *config.Config
	engineMgr  *engine.Manager
	tunnelMgr  *tunnel.Manager
	profileMgr *profile.Manager
	whitelist  *whitelist.Manager

	// Running processes
	engineProc  *exec.Cmd
	dnsProc     *exec.Cmd
	tunProc     *exec.Cmd

	// Native TUN state
	nativeTUN bool // whether sing-box native TUN is active

	// Network info (auto-detected)
	iface      string // e.g., "eth0", "end0"
	localIP    string // e.g., "172.16.11.15"
	realGW     string // e.g., "172.16.11.1"
	subnet     string // e.g., "172.16.11.0/24"
	socksPort  int
	dnsPort    int

	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
}

// New creates a new Gateway instance.
func New(cfg *config.Config, engineMgr *engine.Manager) (*Gateway, error) {
	ctx, cancel := context.WithCancel(context.Background())

	profileMgr, err := profile.NewManager(cfg.Profiles.Directory, cfg.Profiles.ActiveGroup)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("initializing profiles: %w", err)
	}

	tunnelMgr := tunnel.NewManager(cfg, engineMgr)

	wlMgr, err := whitelist.NewManager(cfg.Whitelist)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("initializing whitelist: %w", err)
	}

	gw := &Gateway{
		config:     cfg,
		engineMgr:  engineMgr,
		tunnelMgr:  tunnelMgr,
		profileMgr: profileMgr,
		whitelist:  wlMgr,
		socksPort:  cfg.Server.SOCKSPort,
		dnsPort:    cfg.Server.DNSPort,
		ctx:        ctx,
		cancel:     cancel,
	}

	return gw, nil
}

// Start brings up the full gateway stack.
func (gw *Gateway) Start() error {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	// 1. Detect network
	if err := gw.detectNetwork(); err != nil {
		return fmt.Errorf("network detection: %w", err)
	}

	// 2. Get active link
	activeLink := gw.getActiveLink()
	if activeLink == nil {
		return fmt.Errorf("no active link configured. Use 'bypath add <uri>' first")
	}

	// 3. Start tunnel engine (with auto-fallback)
	if err := gw.startEngineWithFallback(activeLink); err != nil {
		return fmt.Errorf("starting engine: %w", err)
	}

	// 4. Native TUN mode vs legacy mode
	if gw.nativeTUN {
		// sing-box handles TUN device and DNS natively — no tun2socks/dns2socks needed
		log.Printf("🚀 Using sing-box native TUN mode (no tun2socks/dns2socks needed)")

		if err := waitForTUNDevice("tun0", 10*time.Second); err != nil {
			// TUN device didn't appear — fall back to legacy mode
			log.Printf("⚠️ sing-box native TUN failed, falling back to legacy mode")
			if err := gw.restartEngineAsLegacy(activeLink); err != nil {
				return fmt.Errorf("fallback to legacy mode failed: %w", err)
			}
			// Continue to legacy mode setup below
		}
	}

	if gw.nativeTUN {
		// Native TUN succeeded — configure routing
		if gw.config.Gateway.Enabled {
			if len(gw.config.Whitelist.Countries) > 0 {
				log.Printf("🌍 Whitelist countries %v → routed direct via sing-box geoip rules", gw.config.Whitelist.Countries)
			}

			if err := gw.setupRouting(); err != nil {
				log.Printf("⚠️  Routing setup failed: %v", err)
			}
		}
	} else {
		// Legacy mode: use tun2socks + dns2socks
		// 4a. Start DNS proxy
		if err := gw.startDNS(); err != nil {
			log.Printf("⚠️  DNS proxy failed: %v (continuing without DNS)", err)
		}

		// 4b. Start tun2socks
		if gw.config.Gateway.Enabled {
			if err := gw.startTun(); err != nil {
				log.Printf("⚠️  TUN setup failed: %v (proxy-only mode)", err)
				log.Printf("ℹ️  Proxy available at socks5://%s:%d", gw.localIP, gw.socksPort)
			} else {
				// Whitelist is now handled inside sing-box via geoip route rules.
				// No ipset/iptables needed. Just log it.
				if len(gw.config.Whitelist.Countries) > 0 {
					log.Printf("🌍 Whitelist countries %v → routed direct via sing-box geoip rules", gw.config.Whitelist.Countries)
				}

				// Setup iptables routing (simple: LAN → tun0, no fwmark whitelist)
				if err := gw.setupRouting(); err != nil {
					log.Printf("⚠️  Routing setup failed: %v", err)
				}
			}
		}
	}

	log.Printf("✅ Gateway running:")
	log.Printf("   Interface:  %s", gw.iface)
	log.Printf("   Local IP:   %s", gw.localIP)
	log.Printf("   SOCKS:      :%d", gw.socksPort)
	log.Printf("   DNS:        :%d", gw.dnsPort)
	log.Printf("   Tunnel:     %s → %s:%d", activeLink.Protocol, activeLink.Address, activeLink.Port)
	if gw.config.Gateway.Enabled {
		log.Printf("   Mode:       GATEWAY (set clients GW+DNS to %s)", gw.localIP)
	} else {
		log.Printf("   Mode:       PROXY ONLY (use socks5://%s:%d)", gw.localIP, gw.socksPort)
	}

	// 8. Auto-start chains with auto_start: true
	gw.startAutoChains()

	return nil
}

// Stop gracefully shuts down everything.
func (gw *Gateway) Stop() {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	log.Println("🛑 Stopping gateway...")

	// Cleanup routing (mode-aware: skips TUN device/fwmark cleanup in native TUN mode)
	gw.cleanupRouting()

	// Stop tun2socks (only exists in legacy mode)
	if gw.tunProc != nil {
		gw.tunProc.Process.Kill()
		gw.tunProc.Wait()
		log.Println("  ✓ tun2socks stopped")
	}

	// Stop DNS (only exists in legacy mode)
	if gw.dnsProc != nil {
		gw.dnsProc.Process.Kill()
		gw.dnsProc.Wait()
		log.Println("  ✓ DNS proxy stopped")
	}

	// Stop engine — in native TUN mode, sing-box removes its TUN device on exit
	if gw.engineProc != nil {
		gw.engineProc.Process.Kill()
		gw.engineProc.Wait()
		log.Println("  ✓ Engine stopped")
	}

	gw.cancel()
	log.Println("✅ Gateway stopped")
}

// --- Internal methods ---

func (gw *Gateway) detectNetwork() error {
	// Auto-detect interface
	iface := gw.config.Gateway.Interface

	if runtime.GOOS == "windows" {
		// On Windows, use ipconfig/netsh
		out, _ := exec.Command("cmd", "/c", "route", "print", "0.0.0.0").Output()
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 5 && fields[0] == "0.0.0.0" {
				gw.realGW = fields[2]
				gw.localIP = fields[3]
				break
			}
		}
		if gw.localIP == "" {
			// Fallback: get from hostname
			addrs, _ := net.InterfaceAddrs()
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
					gw.localIP = ipNet.IP.String()
					gw.subnet = ipNet.String()
					break
				}
			}
		}
		if iface == "" {
			iface = "Ethernet"
		}
		gw.iface = iface
		if gw.localIP == "" {
			gw.localIP = "127.0.0.1"
		}
		if gw.subnet == "" {
			gw.subnet = gw.localIP + "/24"
		}
		log.Printf("🌐 Network: %s | IP: %s | GW: %s (Windows)", gw.iface, gw.localIP, gw.realGW)
		return nil
	}

	// Linux detection
	if iface == "" {
		out, err := exec.Command("ip", "route", "show", "default").Output()
		if err != nil {
			return fmt.Errorf("detecting default route: %w", err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "dev" && i+1 < len(fields) && iface == "" {
					iface = fields[i+1]
				}
				if f == "via" && i+1 < len(fields) && gw.realGW == "" {
					gw.realGW = fields[i+1]
				}
			}
			if iface != "" && gw.realGW != "" {
				break
			}
		}
	} else {
		// Interface specified, detect gateway
		out, _ := exec.Command("ip", "route", "show", "default").Output()
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "via" && i+1 < len(fields) {
					gw.realGW = fields[i+1]
					break
				}
			}
			if gw.realGW != "" {
				break
			}
		}
	}
	if iface == "" {
		return fmt.Errorf("could not detect network interface")
	}
	gw.iface = iface

	// Get local IP
	out, _ := exec.Command("ip", "-4", "addr", "show", iface).Output()
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				ip, ipNet, _ := net.ParseCIDR(parts[1])
				if ip != nil {
					gw.localIP = ip.String()
					gw.subnet = ipNet.String()
				}
			}
		}
	}

	if gw.localIP == "" {
		return fmt.Errorf("could not detect local IP on %s", iface)
	}
	if gw.realGW == "" {
		return fmt.Errorf("could not detect default gateway")
	}

	log.Printf("🌐 Network: %s | IP: %s | GW: %s | Subnet: %s", gw.iface, gw.localIP, gw.realGW, gw.subnet)
	return nil
}

func (gw *Gateway) getActiveLink() *profile.Link {
	// 1. Try persisted active link
	link := gw.profileMgr.GetActiveLink()
	if link != nil {
		return link
	}

	// 2. Fallback: first testable link from any group
	for _, gName := range gw.profileMgr.ListGroups() {
		g, err := gw.profileMgr.GetGroup(gName)
		if err != nil || len(g.Links) == 0 {
			continue
		}
		for _, l := range g.Links {
			if l.Port >= 10 && l.Address != "" && l.Address != "0.0.0.0" {
				return l
			}
		}
	}
	return nil
}

func (gw *Gateway) startEngineWithFallback(link *profile.Link) error {
	// If NativeTUN is disabled, skip native TUN attempt entirely
	if !gw.config.Gateway.NativeTUN {
		gw.nativeTUN = false
		return gw.startEngineWithLinkFallback(link)
	}

	// Attempt native TUN mode
	err := gw.startEngineWithLinkFallback(link)
	if err != nil {
		// sing-box failed to start with TUN config — fall back to legacy mode
		log.Printf("⚠️ sing-box native TUN failed, falling back to legacy mode")
		gw.nativeTUN = false
		return gw.restartEngineAsLegacy(link)
	}

	return nil
}

// restartEngineAsLegacy kills the current engine process (if any), regenerates config
// with GatewayMode=false, and restarts the engine in legacy (mixed-inbound) mode.
func (gw *Gateway) restartEngineAsLegacy(link *profile.Link) error {
	// Kill the failed engine process
	if gw.engineProc != nil {
		gw.engineProc.Process.Kill()
		gw.engineProc.Wait()
		gw.engineProc = nil
	}

	// Temporarily disable NativeTUN so startEngine generates mixed-inbound config
	origNativeTUN := gw.config.Gateway.NativeTUN
	gw.config.Gateway.NativeTUN = false
	defer func() { gw.config.Gateway.NativeTUN = origNativeTUN }()

	gw.nativeTUN = false
	return gw.startEngineWithLinkFallback(link)
}

// startEngineWithLinkFallback tries the given link first, then falls back to other links
// in the same group if the first one fails or can't connect.
func (gw *Gateway) startEngineWithLinkFallback(link *profile.Link) error {
	// Try active link first
	err := gw.startEngine(link)
	if err == nil {
		// Verify it actually connects
		if gw.verifyConnection() {
			return nil
		}
		// Connection failed, stop and try next
		log.Printf("⚠️  Link '%s' started but can't connect, trying next...", link.Remark)
		if gw.engineProc != nil {
			gw.engineProc.Process.Kill()
			gw.engineProc.Wait()
			gw.engineProc = nil
		}
	} else {
		log.Printf("⚠️  Link '%s' failed to start: %v", link.Remark, err)
	}

	// Try other links in the group (use the active link's group, not config default)
	fallbackGroup := link.Group
	if fallbackGroup == "" {
		fallbackGroup = gw.config.Profiles.ActiveGroup
	}
	g, gerr := gw.profileMgr.GetGroup(fallbackGroup)
	if gerr != nil {
		return fmt.Errorf("no working link found (original error: %w)", err)
	}

	for _, candidate := range g.Links {
		if candidate.Remark == link.Remark {
			continue // skip the one we already tried
		}
		// Skip info-only links (port < 10 or address 0.0.0.0)
		if candidate.Port < 10 || candidate.Address == "" || candidate.Address == "0.0.0.0" {
			continue
		}

		log.Printf("🔄 Trying link: [%s] %s → %s:%d", candidate.Protocol, candidate.Remark, candidate.Address, candidate.Port)

		if startErr := gw.startEngine(candidate); startErr != nil {
			log.Printf("  ❌ Failed: %v", startErr)
			continue
		}

		if gw.verifyConnection() {
			log.Printf("  ✅ Connected!")
			gw.profileMgr.SetActiveLink(candidate)
			return nil
		}

		// Didn't work, kill and try next
		log.Printf("  ❌ No connectivity")
		if gw.engineProc != nil {
			gw.engineProc.Process.Kill()
			gw.engineProc.Wait()
			gw.engineProc = nil
		}
	}

	return fmt.Errorf("no working link found in group '%s'", fallbackGroup)
}

// verifyConnection checks if the SOCKS proxy actually works.
// Uses socks5:// (not socks5h://) with a known IP to avoid DNS dependency.
func (gw *Gateway) verifyConnection() bool {
	addr := fmt.Sprintf("socks5://127.0.0.1:%d", gw.socksPort)
	// Use IP directly to avoid DNS dependency (dns2socks may not be up yet)
	// 1.1.1.1:80 is Cloudflare's reliable public IP
	cmd := exec.CommandContext(gw.ctx, "curl", "-s", "-x", addr,
		"--connect-timeout", "10", "-o", "/dev/null", "-w", "%{http_code}",
		"-H", "Host: cp.cloudflare.com",
		"http://1.1.1.1")
	out, err := cmd.Output()
	if err != nil {
		return false
	}
	code := strings.TrimSpace(string(out))
	return code == "200" || code == "204"
}

func (gw *Gateway) startEngine(link *profile.Link) error {
	log.Printf("🔧 Starting engine for [%s] %s...", link.Protocol, link.Remark)

	// Determine engine
	engineName := gw.resolveEngine(link.Protocol)
	eng, err := gw.engineMgr.Get(engineName)
	if err != nil {
		return fmt.Errorf("engine %s not available: %w", engineName, err)
	}

	// Generate config (with whitelist countries for sing-box geoip routing)
	configGen := tunnel.NewConfigGenerator(paths.Get().TmpDir)
	configGen.WhitelistCountries = gw.config.Whitelist.Countries
	configGen.GeositeCountries = gw.config.Whitelist.GeositeCountries
	configGen.BypassDomains = gw.config.Whitelist.BypassDomains
	configGen.SOCKSPort = gw.socksPort
	if gw.config.SNISpoof.Enabled {
		configGen.SNISpoof = gw.config.SNISpoof.SNI
	}
	if gw.config.Gateway.Enabled && gw.config.Gateway.NativeTUN {
		configGen.GatewayMode = true
		configGen.DNSPort = gw.dnsPort
	}
	configFile, err := configGen.Generate(eng, link)
	if err != nil {
		return fmt.Errorf("generating config: %w", err)
	}

	// Start engine process
	var args []string
	switch eng.Name {
	case "sing-box":
		args = []string{"run", "-c", configFile}
	case "xray":
		args = []string{"run", "-c", configFile}
	default:
		args = []string{"-c", configFile}
	}

	gw.engineProc = exec.CommandContext(gw.ctx, eng.Path, args...)
	if err := gw.engineProc.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", eng.Name, err)
	}

	// Wait for port to be ready
	if err := waitForPort(gw.socksPort, 10*time.Second); err != nil {
		return fmt.Errorf("%s didn't start in time: %w", eng.Name, err)
	}

	// Give sing-box a moment to fully initialize outbound connections
	time.Sleep(2 * time.Second)

	log.Printf("  ✅ %s running on :%d (PID: %d)", eng.Name, gw.socksPort, gw.engineProc.Process.Pid)

	// Mark native TUN as active if we started with gateway mode
	if gw.config.Gateway.Enabled && gw.config.Gateway.NativeTUN {
		gw.nativeTUN = true
	}

	return nil
}

func (gw *Gateway) startDNS() error {
	log.Printf("🔀 Starting DNS proxy on :%d...", gw.dnsPort)

	// Try dns2socks first (if available)
	dns2socksPath, err := exec.LookPath("dns2socks")
	if err == nil {
		gw.dnsProc = exec.CommandContext(gw.ctx, dns2socksPath,
			"-l", fmt.Sprintf("0.0.0.0:%d", gw.dnsPort),
			"-d", "1.1.1.1:53",
			"-s", fmt.Sprintf("socks5://127.0.0.1:%d", gw.socksPort),
			"-f", "-c",
		)
		if err := gw.dnsProc.Start(); err != nil {
			return fmt.Errorf("starting dns2socks: %w", err)
		}
		if err := waitForPort(gw.dnsPort, 5*time.Second); err != nil {
			return fmt.Errorf("dns2socks didn't start: %w", err)
		}
		log.Printf("  ✅ dns2socks running on :%d (DNS through tunnel)", gw.dnsPort)
		return nil
	}

	// Fallback: dnsmasq
	dnsmasqPath, err := exec.LookPath("dnsmasq")
	if err == nil {
		// dnsmasq can't route through SOCKS, but at least provides DNS
		gw.dnsProc = exec.CommandContext(gw.ctx, dnsmasqPath,
			"--no-daemon", "--no-resolv",
			"--server=1.1.1.1", "--server=8.8.8.8",
			fmt.Sprintf("--listen-address=0.0.0.0"),
			"--bind-interfaces",
		)
		if err := gw.dnsProc.Start(); err != nil {
			return fmt.Errorf("starting dnsmasq: %w", err)
		}
		log.Printf("  ⚠️  dnsmasq running (DNS NOT through tunnel — install dns2socks for secure DNS)")
		return nil
	}

	return fmt.Errorf("no DNS proxy available (install dns2socks or dnsmasq)")
}

func (gw *Gateway) startTun() error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("TUN gateway mode not supported on Windows (use proxy mode)")
	}

	log.Printf("🔧 Setting up TUN device...")

	// Check for tun2socks
	tunPath, err := exec.LookPath("tun2socks")
	if err != nil {
		return fmt.Errorf("tun2socks not found (install it for gateway mode)")
	}

	// Remove old TUN if exists
	run("ip", "link", "del", "tun0")
	time.Sleep(500 * time.Millisecond)

	// Create TUN
	if err := run("ip", "tuntap", "add", "mode", "tun", "dev", "tun0"); err != nil {
		return fmt.Errorf("creating tun0: %w", err)
	}
	if err := run("ip", "addr", "add", "10.0.0.1/24", "dev", "tun0"); err != nil {
		return fmt.Errorf("assigning IP to tun0: %w", err)
	}
	if err := run("ip", "link", "set", "tun0", "up"); err != nil {
		return fmt.Errorf("bringing up tun0: %w", err)
	}

	// Start tun2socks
	gw.tunProc = exec.CommandContext(gw.ctx, tunPath,
		"-device", "tun0",
		"-proxy", fmt.Sprintf("socks5://127.0.0.1:%d", gw.socksPort),
	)
	if err := gw.tunProc.Start(); err != nil {
		return fmt.Errorf("starting tun2socks: %w", err)
	}

	time.Sleep(2 * time.Second)
	log.Printf("  ✅ tun2socks running (tun0 → socks5://127.0.0.1:%d)", gw.socksPort)
	return nil
}

func (gw *Gateway) setupRouting() error {
	log.Printf("🔧 Configuring routing...")

	// Enable IP forwarding (needed in both modes)
	run("sysctl", "-w", "net.ipv4.ip_forward=1")

	if gw.nativeTUN {
		// Native TUN mode: sing-box's auto_route handles policy routing.
		// We only need NAT masquerade and FORWARD rules for LAN traffic.
		log.Printf("  ℹ️  Native TUN: skipping fwmark/policy routing (sing-box auto_route handles it)")

		// NAT masquerade on LAN interface so return traffic finds its way back
		run("iptables", "-t", "nat", "-F", "POSTROUTING")
		run("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", gw.iface, "-j", "MASQUERADE")

		// FORWARD rules: allow traffic between LAN interface and tun0
		run("iptables", "-F", "FORWARD")
		run("iptables", "-A", "FORWARD", "-i", gw.iface, "-o", "tun0", "-j", "ACCEPT")
		run("iptables", "-A", "FORWARD", "-i", "tun0", "-o", gw.iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		run("iptables", "-A", "FORWARD", "-i", gw.iface, "-o", gw.iface, "-j", "ACCEPT")

		log.Printf("  ✅ Routing configured (native TUN: LAN ↔ tun0 via sing-box auto_route)")
	} else {
		// Legacy mode: full policy routing with fwmark + route table 100
		// Table 100: default via tun0 + local subnet direct
		run("ip", "route", "flush", "table", "100")
		run("ip", "route", "add", "default", "via", "10.0.0.1", "dev", "tun0", "table", "100")
		run("ip", "route", "add", gw.subnet, "dev", gw.iface, "table", "100")

		// Mark packets from LAN (not destined to LAN) with fwmark 0x1
		// Whitelist (geoip IR → direct) is now handled inside sing-box, no ipset needed.
		run("iptables", "-t", "mangle", "-F", "PREROUTING")
		run("iptables", "-t", "mangle", "-A", "PREROUTING",
			"-i", gw.iface,
			"-s", gw.subnet,
			"!", "-d", gw.subnet,
			"-j", "MARK", "--set-mark", "0x1")

		// Route marked traffic through table 100
		run("ip", "rule", "del", "fwmark", "0x1", "lookup", "100")
		run("ip", "rule", "add", "fwmark", "0x1", "lookup", "100", "prio", "100")

		// NAT
		run("iptables", "-t", "nat", "-F", "POSTROUTING")
		run("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "tun0", "-j", "MASQUERADE")
		run("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", gw.iface, "-j", "MASQUERADE")

		// Forward
		run("iptables", "-F", "FORWARD")
		run("iptables", "-A", "FORWARD", "-i", gw.iface, "-o", "tun0", "-j", "ACCEPT")
		run("iptables", "-A", "FORWARD", "-i", "tun0", "-o", gw.iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		run("iptables", "-A", "FORWARD", "-i", gw.iface, "-o", gw.iface, "-j", "ACCEPT")

		log.Printf("  ✅ Routing configured (LAN → tun0 → tunnel, whitelist via sing-box geoip)")
	}

	return nil
}

func (gw *Gateway) cleanupRouting() {
	// Always clean up iptables rules regardless of mode
	run("iptables", "-t", "mangle", "-F", "PREROUTING")
	run("iptables", "-t", "nat", "-F", "POSTROUTING")
	run("iptables", "-F", "FORWARD")

	if !gw.nativeTUN {
		// Legacy mode: also clean up policy routing and TUN device
		run("ip", "rule", "del", "fwmark", "0x1", "lookup", "100")
		run("ip", "route", "flush", "table", "100")
		run("ip", "link", "del", "tun0")
	}
	// In native TUN mode: skip ip link del tun0 (sing-box cleans up its own device)
	// and skip ip rule del fwmark (not used in native TUN mode)
}

func (gw *Gateway) resolveEngine(protocol string) string {
	// If user has a preferred engine, use it for supported protocols
	if gw.config.Engines.PreferredEngine != "" {
		switch protocol {
		case "vmess", "vless", "trojan", "shadowsocks":
			return gw.config.Engines.PreferredEngine
		}
	}
	switch protocol {
	case "vmess", "vless", "trojan", "shadowsocks", "hysteria2", "tuic", "socks5", "http":
		return "sing-box"
	case "wireguard":
		return "wireguard-go"
	case "openvpn":
		return "openvpn"
	case "ssh":
		return "ssh"
	default:
		return "sing-box"
	}
}

// --- Accessors for API ---

func (gw *Gateway) GetProfileManager() *profile.Manager  { return gw.profileMgr }
func (gw *Gateway) GetTunnelManager() *tunnel.Manager     { return gw.tunnelMgr }
func (gw *Gateway) GetWhitelistManager() *whitelist.Manager { return gw.whitelist }

// --- Helpers ---

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s (%w)", name, strings.Join(args, " "), string(out), err)
	}
	return nil
}

// startAutoChains starts all chains that have auto_start: true.
func (gw *Gateway) startAutoChains() {
	for _, chainCfg := range gw.config.Chains {
		if !chainCfg.AutoStart {
			continue
		}
		log.Printf("⛓️  Auto-starting chain: %s (%d hops)", chainCfg.Name, len(chainCfg.Hops))
		if err := gw.tunnelMgr.StartChain(gw.ctx, chainCfg, gw.profileMgr); err != nil {
			log.Printf("⚠️  Chain %s auto-start failed: %v", chainCfg.Name, err)
		} else {
			log.Printf("✅ Chain %s auto-started", chainCfg.Name)
		}
	}
}

func waitForPort(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("port %d not ready after %v", port, timeout)
}

// waitForTUNDevice polls for a network interface to appear within the given timeout.
// It checks every 500ms using net.InterfaceByName until the interface exists or timeout is reached.
func waitForTUNDevice(name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, err := net.InterfaceByName(name)
		if err == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("TUN device %q not found after %v", name, timeout)
}
