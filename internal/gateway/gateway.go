package gateway

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
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
	"github.com/miekg/dns"
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
	dnsBuiltin  []*dns.Server // built-in DNS servers (fallback when dns2socks/dnsmasq absent)

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

	// 0. Clean up any state left by a previous crashed/kill-9'd instance.
	gw.cleanupPreviousRun()

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
	gatewayActive := gw.nativeTUN || gw.tunProc != nil
	if gatewayActive {
		log.Printf("   Mode:       GATEWAY (set clients GW+DNS to %s)", gw.localIP)
	} else if gw.config.Gateway.Enabled {
		log.Printf("   Mode:       PROXY ONLY ⚠️  (gateway requested but TUN unavailable — use socks5://%s:%d)", gw.localIP, gw.socksPort)
	} else {
		log.Printf("   Mode:       PROXY ONLY (use socks5://%s:%d)", gw.localIP, gw.socksPort)
	}

	// CDN-based links only relay HTTP, not HTTPS. Test asynchronously so Start() returns fast.
	if profile.IsCDNPattern(activeLink) {
		socksPort := gw.socksPort
		ctx := gw.ctx
		go func() {
			checkCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
			defer cancel()
			if !profile.TestHTTPS(checkCtx, socksPort) {
				log.Printf("⚠️  CDN link — HTTPS is not relayed (video/streaming will fail)")
				log.Printf("   Run 'bypath bench' to find an HTTPS-capable link")
			}
		}()
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
	for _, s := range gw.dnsBuiltin {
		s.Shutdown()
	}
	gw.dnsBuiltin = nil

	// Stop engine — in native TUN mode, sing-box removes its TUN device on exit
	if gw.engineProc != nil {
		gw.engineProc.Process.Kill()
		gw.engineProc.Wait()
		log.Println("  ✓ Engine stopped")
	}

	gw.cancel()
	os.Remove(paths.Get().ChildrenFile)
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
// For each link it tries the preferred engine first, then falls back to the alternative
// engine (sing-box ↔ xray) before moving to the next link.
func (gw *Gateway) startEngineWithLinkFallback(link *profile.Link) error {
	// Try active link first (with per-link engine fallback)
	if gw.startEngineWithEngineFallback(link) {
		return nil
	}

	// Try other links in the group (use the active link's group, not config default)
	fallbackGroup := link.Group
	if fallbackGroup == "" {
		fallbackGroup = gw.config.Profiles.ActiveGroup
	}
	g, gerr := gw.profileMgr.GetGroup(fallbackGroup)
	if gerr != nil {
		return fmt.Errorf("no working link found in group '%s'", fallbackGroup)
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

		if gw.startEngineWithEngineFallback(candidate) {
			gw.profileMgr.SetActiveLink(candidate)
			return nil
		}
	}

	return fmt.Errorf("no working link found in group '%s'", fallbackGroup)
}

// startEngineWithEngineFallback tries a link with its preferred engine, then falls back
// to the alternative engine (sing-box ↔ xray) if the first attempt fails.
// Returns true if the link is running and verified, false otherwise.
func (gw *Gateway) startEngineWithEngineFallback(link *profile.Link) bool {
	primaryEngine := gw.resolveEngine(link.Protocol)

	// Try primary engine
	if err := gw.startEngine(link); err == nil {
		if gw.verifyConnection() {
			return true
		}
		log.Printf("  ⚠️  %s started but no connectivity, trying alternative engine...", primaryEngine)
		if gw.engineProc != nil {
			gw.engineProc.Process.Kill()
			gw.engineProc.Wait()
			gw.engineProc = nil
		}
	} else {
		log.Printf("  ⚠️  %s failed: %v", primaryEngine, err)
	}

	// Determine alternative engine
	altEngine := gw.alternativeEngine(primaryEngine, link.Protocol)
	if altEngine == "" {
		return false
	}

	log.Printf("  🔀 Trying alternative engine: %s", altEngine)

	// Temporarily override preferred engine for this attempt
	origPreferred := gw.config.Engines.PreferredEngine
	gw.config.Engines.PreferredEngine = altEngine
	defer func() { gw.config.Engines.PreferredEngine = origPreferred }()

	if err := gw.startEngine(link); err == nil {
		if gw.verifyConnection() {
			log.Printf("  ✅ Connected with %s!", altEngine)
			return true
		}
		log.Printf("  ❌ %s also no connectivity", altEngine)
		if gw.engineProc != nil {
			gw.engineProc.Process.Kill()
			gw.engineProc.Wait()
			gw.engineProc = nil
		}
	} else {
		log.Printf("  ❌ %s also failed: %v", altEngine, err)
	}

	return false
}

// alternativeEngine returns the fallback engine for a given primary engine and protocol.
// Only switches between sing-box and xray for supported protocols.
// Returns "" if no alternative is available.
func (gw *Gateway) alternativeEngine(primaryEngine, protocol string) string {
	// Only sing-box ↔ xray fallback makes sense for these protocols
	switch protocol {
	case "vmess", "vless", "trojan", "shadowsocks":
		// ok to try alternative
	default:
		return ""
	}
	switch primaryEngine {
	case "sing-box":
		if _, err := gw.engineMgr.Get("xray"); err == nil {
			return "xray"
		}
	case "xray":
		if _, err := gw.engineMgr.Get("sing-box"); err == nil {
			return "sing-box"
		}
	}
	return ""
}

// verifyConnection checks if the SOCKS proxy can reach the actual internet
// through the tunnel — NOT just Cloudflare's own CDN edge.
//
// CDN-based VLESS proxies (*.okarimi.ir, *.oneset.ir via Cloudflare port 2083)
// always return 204 for "Host: cp.cloudflare.com / http://1.1.1.1" because
// the CDN edge answers locally without actually forwarding through the tunnel.
// We must verify with a NON-Cloudflare target to detect real connectivity.
func (gw *Gateway) verifyConnection() bool {
	addr := fmt.Sprintf("socks5h://127.0.0.1:%d", gw.socksPort)

	// Candidates: non-Cloudflare targets that return predictable HTTP responses.
	// socks5h:// means hostname sent to proxy for remote DNS (no local DNS needed).
	candidates := []struct {
		url      string
		wantCode string
	}{
		// Google's generate_204 — returns exactly 204, not Cloudflare.
		{"http://www.gstatic.com/generate_204", "204"},
		// Microsoft connectivity check — returns 200 with small body.
		{"http://www.msftconnecttest.com/connecttest.txt", "200"},
		// Apple captive portal check — returns 200.
		{"http://captive.apple.com/hotspot-detect.html", "200"},
	}

	baseArgs := []string{"-s", "-x", addr, "--connect-timeout", "8", "--max-time", "12",
		"-o", "/dev/null", "-w", "%{http_code}"}
	if gw.nativeTUN && gw.localIP != "" {
		baseArgs = append(baseArgs, "--interface", gw.localIP)
	}

	tunnelOK := false
	for _, c := range candidates {
		args := append(baseArgs, c.url)
		cmd := exec.CommandContext(gw.ctx, "curl", args...)
		out, err := cmd.Output()
		if err == nil && strings.TrimSpace(string(out)) == c.wantCode {
			tunnelOK = true
			break
		}
	}
	if !tunnelOK {
		return false
	}

	// If Iran is whitelisted, also verify that Iranian sites are routed direct
	// (not proxied through a foreign exit node).
	return gw.verifyWhitelistRouting()
}

// verifyWhitelistRouting checks that whitelisted-country sites are reachable via
// direct routing, not through the proxy. Only runs when relevant countries are configured.
//
// Iranian routing check:
//   - login.samandehi.ir returns HTTP 307 from Iranian IPs, but 403 from foreign IPs.
//     So 403 means traffic is going through the proxy instead of direct — fail.
//   - wp.mahex.com/ip and ip.shecan.ir return the caller's IP. If routing is correct
//     (direct from Iran) these sites are reachable. If going through proxy, they block
//     foreign TLS and return SSL errors — fail.
func (gw *Gateway) verifyWhitelistRouting() bool {
	hasIR := false
	for _, c := range gw.config.Whitelist.Countries {
		if strings.EqualFold(c, "ir") {
			hasIR = true
			break
		}
	}
	if !hasIR {
		return true
	}

	addr := fmt.Sprintf("socks5h://127.0.0.1:%d", gw.socksPort)
	baseArgs := []string{"-s", "-x", addr, "--connect-timeout", "8", "--max-time", "12",
		"-o", "/dev/null", "-w", "%{http_code}"}

	// samandehi.ir: 307 = direct (Iranian IP), 403 = going through proxy (foreign IP).
	code := func(url string) string {
		args := append(append([]string{}, baseArgs...), url)
		cmd := exec.CommandContext(gw.ctx, "curl", args...)
		out, err := cmd.Output()
		if err != nil {
			return "000"
		}
		return strings.TrimSpace(string(out))
	}

	samandehiCode := code("https://login.samandehi.ir")
	if samandehiCode == "403" {
		log.Printf("  ⚠️  IR routing check: login.samandehi.ir returned 403 (traffic going through proxy, not direct)")
		return false
	}
	if samandehiCode == "000" {
		log.Printf("  ⚠️  IR routing check: login.samandehi.ir unreachable (000)")
		return false
	}
	log.Printf("  ✅ IR routing: login.samandehi.ir → %s (direct)", samandehiCode)

	// IP checker sites: these block foreign TLS, so reachability = direct routing.
	ipCheckers := []string{
		"https://wp.mahex.com/ip",
		"https://ip.shecan.ir",
	}
	baseArgsBody := []string{"-s", "-x", addr, "--connect-timeout", "8", "--max-time", "12"}
	for _, url := range ipCheckers {
		args := append(append([]string{}, baseArgsBody...), url)
		cmd := exec.CommandContext(gw.ctx, "curl", args...)
		out, err := cmd.Output()
		if err == nil && len(strings.TrimSpace(string(out))) > 0 {
			log.Printf("  ✅ IR routing: %s → %s", url, strings.TrimSpace(string(out)))
			return true
		}
		log.Printf("  ⚠️  IR routing: %s unreachable via direct path", url)
	}

	// samandehi passed but IP checkers were unreachable — not a routing failure,
	// just those specific sites being down. Consider routing OK.
	return true
}

func (gw *Gateway) startEngine(link *profile.Link) error {
	log.Printf("🔧 Starting engine for [%s] %s...", link.Protocol, link.Remark)

	// Pin the server hostname in /etc/hosts BEFORE starting the engine.
	// The engine needs to connect to the VLESS server by hostname, but ISPs
	// intercept DNS and return fake IPs. Pinning first ensures the engine gets
	// the real IP regardless of what the system DNS returns.
	pinnedHosts := map[string]string{}
	if link.Address != "" {
		if ip := gw.pinHostToEtcHosts(link.Address); ip != "" {
			pinnedHosts[link.Address] = ip
		}
	}

	// Determine engine
	engineName := gw.resolveEngine(link.Protocol)
	eng, err := gw.engineMgr.Get(engineName)
	if err != nil {
		return fmt.Errorf("engine %s not available: %w", engineName, err)
	}

	// Generate config (with routing rules or legacy whitelist for geoip/geosite routing)
	configGen := tunnel.NewConfigGenerator(paths.Get().TmpDir)
	configGen.PinnedHosts = pinnedHosts
	if len(gw.config.Routing.Rules) > 0 {
		// New rule-based routing: map config rules to tunnel rules
		rules := make([]tunnel.RoutingRule, len(gw.config.Routing.Rules))
		for i, r := range gw.config.Routing.Rules {
			rules[i] = tunnel.RoutingRule{Match: r.Match, Outbound: r.Outbound}
		}
		configGen.RoutingRules = rules
		configGen.ExternalOutbounds = gw.config.Routing.ExternalOutbounds
	} else {
		// Legacy whitelist config (deprecated — shows warning at load time)
		configGen.WhitelistCountries = gw.config.Whitelist.Countries
		configGen.GeositeCountries = gw.config.Whitelist.GeositeCountries
		if len(configGen.GeositeCountries) == 0 {
			configGen.GeositeCountries = gw.config.Whitelist.Countries
		}
		configGen.BypassDomains = gw.config.Whitelist.BypassDomains
		configGen.ForceProxyDomains = gw.config.Whitelist.ForceProxyDomains
	}
	configGen.DNSUpstream = gw.config.Gateway.DNSUpstream
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

	// Mark native TUN as active only when sing-box started with gateway mode.
	// xray does not create a TUN device — it provides SOCKS only.
	if gw.config.Gateway.Enabled && gw.config.Gateway.NativeTUN && eng.Name == "sing-box" {
		gw.nativeTUN = true
	}

	return nil
}

func (gw *Gateway) startDNS() error {
	log.Printf("🔀 Starting DNS proxy on :%d...", gw.dnsPort)

	// Kill only bypath's own previous DNS proxy (tracked by PID), not user processes.
	if gw.dnsProc != nil && gw.dnsProc.Process != nil {
		gw.dnsProc.Process.Kill()
		gw.dnsProc.Wait()
		gw.dnsProc = nil
	}

	upstream := gw.config.Gateway.DNSUpstream
	if len(upstream) == 0 {
		upstream = []string{"1.1.1.1", "8.8.8.8"}
	}

	// Try dns2socks first (routes DNS through the tunnel — preferred).
	// dns2socks takes a single upstream; use the first configured one.
	dns2socksPath, err := exec.LookPath("dns2socks")
	if err == nil {
		gw.dnsProc = exec.CommandContext(gw.ctx, dns2socksPath,
			"-l", fmt.Sprintf("0.0.0.0:%d", gw.dnsPort),
			"-d", upstream[0]+":53",
			"-s", fmt.Sprintf("socks5://127.0.0.1:%d", gw.socksPort),
			"-f", "-c",
		)
		if err := gw.dnsProc.Start(); err != nil {
			return fmt.Errorf("starting dns2socks: %w", err)
		}
		if err := waitForPort(gw.dnsPort, 5*time.Second); err != nil {
			return fmt.Errorf("dns2socks didn't start: %w", err)
		}
		trackChildPID(gw.dnsProc.Process.Pid)
		log.Printf("  ✅ dns2socks running on :%d → %s (DNS through tunnel)", gw.dnsPort, upstream[0])
		return nil
	}

	// Fallback: dnsmasq (DNS goes direct, not through tunnel).
	dnsmasqPath, err := exec.LookPath("dnsmasq")
	if err == nil {
		args := []string{"--no-daemon", "--no-resolv", "--listen-address=0.0.0.0", "--bind-interfaces"}
		for _, ns := range upstream {
			args = append(args, "--server="+ns)
		}
		gw.dnsProc = exec.CommandContext(gw.ctx, dnsmasqPath, args...)
		if err := gw.dnsProc.Start(); err != nil {
			return fmt.Errorf("starting dnsmasq: %w", err)
		}
		trackChildPID(gw.dnsProc.Process.Pid)
		log.Printf("  ⚠️  dnsmasq running → %v (DNS NOT through tunnel — install dns2socks for secure DNS)", upstream)
		return nil
	}

	// Last resort: built-in DNS forwarder (no external tool needed).
	return gw.startBuiltinDNS(upstream)
}

// startBuiltinDNS starts a DNS forwarder using DoH (DNS-over-HTTPS) routed through
// the SOCKS5 proxy. This avoids ISP DNS hijacking/poisoning for blocked sites.
// Falls back to direct UDP if the proxy-routed DoH fails (e.g. proxy not yet ready).
func (gw *Gateway) startBuiltinDNS(upstreams []string) error {
	// Build DoH URLs from upstream IPs.
	dohURLs := make([]string, 0, len(upstreams))
	for _, up := range upstreams {
		if net.ParseIP(up) != nil {
			dohURLs = append(dohURLs, "https://"+up+"/dns-query")
		} else {
			dohURLs = append(dohURLs, up)
		}
	}

	// HTTP client that tunnels through SOCKS5 (xray) — avoids ISP DNS hijacking.
	socksAddr := fmt.Sprintf("127.0.0.1:%d", gw.socksPort)
	proxyHTTP := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				conn, err := d.DialContext(ctx, "tcp", socksAddr)
				if err != nil {
					return nil, err
				}
				// SOCKS5 handshake: no-auth, then CONNECT
				if err := socks5Connect(conn, addr); err != nil {
					conn.Close()
					return nil, fmt.Errorf("socks5 connect %s: %w", addr, err)
				}
				return conn, nil
			},
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}

	// Fallback: plain UDP client (direct, no proxy) for when proxy isn't ready.
	udpClient := &dns.Client{Net: "udp", Timeout: 4 * time.Second}

	queryFn := func(ctx context.Context, r *dns.Msg) *dns.Msg {
		packed, err := r.Pack()
		if err == nil {
			for _, dohURL := range dohURLs {
				req, _ := http.NewRequestWithContext(ctx, http.MethodPost, dohURL,
					bytes.NewReader(packed))
				req.Header.Set("Content-Type", "application/dns-message")
				req.Header.Set("Accept", "application/dns-message")
				resp, err := proxyHTTP.Do(req)
				if err == nil {
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					m := new(dns.Msg)
					if m.Unpack(body) == nil {
						return m
					}
				}
			}
		}
		// Proxy unavailable — fall back to direct UDP.
		for _, up := range upstreams {
			resp, _, err := udpClient.ExchangeContext(ctx, r, up+":53")
			if err == nil {
				return resp
			}
		}
		return nil
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		resp := queryFn(gw.ctx, r)
		if resp == nil {
			m := new(dns.Msg)
			m.SetRcode(r, dns.RcodeServerFailure)
			w.WriteMsg(m)
			return
		}
		resp.Id = r.Id
		w.WriteMsg(resp)
	})

	addr := fmt.Sprintf("0.0.0.0:%d", gw.dnsPort)

	udpConn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("built-in DNS (UDP): %w", err)
	}
	tcpLn, err := net.Listen("tcp", addr)
	if err != nil {
		udpConn.Close()
		return fmt.Errorf("built-in DNS (TCP): %w", err)
	}

	udpSrv := &dns.Server{PacketConn: udpConn, Net: "udp", Handler: mux}
	tcpSrv := &dns.Server{Listener: tcpLn, Net: "tcp", Handler: mux}

	go udpSrv.ActivateAndServe()
	go tcpSrv.ActivateAndServe()

	gw.dnsBuiltin = append(gw.dnsBuiltin, udpSrv, tcpSrv)
	log.Printf("  ✅ Built-in DNS forwarder on :%d → DoH via proxy (%v)", gw.dnsPort, upstreams)
	return nil
}

// socks5Connect performs a minimal SOCKS5 no-auth handshake + CONNECT on an open conn.
func socks5Connect(conn net.Conn, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	// Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		return err
	}
	// Server choice
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if buf[1] != 0 {
		return fmt.Errorf("socks5: server chose auth method %d", buf[1])
	}

	// CONNECT request: VER=5, CMD=1, RSV=0, ATYP=3 (domain), then host+port
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	// Reply: skip VER, REP, RSV, then read address (variable length)
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[1] != 0 {
		return fmt.Errorf("socks5: CONNECT failed, REP=%d", head[1])
	}
	switch head[3] {
	case 1: // IPv4
		io.ReadFull(conn, make([]byte, 6))
	case 3: // domain
		n := make([]byte, 1)
		io.ReadFull(conn, n)
		io.ReadFull(conn, make([]byte, int(n[0])+2))
	case 4: // IPv6
		io.ReadFull(conn, make([]byte, 18))
	}
	conn.SetDeadline(time.Time{})
	return nil
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
	trackChildPID(gw.tunProc.Process.Pid)

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

		// Intercept LAN DNS so DHCP-configured DNS doesn't bypass the tunnel.
		gw.setupDNSIntercept()

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

		// Intercept LAN DNS so DHCP-configured DNS doesn't bypass the tunnel.
		gw.setupDNSIntercept()

		log.Printf("  ✅ Routing configured (LAN → tun0 → tunnel, whitelist via sing-box geoip)")

		// Pin the tunnel server's hostname in /etc/hosts BEFORE switching DNS.
		// This prevents a chicken-and-egg problem: after resolv.conf points to
		// dns2socks (127.0.0.1), xray needs to resolve the server hostname but
		// can't do so until xray itself is up and forwarding DNS queries.
		if gw.engineProc != nil {
			// engineProc is the xray/sing-box process; find the link that was used
			if link := gw.profileMgr.GetActiveLink(); link != nil && link.Address != "" {
				gw.pinHostToEtcHosts(link.Address)
			}
		}

		// Point the host's own DNS resolver to dns2socks (127.0.0.1) so that
		// processes on Orange Pi itself (xray, curl, etc.) get unblocked DNS.
		// Without this, /etc/resolv.conf points to 8.8.8.8 which is DNS-poisoned
		// in Iran and returns fake IPs (e.g. 10.10.34.36) for blocked sites.
		gw.setResolvConf("127.0.0.1")
	}

	return nil
}

// pinHostToEtcHosts resolves hostname bypassing /etc/resolv.conf (which may
// be ISP-poisoned) and writes a static entry to /etc/hosts. This lets
// xray/sing-box reach the tunnel server after resolv.conf is switched to 127.0.0.1.
// Returns the resolved IP on success, or "" if resolution failed or hostname is already an IP.
func (gw *Gateway) pinHostToEtcHosts(hostname string) string {
	// Skip if it's already an IP
	if net.ParseIP(hostname) != nil {
		return ""
	}

	// Use the configured upstream DNS servers directly (bypass system resolv.conf).
	// ISPs often poison resolv.conf DNS for proxy server hostnames, returning
	// internal IPs (e.g. 10.10.34.36) that masquerade as the real server.
	upstream := gw.config.Gateway.DNSUpstream
	if len(upstream) == 0 {
		upstream = []string{"1.1.1.1", "8.8.8.8"}
	}

	var ip string
	for _, ns := range upstream {
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "udp", ns+":53")
			},
		}
		addrs, err := r.LookupHost(context.Background(), hostname)
		if err != nil || len(addrs) == 0 {
			continue
		}
		candidate := addrs[0]
		// Reject obviously-intercepted IPs: private/loopback ranges used by ISPs
		// to redirect blocked hostnames.
		if parsed := net.ParseIP(candidate); parsed != nil {
			if parsed.IsLoopback() || parsed.IsPrivate() {
				log.Printf("⚠️  Rejected intercepted IP %s for %s (from %s)", candidate, hostname, ns)
				continue
			}
		}
		ip = candidate
		break
	}

	if ip == "" {
		log.Printf("⚠️  Could not resolve %s via any upstream DNS", hostname)
		return ""
	}

	marker := "# bypath-pin"
	entry := fmt.Sprintf("%s %s %s\n", ip, hostname, marker)

	current, _ := os.ReadFile("/etc/hosts")
	// Remove any existing bypath-pin lines for this host
	var filtered []string
	for _, line := range strings.Split(string(current), "\n") {
		if strings.Contains(line, marker) && strings.Contains(line, hostname) {
			continue
		}
		filtered = append(filtered, line)
	}
	newContent := strings.Join(filtered, "\n")
	if !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}
	newContent += entry

	if err := os.WriteFile("/etc/hosts", []byte(newContent), 0644); err != nil {
		log.Printf("⚠️  Could not pin %s to /etc/hosts: %v", hostname, err)
		return ""
	}
	log.Printf("🔧 Pinned %s → %s in /etc/hosts", hostname, ip)
	return ip
}

// unpinHostsFromEtcHosts removes all bypath-pin entries added by pinHostToEtcHosts.
func (gw *Gateway) unpinHostsFromEtcHosts() {
	marker := "# bypath-pin"
	current, err := os.ReadFile("/etc/hosts")
	if err != nil {
		return
	}
	var filtered []string
	for _, line := range strings.Split(string(current), "\n") {
		if strings.Contains(line, marker) {
			continue
		}
		filtered = append(filtered, line)
	}
	os.WriteFile("/etc/hosts", []byte(strings.Join(filtered, "\n")), 0644)
}

const resolvBackup = "/etc/resolv.conf.bypath-backup"

// trackChildPID appends the PID of a bypath-owned child process to the children
// file so cleanupPreviousRun can kill only our own processes, not user-started ones.
func trackChildPID(pid int) {
	f, err := os.OpenFile(paths.Get().ChildrenFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%d\n", pid)
}

// killTrackedChildren reads the children file and kills only the PIDs bypath
// started itself. Removes the file afterwards.
func killTrackedChildren() {
	data, err := os.ReadFile(paths.Get().ChildrenFile)
	if err != nil {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pid := 0
		fmt.Sscanf(line, "%d", &pid)
		if pid <= 1 {
			continue
		}
		if proc, err := os.FindProcess(pid); err == nil {
			proc.Kill()
		}
	}
	os.Remove(paths.Get().ChildrenFile)
}

// setResolvConf saves the current resolv.conf (DHCP-assigned) as a backup,
// then overwrites it with bypath's nameserver (immutable so dhcpcd can't clobber it).
func (gw *Gateway) setResolvConf(nameserver string) {
	exec.Command("chattr", "-i", "/etc/resolv.conf").Run()

	// Back up whatever the DHCP client wrote — we'll restore it on stop.
	if orig, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		if !strings.Contains(string(orig), "127.0.0.1") {
			os.WriteFile(resolvBackup, orig, 0644)
		}
	}

	content := fmt.Sprintf("nameserver %s\n", nameserver)
	if err := os.WriteFile("/etc/resolv.conf", []byte(content), 0644); err != nil {
		log.Printf("⚠️  Could not update /etc/resolv.conf: %v", err)
		return
	}

	if err := exec.Command("chattr", "+i", "/etc/resolv.conf").Run(); err != nil {
		log.Printf("⚠️  chattr +i failed (non-ext4?): %v", err)
	}

	log.Printf("🔧 /etc/resolv.conf → nameserver %s (immutable)", nameserver)
}

// restoreResolvConf removes the immutable flag and restores the original
// DHCP-assigned resolv.conf. Falls back to 8.8.8.8 if no backup exists.
func (gw *Gateway) restoreResolvConf() {
	exec.Command("chattr", "-i", "/etc/resolv.conf").Run()

	if backup, err := os.ReadFile(resolvBackup); err == nil && len(backup) > 0 {
		if err := os.WriteFile("/etc/resolv.conf", backup, 0644); err == nil {
			os.Remove(resolvBackup)
			log.Printf("🔧 /etc/resolv.conf restored (DHCP original)")
			return
		}
	}

	// No backup — write a safe fallback so DNS works after stop.
	os.WriteFile("/etc/resolv.conf", []byte("nameserver 8.8.8.8\nnameserver 1.1.1.1\n"), 0644)
	log.Printf("🔧 /etc/resolv.conf restored (fallback 8.8.8.8)")
}

// setupDNSIntercept redirects all DNS queries (port 53) arriving on the LAN
// interface to bypath's own DNS proxy, regardless of what DNS server the
// DHCP gave the client. This is the transparent DNS hijack that makes bypath
// work without the user ever touching their DNS settings.
func (gw *Gateway) setupDNSIntercept() {
	dnsPort := fmt.Sprintf("%d", gw.dnsPort)
	// Redirect UDP and TCP DNS from LAN clients to our local DNS proxy.
	// Only applies to traffic arriving on the LAN interface so we don't
	// redirect bypath's own DNS queries (those originate from lo/tun0).
	run("iptables", "-t", "nat", "-A", "PREROUTING",
		"-i", gw.iface,
		"-s", gw.subnet,
		"-p", "udp", "--dport", "53",
		"-j", "REDIRECT", "--to-port", dnsPort)
	run("iptables", "-t", "nat", "-A", "PREROUTING",
		"-i", gw.iface,
		"-s", gw.subnet,
		"-p", "tcp", "--dport", "53",
		"-j", "REDIRECT", "--to-port", dnsPort)
	log.Printf("🔀 DNS intercept active: LAN :53 → :%s (DHCP DNS ignored)", dnsPort)
}

func (gw *Gateway) cleanupRouting() {
	// Always clean up iptables rules regardless of mode
	run("iptables", "-t", "mangle", "-F", "PREROUTING")
	run("iptables", "-t", "nat", "-F", "PREROUTING")
	run("iptables", "-t", "nat", "-F", "POSTROUTING")
	run("iptables", "-F", "FORWARD")

	if !gw.nativeTUN {
		// Legacy mode: also clean up policy routing and TUN device
		run("ip", "rule", "del", "fwmark", "0x1", "lookup", "100")
		run("ip", "route", "flush", "table", "100")
		run("ip", "link", "del", "tun0")
	}

	// Always restore DNS and hosts — both legacy and native TUN modes may have
	// modified resolv.conf, and we must leave the system working after stop.
	gw.restoreResolvConf()
	gw.unpinHostsFromEtcHosts()
}

// cleanupPreviousRun kills leftover child processes and restores network state
// from any previous crashed or kill-9'd bypath instance. Called unconditionally
// at the start of Start() so every startup begins from a known-clean state.
func (gw *Gateway) cleanupPreviousRun() {
	log.Println("🧹 Cleaning up state from previous run...")

	// Kill child processes from the previous instance.
	// Engine processes: kill by config-path pattern (safe — only matches bypath's own).
	exec.Command("pkill", "-f", "xray run -c /tmp/bypath").Run()
	exec.Command("pkill", "-f", "sing-box run -c /tmp/bypath").Run()
	// dns2socks / tun2socks: kill only tracked PIDs to avoid killing user processes.
	killTrackedChildren()

	// Allow processes to exit before cleaning up network state.
	time.Sleep(300 * time.Millisecond)

	// Clean up network state unconditionally — we don't know what the
	// previous instance's mode was (legacy vs native TUN).
	exec.Command("iptables", "-t", "mangle", "-F", "PREROUTING").Run()
	exec.Command("iptables", "-t", "nat", "-F", "PREROUTING").Run()
	exec.Command("iptables", "-t", "nat", "-F", "POSTROUTING").Run()
	exec.Command("iptables", "-F", "FORWARD").Run()
	exec.Command("ip", "rule", "del", "fwmark", "0x1", "lookup", "100").Run()
	exec.Command("ip", "route", "flush", "table", "100").Run()
	exec.Command("ip", "link", "del", "tun0").Run()

	// Clean up native TUN policy rules (sing-box uses prio 9000+).
	for _, prio := range []string{"9000", "9001", "9002", "9003", "9010"} {
		exec.Command("ip", "rule", "del", "prio", prio).Run()
	}
	exec.Command("ip", "route", "flush", "table", "2022").Run()

	// Restore resolv.conf if bypath left it pointing to 127.0.0.1.
	// Restore resolv.conf: prefer the DHCP backup, fall back to 8.8.8.8.
	exec.Command("chattr", "-i", "/etc/resolv.conf").Run()
	if backup, err := os.ReadFile(resolvBackup); err == nil && len(backup) > 0 {
		os.WriteFile("/etc/resolv.conf", backup, 0644)
		os.Remove(resolvBackup)
	} else if content, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		if strings.TrimSpace(string(content)) == "nameserver 127.0.0.1" {
			os.WriteFile("/etc/resolv.conf", []byte("nameserver 8.8.8.8\nnameserver 1.1.1.1\n"), 0644)
		}
	}

	// Remove any host pins left by a previous run.
	gw.unpinHostsFromEtcHosts()
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
