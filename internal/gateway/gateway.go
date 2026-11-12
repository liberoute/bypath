package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/embedbin"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/metrics"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/tunnel"
	"github.com/miekg/dns"
)

// Gateway is the main orchestrator. When Start() is called it:
// 1. Starts the tunnel engine (sing-box/xray) with generated config
// 2. Starts DNS proxy (dns2socks or built-in) on port 53
// 3. Starts tun2socks to create a TUN device routed through the SOCKS proxy
// 4. Configures iptables so LAN clients' traffic goes through the TUN
type Gateway struct {
	config     *config.Config
	engineMgr  *engine.Manager
	tunnelMgr  *tunnel.Manager
	profileMgr *profile.Manager

	// Running processes / in-process runners
	engineProc     *exec.Cmd
	engineWaiter   *engine.ExitWaiter
	embeddedEngine engine.EmbeddedRunner // non-nil when engine runs in-process (full build)
	dnsProc        *exec.Cmd
	tunProc        *exec.Cmd
	tunWaiter      *engine.ExitWaiter // single reaper for tunProc
	dnsBuiltin     []*dns.Server      // built-in DNS servers (fallback when dns2socks/dnsmasq absent)

	// Runtime supervision state (D4). Guarded by rtMu, never by mu; the watchdog
	// must be able to report state while the lifecycle mutex is held.
	rtMu          sync.Mutex
	runtime       RuntimeStatus
	health        HealthEvidence
	activeLinkRef *profile.Link
	embeddedRef   engine.EmbeddedRunner
	watchStop     chan struct{}
	stopping      bool
	recoverCtx    context.Context
	recoverCancel context.CancelFunc
	lastStartErr  string

	// Native TUN state
	nativeTUN    bool   // whether sing-box native TUN is active
	activeEngine string // name of the currently running engine (e.g. "sing-box", "xray")

	// Runtime artifacts that may contain credentials (removed on Stop).
	configFile string

	// Network info (auto-detected)
	iface     string // e.g., "eth0", "lan0"
	localIP   string // e.g., "192.168.1.15"
	realGW    string // e.g., "192.168.1.1"
	subnet    string // e.g., "192.168.1.0/24"
	socksPort int
	dnsPort   int

	ctx    context.Context
	cancel context.CancelFunc
	// ctx and cancel are guarded by rtMu so shutdown can read them while the
	// lifecycle mutex is held by an in-flight Start.
	abortPending bool // set by AbortStartup while a start is in flight
	// starting counts Start requests that have not returned yet, including ones
	// still waiting for mu. AbortStartup only records a pending abort while this
	// is non-zero, so an abort that arrives after a start completed cannot
	// poison the next connection.
	starting int
	// operatorStop records an explicit tunnel disconnect so the daemon's
	// automatic retry loop does not immediately reconnect against the operator.
	operatorStop bool
	// shutdown records that the process is exiting. It is sticky, unlike
	// abortPending: a signal that arrives before Start reaches the lifecycle
	// lock must still stop the tunnel from coming up.
	shutdown bool
	mu       sync.Mutex

	// Prior dnsmasq.service runtime state for this Gateway instance.
	dnsmasq dnsmasqPriorState

	// Host-network state actually applied by this instance. Proxy-only runs
	// leave these false so Stop never touches unrelated host configuration.
	networkMutated      bool
	legacyRoutingActive bool
	resolvedStopped     bool
	tunCreated          bool
	run                 *gatewayRunState
	// startupDeadline is the end of the single fallback budget for this Start.
	// The native-TUN replay through tun2socks must not open a second full
	// budget, or a hanging engine could double the documented startup bound.
	startupDeadline time.Time
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

	gw := &Gateway{
		config:     cfg,
		engineMgr:  engineMgr,
		tunnelMgr:  tunnelMgr,
		profileMgr: profileMgr,
		socksPort:  cfg.Server.SOCKSPort,
		dnsPort:    cfg.Server.DNSPort,
		ctx:        ctx,
		cancel:     cancel,
	}

	return gw, nil
}

// startupHooks lets tests drive the real Start/Stop lifecycle with an injected
// engine and detection path. Production passes nil and uses the host
// implementations. Host command execution is stubbed separately through the
// package-level run/status/output hooks.
type startupHooks struct {
	detectNetwork func() error
	activeLink    func() *profile.Link
	startEngine   func(*profile.Link) error
}

// Start brings up the full gateway stack.
func (gw *Gateway) Start() error {
	return gw.StartWithContext(context.Background())
}

// StartWithContext brings up the full stack on behalf of a caller that may
// cancel. A caller that is already gone must never start the tunnel: aborting
// such a start through AbortStartup is not enough, because an abort that lands
// before the start registers is ignored and the start then runs behind a
// disconnect.
func (gw *Gateway) StartWithContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	gw.beginStart()
	defer gw.endStart()
	err := gw.startWithContext(ctx, nil)
	if err != nil {
		// "No connection selected" is a waiting state, not a failure: the
		// daemon is healthy and the operator can still add one.
		state := StateFailed
		if errors.Is(err, ErrNoActiveLink) {
			state = StateDisconnected
		}
		gw.setRuntimeState(state, err.Error())
	}
	return err
}

// beginStart/endStart bracket every Start request. endStart clears a pending
// abort once the last request returns: an abort that lost the race with a
// completed Start belongs to that start, not to the next connection.
func (gw *Gateway) beginStart() {
	gw.rtMu.Lock()
	gw.starting++
	gw.rtMu.Unlock()
}

func (gw *Gateway) endStart() {
	gw.rtMu.Lock()
	if gw.starting > 0 {
		gw.starting--
	}
	if gw.starting == 0 {
		gw.abortPending = false
	}
	gw.rtMu.Unlock()
}

// AbortStartup interrupts an in-flight Start (engine attempts, readiness waits,
// TUN setup) so shutdown does not wait for engine timeouts. It is safe to call
// from a signal handler while Start is running: the next Start recreates the
// context in initRuntimeLocked. A late abort after the last Start returned is
// ignored so it cannot poison the next connection.
func (gw *Gateway) AbortStartup() {
	gw.rtMu.Lock()
	if gw.starting == 0 {
		gw.rtMu.Unlock()
		return
	}
	gw.abortPending = true
	cancel := gw.signalStopLocked()
	gw.rtMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// ShutdownStartup records that the process is exiting and interrupts any
// in-flight or future Start. Unlike AbortStartup it never expires, so a signal
// delivered before Start reaches the lifecycle lock still prevents the tunnel
// from being reported as up.
func (gw *Gateway) ShutdownStartup() {
	gw.rtMu.Lock()
	gw.shutdown = true
	gw.abortPending = true
	cancel := gw.signalStopLocked()
	gw.rtMu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (gw *Gateway) startWith(h *startupHooks) error {
	return gw.startWithContext(context.Background(), h)
}

func (gw *Gateway) startWithContext(ctx context.Context, h *startupHooks) error {
	gw.beginStart()
	defer gw.endStart()

	gw.mu.Lock()
	defer gw.mu.Unlock()

	// A caller that cancelled while this start waited for the lifecycle lock
	// must not initialise or touch host state. AbortStartup cannot cover this
	// window because it is ignored before a start is registered.
	if err := ctx.Err(); err != nil {
		return err
	}

	// An operator can bring the gateway up through the control socket while the
	// daemon's retry loop is still waiting. Restarting it here would tear down
	// the working connection; the operator's Start already did the work.
	if gw.GetRuntimeStatus().State == StateConnected {
		log.Println("ℹ️  Gateway is already connected; skipping this start request")
		return nil
	}

	if gw.initRuntimeLocked() {
		// AbortStartup arrived before this Start reached the lock. Honouring it
		// here is the whole point: otherwise the recreated context would erase
		// the shutdown request.
		return context.Canceled
	}

	// Every failure after cleanup may have host state to undo; run the normal
	// shutdown path instead of returning a half-configured host to the caller.
	rollback := func(err error) error {
		gw.stopLocked()
		return err
	}

	detect := gw.detectNetwork
	findLink := gw.getActiveLink
	startEngine := gw.startEngineWithFallback
	if h != nil {
		if h.detectNetwork != nil {
			detect = h.detectNetwork
		}
		if h.activeLink != nil {
			findLink = h.activeLink
		}
		if h.startEngine != nil {
			startEngine = h.startEngine
		}
	}

	// 0. Get the active link first. A missing connection must not touch host
	// state: the daemon stays up with its panel and API so one can be imported.
	activeLink := findLink()
	if activeLink == nil {
		return permanent(fmt.Errorf("%w: add or select a connection first", ErrNoActiveLink))
	}

	// 0a. Clean up any state left by a previous crashed/kill-9'd instance. A
	// failed recovery means bypath cannot prove the host is clean, so startup
	// aborts instead of layering new changes on top of unknown state.
	if err := gw.cleanupPreviousRun(); err != nil {
		return permanent(fmt.Errorf("incomplete recovery from previous run: %w", err))
	}

	// 1. Detect network
	if err := detect(); err != nil {
		return fmt.Errorf("network detection: %w", err)
	}

	// 2a. Native routing must be deterministic before the engine can create
	// routes: reserve bypath's own table/rule index and persist ownership first.
	if gw.config.Gateway.Enabled && gw.config.Gateway.NativeTUN {
		if err := gw.prepareNativeOwnership(); err != nil {
			return rollback(fmt.Errorf("preparing native TUN ownership: %w", err))
		}
	}

	// 2b. Gateway startup no longer touches the host resolver before the engine
	// is up. Port 53 is freed by startDNS once the data path exists, so a failed
	// engine start leaves systemd-resolved and dnsmasq untouched.

	// 3. Start tunnel engine (with auto-fallback). Ownership may already be
	// recorded, so a failed start is rolled back before returning instead of
	// leaving host state pending.
	if err := startEngine(activeLink); err != nil {
		gw.stopLocked()
		return fmt.Errorf("starting engine: %w", err)
	}

	// 4. Bring up the transparent data path.
	if gw.nativeTUN {
		// sing-box handles the TUN device natively — no tun2socks needed.
		log.Printf("🚀 Using sing-box native TUN mode (no tun2socks needed)")

		if err := waitForTUNDeviceContext(gw.ctx, "tun0", 10*time.Second); err != nil {
			log.Printf("⚠️ sing-box TUN device did not appear: %v — retrying through tun2socks", err)
			if err := gw.restartEngineAsLegacy(activeLink); err != nil {
				gw.stopLocked()
				return fmt.Errorf("fallback to tun2socks failed: %w", err)
			}
		}
	}

	if gw.nativeTUN {
		if len(gw.config.Whitelist.Countries) > 0 {
			log.Printf("🌍 Whitelist countries %v → routed direct via sing-box geoip rules", gw.config.Whitelist.Countries)
		}
	} else if gw.config.Gateway.Enabled {
		// tun2socks is the data path for xray, OpenVPN and native-TUN fallback.
		// A gateway run without a working TUN is not a gateway: reporting success
		// would tell clients to route through a host that cannot forward them.
		if err := gw.startTun(); err != nil {
			log.Printf("❌ Transparent gateway unavailable: %v", err)
			gw.stopLocked()
			return fmt.Errorf("transparent gateway unavailable: %w", err)
		}
		if len(gw.config.Whitelist.Countries) > 0 {
			log.Printf("🌍 Whitelist countries %v → routed direct via sing-box geoip rules", gw.config.Whitelist.Countries)
		}
	}

	// 5. DNS and host routing, only after the data path is proven to exist.
	// The resolver is configured for both native TUN and tun2socks, so a client
	// pointing at bypath never depends on engine-specific DNS behaviour.
	if gw.config.Gateway.Enabled {
		if err := gw.startDNS(); err != nil {
			log.Printf("❌ DNS proxy failed: %v", err)
			gw.stopLocked()
			return fmt.Errorf("starting DNS proxy: %w", err)
		}
		if err := gw.verifyDNSReady(gw.dnsWarmup()); err != nil {
			log.Printf("❌ DNS is not usable through the tunnel: %v", err)
			gw.stopLocked()
			return err
		}
		if err := gw.setupRouting(); err != nil {
			log.Printf("❌ Routing setup failed: %v", err)
			gw.stopLocked()
			return fmt.Errorf("configuring host networking: %w", err)
		}
	}

	// A stop that arrived while this Start held mu must not be published as a
	// live tunnel: the setup above may have completed after the abort was
	// recorded, and reporting CONNECTED here would leave a data path running
	// without a watchdog. Tear it down the same way every other failure does.
	if gw.isStopping() || gw.lifetimeContext().Err() != nil {
		gw.stopLocked()
		return context.Canceled
	}

	metrics.GatewayUp.Set(1)
	metrics.SetActiveEngine(gw.activeEngine)
	// The banner must describe the link that is actually carrying traffic, not
	// the link originally requested before fallback ran (D5).
	activeLink = gw.currentActiveLink()
	if activeLink == nil {
		activeLink = findLink()
	}
	log.Printf("✅ Gateway running:")
	log.Printf("   Interface:  %s", gw.iface)
	log.Printf("   Local IP:   %s", gw.localIP)
	socksAddr := gw.config.Server.SOCKSListenAddress()
	log.Printf("   SOCKS:      %s:%d", socksAddr, gw.socksPort)
	// DNS is only reported when this run actually owns a listener (D7).
	if gw.dnsProc != nil || len(gw.dnsBuiltin) > 0 {
		log.Printf("   DNS:        :%d", gw.dnsPort)
	}
	if activeLink != nil {
		log.Printf("   Tunnel:     %s [%s] → %s:%d", activeLink.Protocol, activeLink.Remark, activeLink.Address, activeLink.Port)
	}
	gatewayActive := gw.nativeTUN || gw.tunProc != nil
	if gatewayActive {
		log.Printf("   Mode:       GATEWAY (set clients GW+DNS to %s)", gw.localIP)
	} else if gw.config.Gateway.Enabled {
		log.Printf("   Mode:       PROXY ONLY ⚠️  (gateway requested but TUN unavailable — use socks5://%s:%d)", socksAddr, gw.socksPort)
	} else {
		log.Printf("   Mode:       PROXY ONLY (use socks5://%s:%d)", socksAddr, gw.socksPort)
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

	gw.setRuntimeState(StateConnected, "")
	gw.startWatchdog()

	return nil
}

// Stop gracefully shuts down everything.
func (gw *Gateway) Stop() {
	// Interrupt supervision before taking mu: a recovery attempt may hold mu
	// for the duration of an engine start, and shutdown must not wait for it.
	gw.signalStop()
	gw.mu.Lock()
	defer gw.mu.Unlock()
	gw.stopLocked()
}

// stopLocked is the shared shutdown path for Stop and startup rollback. The
// caller must hold gw.mu.
func (gw *Gateway) stopLocked() {
	log.Println("🛑 Stopping gateway...")
	gw.startupDeadline = time.Time{}

	// Stop tun2socks first: it is the consumer of the TUN device the routing
	// rollback removes.
	if gw.tunProc != nil {
		gw.tunProc.Process.Kill()
		if w := gw.tunWaiterRef(); w != nil {
			w.Wait(5 * time.Second)
		}
		log.Println("  ✓ tun2socks stopped")
		gw.tunProc = nil
		gw.setTunWaiter(nil)
	}

	// Stop DNS listeners before restoring systemd-resolved/dnsmasq. Releasing
	// port 53 first lets the external service bind successfully on restart; a
	// restore attempted while bypath still owns the port would leave the host
	// without a working resolver.
	if gw.dnsProc != nil {
		gw.dnsProc.Process.Kill()
		gw.dnsProc.Wait()
		log.Println("  ✓ DNS proxy stopped")
		gw.dnsProc = nil
	}
	for _, s := range gw.dnsBuiltin {
		s.Shutdown()
	}
	gw.dnsBuiltin = nil

	// Stop engine — in native TUN mode, sing-box removes its TUN device on exit
	if gw.embeddedEngine != nil || gw.engineProc != nil {
		gw.stopEngineLocked()
		log.Println("  ✓ Engine stopped")
	}
	gw.activeEngine = ""

	// The ownership record is the only authority for host-network rollback.
	// Running it after every bypath-owned listener and process is gone means
	// resolver/service restoration happens against a released port 53.
	cleanupErr := gw.cleanupRouting()

	metrics.GatewayUp.Set(0)
	metrics.SetActiveEngine("")
	gw.cancel()

	// Chains and API-started tunnels own engine processes too. Stop them before
	// deleting generation directories so no live engine is left behind (D4/D6).
	if gw.tunnelMgr != nil {
		gw.tunnelMgr.StopAll()
	}

	// Generated configs and extracted OpenVPN material can contain private keys.
	if gw.configFile != "" {
		tunnel.RemoveGenerationDir(paths.Get().TmpDir, gw.configFile)
		gw.configFile = ""
	}
	// Any remaining gen-* directory belongs to an earlier run whose engine has
	// already been stopped and reaped (D6).
	if removed, err := tunnel.RemoveStaleGenerations(paths.Get().TmpDir, ""); err != nil {
		log.Printf("⚠️  Could not remove stale generation directories: %v", err)
	} else if removed > 0 {
		log.Printf("🧹 Removed %d stale generation directorie(s)", removed)
	}
	os.Remove(paths.Get().ChildrenFile)
	gw.setRuntimeState(StateDisconnected, "")
	if cleanupErr != nil {
		log.Printf("⚠️  Gateway stopped with unfinished host-state cleanup; the ownership record was kept for the next start: %v", cleanupErr)
		return
	}
	log.Println("✅ Gateway stopped")
}

// Reload applies a new config without restarting the gateway.
// Returns the names of fields that require an engine restart to take effect.
func (gw *Gateway) Reload(newCfg *config.Config) []string {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	var needRestart []string

	old := gw.config

	if newCfg.Server.SOCKSPort != old.Server.SOCKSPort {
		needRestart = append(needRestart, "server.socks_port")
	}
	if newCfg.Server.SOCKSListenAddress() != old.Server.SOCKSListenAddress() ||
		newCfg.Server.SOCKSUsername != old.Server.SOCKSUsername ||
		newCfg.Server.SOCKSPassword != old.Server.SOCKSPassword {
		needRestart = append(needRestart, "server.socks_listen")
	}
	if newCfg.Server.APIPort != old.Server.APIPort {
		needRestart = append(needRestart, "server.api_port")
	}
	if newCfg.Gateway.NativeTUN != old.Gateway.NativeTUN {
		needRestart = append(needRestart, "gateway.native_tun")
	}
	if strings.Join(newCfg.Gateway.DNSUpstream, ",") != strings.Join(old.Gateway.DNSUpstream, ",") {
		needRestart = append(needRestart, "gateway.dns_upstream")
	}
	if newCfg.Gateway.DNSMode != old.Gateway.DNSMode {
		needRestart = append(needRestart, "gateway.dns_mode")
	}
	if localDNSChanged(old.Gateway.LocalDNS, newCfg.Gateway.LocalDNS) {
		needRestart = append(needRestart, "gateway.local_dns")
	}
	if newCfg.Engines.PreferredEngine != old.Engines.PreferredEngine {
		needRestart = append(needRestart, "engines.preferred")
	}
	// Routing inputs are compiled into the engine configuration, so a change to
	// them is only live after the engine is restarted with a regenerated config.
	if routingChanged(old, newCfg) {
		needRestart = append(needRestart, "routing")
	}

	// Replace config contents so all code paths using gw.config pick up the new values.
	*gw.config = *newCfg

	if len(needRestart) > 0 {
		log.Printf("♻️  Config reloaded — the following changes require engine restart: %s", strings.Join(needRestart, ", "))
	} else {
		log.Printf("♻️  Config reloaded — all changes applied")
	}
	return needRestart
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
				gw.profileMgr.SetActiveLink(l)
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

	// Attempt native TUN mode. tun2socks is always available (embedded on the
	// full build, pinned managed download on Lite), so a native failure is
	// recoverable through the transparent legacy path — never a proxy-only run.
	//
	// The legacy retry shares this deadline. Giving it a fresh total budget
	// would double the documented startup bound.
	parent := gw.startContext()
	total := gw.fallbackTotalTimeout()
	gw.startupDeadline = time.Now().Add(total)
	ctx, cancel := context.WithTimeout(parent, total)
	defer cancel()

	if err := gw.startEngineWithLinkFallbackCtx(ctx, link); err != nil {
		if err := parent.Err(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("startup fallback budget of %s exhausted: %w", total, err)
		}
		log.Printf("⚠️ Native TUN start failed: %v — retrying through tun2socks", err)
		gw.nativeTUN = false
		return gw.restartEngineAsLegacyCtx(ctx, link)
	}

	return nil
}

// restartEngineAsLegacy kills the current engine process (if any), regenerates config
// with GatewayMode=false, and restarts the engine in legacy (mixed-inbound) mode.
// It spends what is left of the startup budget instead of starting a new one.
func (gw *Gateway) restartEngineAsLegacy(link *profile.Link) error {
	budget := gw.fallbackTotalTimeout()
	if !gw.startupDeadline.IsZero() {
		if remaining := time.Until(gw.startupDeadline); remaining < budget {
			budget = remaining
		}
	}
	if budget <= 0 {
		return fmt.Errorf("startup budget exhausted before the tun2socks fallback could start")
	}
	ctx, cancel := context.WithTimeout(gw.startContext(), budget)
	defer cancel()
	return gw.restartEngineAsLegacyCtx(ctx, link)
}

func (gw *Gateway) restartEngineAsLegacyCtx(ctx context.Context, link *profile.Link) error {
	metrics.TunnelRestarts.Inc()
	gw.stopEngineLocked()

	// Temporarily disable NativeTUN so startEngine generates mixed-inbound config
	origNativeTUN := gw.config.Gateway.NativeTUN
	gw.config.Gateway.NativeTUN = false
	defer func() { gw.config.Gateway.NativeTUN = origNativeTUN }()

	gw.nativeTUN = false
	return gw.startEngineWithLinkFallbackCtx(ctx, link)
}

// Injectable seams for fallback tests. The real implementations start engines
// and probe the host network, which unit tests cannot do.
var (
	startEngineAttempt    = (*Gateway).startEngine
	startEnginePinned     = (*Gateway).startEnginePinned
	probeTunnelConnection = (*Gateway).verifyConnection
)

const (
	defaultEndpointFallbackTimeout = 90 * time.Second
	defaultTotalFallbackTimeout    = 5 * time.Minute
	defaultProbeTimeout            = 12 * time.Second
)

func parseFallbackDuration(raw string, fallback time.Duration) time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(raw)); err == nil && d > 0 {
		return d
	}
	return fallback
}

// fallbackEndpointTimeout bounds one link attempt: engine readiness plus the
// connectivity probes for that link.
func (gw *Gateway) fallbackEndpointTimeout() time.Duration {
	return parseFallbackDuration(gw.config.Engines.Fallback.EndpointTimeout, defaultEndpointFallbackTimeout)
}

// fallbackTotalTimeout bounds the whole startup chain across every group link.
func (gw *Gateway) fallbackTotalTimeout() time.Duration {
	return parseFallbackDuration(gw.config.Engines.Fallback.TotalTimeout, defaultTotalFallbackTimeout)
}

func (gw *Gateway) probeTimeout() time.Duration {
	return defaultProbeTimeout
}

// startEngineWithLinkFallback tries the given link first, then falls back to other links
// in the same group if the first one fails or can't connect.
// For each link it tries the preferred engine first, then falls back to the alternative
// engine (sing-box ↔ xray) before moving to the next link.
//
// Cancellation is honored at every step: the total budget context stops the
// chain, and Stop cancels the gateway context so an in-flight DNS lookup,
// handshake or probe returns immediately instead of waiting for its timeout.
//
// When every attempt failed before an engine could run (local configuration
// error), the returned error is permanent so the run loop stops instead of
// retrying a link that cannot work without an edit.
//
// The caller holds gw.mu: this runs inside the startup phase, and the cleanup
// it performs must not interleave with Stop's rollback.
func (gw *Gateway) startEngineWithLinkFallback(link *profile.Link) error {
	ctx, cancel := context.WithTimeout(gw.startContext(), gw.fallbackTotalTimeout())
	defer cancel()
	return gw.startEngineWithLinkFallbackCtx(ctx, link)
}

func (gw *Gateway) startEngineWithLinkFallbackCtx(ctx context.Context, link *profile.Link) error {
	total := gw.fallbackTotalTimeout()
	endpoint := gw.fallbackEndpointTimeout()

	attempts := 0
	var selectedErr error
	var fallbacks []linkAttempt
	record := func(failed *profile.Link, err error, selected bool) {
		err = outcomeError(failed, err)
		attempts++
		if selected {
			selectedErr = err
			return
		}
		fallbacks = append(fallbacks, linkAttempt{Link: linkLabel(failed), Err: err})
	}
	// stopped reports shutdown separately from the fallback budget expiring.
	stopped := func() error {
		if err := gw.startContext().Err(); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("startup fallback budget of %s exhausted: %w", total, err)
		}
		return nil
	}

	// Try active link first (with per-link engine fallback)
	if ok, err := gw.startLinkAttempt(ctx, endpoint, link); ok {
		gw.recordActiveLink(link)
		gw.clearFallbackNotice()
		return nil
	} else if stopErr := stopped(); stopErr != nil {
		return stopErr
	} else {
		record(link, err, true)
	}

	// Try other links in the group (use the active link's group, not config default)
	fallbackGroup := link.Group
	if fallbackGroup == "" {
		fallbackGroup = gw.config.Profiles.ActiveGroup
	}
	fail := func() error {
		failure := &linkFailure{
			Selected:  linkLabel(link),
			Group:     fallbackGroup,
			At:        time.Now(),
			Cause:     selectedErr,
			Fallbacks: fallbacks,
		}
		if attempts > 0 && failure.allLocalConfig() {
			return permanent(failure)
		}
		return failure
	}
	g, gerr := gw.profileMgr.GetGroup(fallbackGroup)
	if gerr != nil {
		return fail()
	}

	for _, candidate := range eligibleFallbackLinks(link, g.Links) {
		if err := stopped(); err != nil {
			return err
		}
		log.Printf("🔄 Trying link: [%s] %s → %s:%d", candidate.Protocol, candidate.Remark, candidate.Address, candidate.Port)

		if ok, err := gw.startLinkAttempt(ctx, endpoint, candidate); ok {
			gw.profileMgr.SetActiveLink(candidate)
			gw.recordActiveLink(candidate)
			gw.recordFallback(linkLabel(link), selectedErr)
			return nil
		} else if stopErr := stopped(); stopErr != nil {
			return stopErr
		} else {
			record(candidate, err, false)
		}
	}

	if err := stopped(); err != nil {
		return err
	}
	return fail()
}

// startLinkAttempt gives one link its own bounded context so a dead endpoint
// cannot consume the whole fallback budget.
func (gw *Gateway) startLinkAttempt(parent context.Context, endpoint time.Duration, link *profile.Link) (bool, error) {
	if err := parent.Err(); err != nil {
		return false, err
	}
	// An OpenVPN link may spend one handshake window on a pinned endpoint that
	// accepts TCP but never completes the tunnel, then retry another candidate.
	// Give it room for both windows plus the post-start connectivity probe
	// instead of letting the generic budget cancel the retry halfway.
	if link.Protocol == "openvpn" {
		if min := 2*engine.OpenVPNMinStartup + 15*time.Second; endpoint < min {
			endpoint = min
		}
	}
	ctx, cancel := context.WithTimeout(parent, endpoint)
	defer cancel()

	ok, err := gw.startEngineWithEngineFallback(ctx, link)
	// A canceled parent always wins: the caller must not start another link
	// while shutdown is in progress.
	if parentErr := parent.Err(); parentErr != nil {
		return false, parentErr
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return false, fmt.Errorf("link '%s' exceeded its %s attempt budget", link.Remark, endpoint)
	}
	return ok, err
}

// eligibleFallbackLinks filters the group's links down to those that may
// replace selected without weakening a security requirement.
func eligibleFallbackLinks(selected *profile.Link, links []*profile.Link) []*profile.Link {
	var out []*profile.Link
	for _, candidate := range links {
		if candidate == nil {
			continue
		}
		if selected != nil && candidate.Remark == selected.Remark {
			continue // skip the one we already tried
		}
		// Skip info-only links (port < 10 or address 0.0.0.0)
		if candidate.Port < 10 || candidate.Address == "" || candidate.Address == "0.0.0.0" {
			continue
		}
		if !engine.FallbackCompatible(selected, candidate) {
			log.Printf("  ⛔ Skipping link [%s] %s: does not match the selected VLESS Encryption policy", candidate.Protocol, candidate.Remark)
			continue
		}
		out = append(out, candidate)
	}
	return out
}

// startEngineWithEngineFallback starts an engine for the given link (with automatic
// engine fallback handled by FallbackController) then verifies connectivity.
// It reports whether the tunnel is usable and, on failure, the error that
// stopped startup (nil when only the connectivity probe failed).
func (gw *Gateway) startEngineWithEngineFallback(ctx context.Context, link *profile.Link) (bool, error) {
	if err := startEngineAttempt(gw, ctx, link); err != nil {
		log.Printf("  ❌ Engine start failed: %v", err)
		// A failed attempt may already have launched a process (for example a
		// deadline during the warm-up). Release the SOCKS port before the next
		// candidate, exactly like the probe failures below.
		gw.stopEngineLocked()
		gw.noteStartError(err)
		return false, err
	}

	// CDN-fronted VLESS proxies (e.g. Cloudflare port 2083) need a few seconds
	// to complete the WS/TLS handshake before the first DoH query can succeed.
	// Port-ready does not mean tunnel-ready: retry with backoff before giving up.
	delays := []time.Duration{0, 3 * time.Second, 5 * time.Second}
	for i, d := range delays {
		if d > 0 {
			log.Printf("  🔄 Connectivity check attempt %d/3 (waiting %s for tunnel warm-up)...", i+1, d)
			timer := time.NewTimer(d)
			select {
			case <-ctx.Done():
				timer.Stop()
				gw.stopEngineLocked()
				return false, ctx.Err()
			case <-timer.C:
			}
		}
		if probeTunnelConnection(gw, ctx) {
			if err := ctx.Err(); err != nil {
				gw.stopEngineLocked()
				return false, err
			}
			return true, nil
		}
		if ctx.Err() != nil {
			gw.stopEngineLocked()
			return false, ctx.Err()
		}
	}

	log.Printf("  ⚠️  Engine started but no connectivity")
	gw.stopEngineLocked()
	return false, nil
}

// verifyConnection checks if the SOCKS proxy can reach the actual internet
// through the tunnel — NOT just Cloudflare's own CDN edge.
//
// CDN-based VLESS proxies (*.example.net, *.example.org via Cloudflare port 2083)
// always return 204 for "Host: cp.cloudflare.com / http://1.1.1.1" because
// the CDN edge answers locally without actually forwarding through the tunnel.
// We must verify with a NON-Cloudflare target to detect real connectivity.
func (gw *Gateway) verifyConnection(ctx context.Context) bool {
	// Called while the lifecycle lock is held, so the config and port reads
	// below cannot race a reload.
	listen := strings.TrimSpace(gw.config.Server.SOCKSListen)
	port := gw.socksPort
	if listen == "" || listen == "0.0.0.0" || listen == "::" {
		listen = "127.0.0.1"
	}
	addr := net.JoinHostPort(listen, strconv.Itoa(port))

	// Candidates: non-Cloudflare targets that return predictable HTTP responses.
	// The in-process SOCKS client sends hostnames to the proxy (remote DNS), so
	// no local resolver or external curl binary is required.
	candidates := []struct {
		url      string
		wantCode int
	}{
		// Google's generate_204 — returns exactly 204, not Cloudflare.
		{"http://www.gstatic.com/generate_204", 204},
		// Microsoft connectivity check.
		{"http://www.msftconnecttest.com/connecttest.txt", 200},
		// Apple captive portal check.
		{"http://captive.apple.com/hotspot-detect.html", 200},
	}

	probeTimeout := gw.probeTimeout()
	for _, c := range candidates {
		if ctx.Err() != nil {
			return false
		}
		probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
		_, code, err := profile.GetThroughProxyAt(probeCtx, addr, c.url, nil, 4<<10)
		cancel()
		if err == nil && code == c.wantCode {
			return true
		}
	}
	return false
}

func isCatchAllMatcher(match string) bool {
	switch strings.ReplaceAll(match, " ", "") {
	case "default", "ip_cidr:0.0.0.0/0":
		return true
	}
	return false
}

// defaultOutboundLabel names the outbound the rules send unmatched traffic to.
func defaultOutboundLabel(cfg *config.Config) string {
	out := "proxy"
	for _, r := range cfg.Routing.Rules {
		if isCatchAllMatcher(r.Match) {
			out = r.Outbound
		}
	}
	return out
}

// startEngine starts an engine for the link. An OpenVPN link whose pinned
// endpoint accepts TCP but never completes a handshake is retried with the
// next validated candidate before the link is declared failed: OpenVPN
// round-robin records can name such endpoints, and TCP reachability cannot
// distinguish them from healthy ones.
func (gw *Gateway) startEngine(ctx context.Context, link *profile.Link) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	log.Printf("🔧 Starting engine for [%s] %s...", link.Protocol, link.Remark)

	sets := gw.pinnedHostSetsFor(ctx, link)
	tried := map[string]bool{}
	attempts := 0
	reresolved := false
	failedPins := map[string]string{}
	var lastErr error
	for attempts < openVPNMaxEndpointAttempts {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(sets) == 0 {
			// OpenVPN rotates its A records: once every known candidate has
			// failed, one fresh lookup can name an entry point that was not in
			// the original answer.
			if link.Protocol != "openvpn" || reresolved {
				break
			}
			reresolved = true
			log.Printf("  🔄 OpenVPN endpoint candidates exhausted; re-resolving %s", link.Address)
			for _, s := range gw.pinnedHostSetsFor(ctx, link) {
				if !tried[pinSetKey(s)] {
					sets = append(sets, s)
				}
			}
			continue
		}
		pins := sets[0]
		sets = sets[1:]
		key := pinSetKey(pins)
		if tried[key] {
			continue
		}
		tried[key] = true
		if attempts > 0 {
			log.Printf("  🔄 OpenVPN endpoint %s did not complete a handshake; trying %s", describePinSet(failedPins), describePinSet(pins))
		}
		attempts++
		lastErr = startEnginePinned(gw, ctx, link, pins)
		if lastErr == nil {
			return nil
		}
		failedPins = pins
		if errors.Is(lastErr, engine.ErrLocalConfig) || link.Protocol != "openvpn" {
			return lastErr
		}
	}
	if lastErr == nil || link.Protocol != "openvpn" {
		return lastErr
	}
	return fmt.Errorf("all OpenVPN endpoint candidates failed for link '%s': %w", link.Remark, lastErr)
}

// startEnginePinned starts an engine with the given host pins.
func (gw *Gateway) startEnginePinned(ctx context.Context, link *profile.Link, pinnedHosts map[string]string) error {
	// Build config generator (shared across all fallback engine attempts).
	configGen := tunnel.NewConfigGenerator(paths.Get().TmpDir)
	configGen.PinnedHosts = pinnedHosts
	configGen.ProfileDir = gw.profilesDirectory()
	if len(gw.config.Routing.Rules) > 0 {
		rules := make([]tunnel.RoutingRule, len(gw.config.Routing.Rules))
		for i, r := range gw.config.Routing.Rules {
			rules[i] = tunnel.RoutingRule{Match: r.Match, Outbound: r.Outbound}
		}
		configGen.RoutingRules = rules
		configGen.ExternalOutbounds = gw.config.Routing.ExternalOutbounds
	} else {
		configGen.WhitelistCountries = gw.config.Whitelist.Countries
		configGen.GeositeCountries = gw.config.Whitelist.GeositeCountries
		if len(configGen.GeositeCountries) == 0 {
			configGen.GeositeCountries = gw.config.Whitelist.Countries
		}
		configGen.BypassDomains = gw.config.Whitelist.BypassDomains
		configGen.ForceProxyDomains = gw.config.Whitelist.ForceProxyDomains
	}
	configGen.DNSUpstream = gw.config.Gateway.DNSUpstream
	if len(gw.config.Gateway.LocalDNS) > 0 {
		rules := make([]tunnel.LocalDNSRule, 0, len(gw.config.Gateway.LocalDNS))
		for _, entry := range gw.config.Gateway.LocalDNS {
			if entry.Server != "" && len(entry.Domains) > 0 {
				rules = append(rules, tunnel.LocalDNSRule{Server: entry.Server, Domains: entry.Domains})
			}
		}
		configGen.LocalDNSRules = rules
	}
	configGen.SOCKSPort = gw.socksPort
	configGen.SOCKSListen = gw.config.Server.SOCKSListenAddress()
	configGen.SOCKSUsername = gw.config.Server.SOCKSUsername
	configGen.SOCKSPassword = gw.config.Server.SOCKSPassword
	if gw.config.SNISpoof.Enabled {
		configGen.SNISpoof = gw.config.SNISpoof.SNI
	}
	if gw.config.Gateway.Enabled && gw.config.Gateway.NativeTUN {
		configGen.GatewayMode = true
		configGen.DNSPort = gw.dnsPort
	}

	// Try embedded (in-process) engine first if one is registered (full build only).
	preferredName := gw.config.Engines.PreferredEngine
	if engine.RequiresXray(link) {
		// XHTTP and VLESS Encryption are xray-only. Falling back to sing-box
		// would silently drop the encryption parameters, so this is a hard choice.
		if preferredName != "" && preferredName != "xray" {
			log.Printf("  ⚠️  Profile requires xray; ignoring configured engine %q", preferredName)
		}
		preferredName = "xray"
	}
	if link.Protocol == "openvpn" {
		preferredName = "sing-box"
	}
	if preferredName == "" && len(gw.config.Engines.Fallback.Order) > 0 {
		preferredName = gw.config.Engines.Fallback.Order[0]
	}
	if preferredName == "" {
		preferredName = "sing-box"
	}
	// OpenVPN endpoints need sing-box >= 1.14; only the verified external binary
	// path is supported, so skip the embedded runner for these profiles.
	if factory, ok := engine.GetEmbedded(preferredName); ok && link.Protocol != "openvpn" {
		configFile, cfgErr := configGen.Generate(&engine.Engine{Name: preferredName}, link)
		if cfgErr == nil {
			runner, runErr := factory(configFile)
			if runErr == nil {
				if startErr := runner.Start(); startErr == nil {
					// The in-process runner is only usable once our own process
					// owns the SOCKS listener; a fixed sleep reported success
					// for engines that had already died.
					if ownErr := engine.WaitForOwnedListener(ctx, os.Getpid(), gw.socksPort, 10*time.Second); ownErr != nil {
						runner.Stop() //nolint:errcheck
						configGen.DiscardConfig(configFile)
						log.Printf("  ⚠️  Embedded %s does not own :%d: %v — falling back to binary", preferredName, gw.socksPort, ownErr)
					} else if portErr := waitForPortContext(ctx, gw.socksPort, 5*time.Second); portErr != nil {
						runner.Stop() //nolint:errcheck
						configGen.DiscardConfig(configFile)
						log.Printf("  ⚠️  Embedded %s listener is not answering: %v — falling back to binary", preferredName, portErr)
					} else {
						gw.embeddedEngine = runner
						gw.setEmbedded(runner)
						gw.activeEngine = preferredName
						gw.setRuntimeEngine(preferredName)
						gw.configFile = configFile
						log.Printf("  ✅ %s running in-process (embedded) on :%d", preferredName, gw.socksPort)
						// Only sing-box non-OpenVPN profiles get a TUN inbound. Xray
						// has no TUN and the OpenVPN generator emits SOCKS only, so
						// claiming native TUN there would wait for a device that is
						// never created and skip tun2socks.
						gw.nativeTUN = gw.config.Gateway.Enabled && gw.config.Gateway.NativeTUN &&
							preferredName == "sing-box" && link.Protocol != "openvpn" && !engine.RequiresXray(link)
						return nil
					}
				} else {
					configGen.DiscardConfig(configFile)
					log.Printf("  ⚠️  Embedded %s start failed: %v — falling back to binary", preferredName, startErr)
				}
			} else {
				configGen.DiscardConfig(configFile)
				log.Printf("  ⚠️  Embedded %s init failed: %v — falling back to binary", preferredName, runErr)
			}
		} else {
			configGen.DiscardGeneration()
			log.Printf("  ⚠️  Embedded %s config gen failed: %v — falling back to binary", preferredName, cfgErr)
		}
	}

	// FallbackController handles engine selection and startup with automatic fallback.
	// The startup ctx bounds readiness and probes; the gateway root context owns
	// the process so a successful engine survives the per-attempt deadline.
	fc := engine.NewFallbackController(gw.engineMgr, gw.config.Engines.Fallback, configGen, gw.socksPort)
	result, err := fc.StartWithLifetime(ctx, gw.startContext(), link, gw.config.Engines.PreferredEngine)
	if err != nil {
		if errors.Is(err, engine.ErrLocalConfig) {
			return permanent(err)
		}
		return err
	}

	gw.engineProc = result.Process
	gw.setEngineWaiter(result.Waiter)
	gw.activeEngine = result.EngineName
	gw.setRuntimeEngine(result.EngineName)
	gw.configFile = result.ConfigFile
	// Track the engine so a hard stop or the next startup can kill only
	// bypath-owned children on every platform (no pkill on Windows).
	trackChildPID(result.Process.Process.Pid)

	// Give the engine a moment to fully initialize outbound connections.
	timer := time.NewTimer(2 * time.Second)
	select {
	case <-ctx.Done():
		timer.Stop()
		// The process is already assigned and owns the SOCKS port. Leaving it
		// running would make every later candidate fail on "port in use".
		gw.stopEngineLocked()
		return ctx.Err()
	case <-timer.C:
	}

	log.Printf("  ✅ %s running on :%d (PID: %d)", result.EngineName, gw.socksPort, gw.engineProc.Process.Pid)

	// Mark native TUN as active only when sing-box actually generated one.
	// xray provides SOCKS only, and the OpenVPN generator emits SOCKS inbounds
	// without a TUN, so both must use the tun2socks data path.
	gw.nativeTUN = gw.config.Gateway.Enabled && gw.config.Gateway.NativeTUN &&
		result.EngineName == "sing-box" && link.Protocol != "openvpn" && !engine.RequiresXray(link)

	return nil
}

// disableSystemdResolved temporarily stops systemd-resolved when it holds
// port 53. It is deliberately not disabled persistently: cleanup restarts the
// service so a reboot keeps the host's original resolver configuration.
// systemd-resolved binds to port 53 (127.0.0.53 and/or 127.0.0.54) which
// prevents dns2socks/dnsmasq from binding to 0.0.0.0:53.
// Common on Debian 12+, Ubuntu 18+. Not present on Armbian minimal.
//
// Ownership is persisted before the service or resolver file is touched. A
// persistence failure is returned and leaves the host untouched.
func (gw *Gateway) disableSystemdResolved() (bool, error) {
	// In a private network namespace the resolver services of the host are
	// irrelevant: their port 53 belongs to another network stack, and stopping
	// them would break host DNS for no benefit.
	if networkNamespaceIsolated() {
		return false, nil
	}
	out, err := systemctlOutput("is-active", "systemd-resolved")
	if err != nil || strings.TrimSpace(string(out)) != "active" {
		return false, nil // not running, nothing to do
	}

	log.Printf("  ⚠️  systemd-resolved is active (conflicts with port 53) — stopping temporarily...")

	// Record ownership before the service changes, so a crash still restores it.
	st, err := gw.ensureRunState("pending")
	if err != nil {
		return false, err
	}
	st.ResolvedStopped = true
	if err := gw.persistRunState(); err != nil {
		st.ResolvedStopped = false
		return false, err
	}

	if err := systemctlRun("stop", "systemd-resolved"); err != nil {
		// The record keeps the flag: the service may have stopped despite the
		// error, and the next recovery run will restore it.
		return false, fmt.Errorf("stopping systemd-resolved: %w", err)
	}

	// If the resolver is the systemd stub symlink, remember its target so
	// cleanup can restore it exactly instead of degrading it to plain 1.1.1.1.
	if _, statErr := os.Stat(resolvLinkBackup); os.IsNotExist(statErr) {
		if target, linkErr := os.Readlink(resolvConfPath); linkErr == nil && strings.Contains(target, "systemd") {
			if err := writeFileAtomic(resolvLinkBackup, []byte(target), 0600); err != nil {
				return false, fmt.Errorf("saving the systemd-resolved stub target: %w", err)
			}
		}
	}
	if target, linkErr := os.Readlink(resolvConfPath); linkErr == nil && strings.Contains(target, "systemd") {
		st.ResolvChanged = true
		if err := gw.persistRunState(); err != nil {
			st.ResolvChanged = false
			return false, err
		}
		if err := os.Remove(resolvConfPath); err != nil && !os.IsNotExist(err) {
			return false, fmt.Errorf("detaching %s: %w", resolvConfPath, err)
		}
		if err := writeResolvConf(resolvConfPath, []byte("nameserver 1.1.1.1\nnameserver 8.8.8.8\n"), 0644); err != nil {
			return false, fmt.Errorf("writing %s: %w", resolvConfPath, err)
		}
		log.Printf("  ✅ /etc/resolv.conf detached from systemd-resolved stub (target remembered)")
	}

	log.Printf("  ✅ systemd-resolved stopped (will be restarted on cleanup)")
	return true, nil
}

// dnsPolicy is the explicit DNS leak policy for gateway mode.
type dnsPolicy int

const (
	// dnsPolicyStrict resolves DNS only through the tunnel. A failed lookup is
	// answered with SERVFAIL; it never falls back to direct upstream DNS.
	dnsPolicyStrict dnsPolicy = iota
	// dnsPolicyLocal explicitly permits direct upstream DNS queries.
	dnsPolicyLocal
)

// parseDNSMode maps gateway.dns_mode to a policy. An unknown value is an error
// (fail closed) rather than a silent fallback to direct DNS.
func parseDNSMode(mode string) (dnsPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "strict":
		return dnsPolicyStrict, nil
	case "local":
		return dnsPolicyLocal, nil
	default:
		return dnsPolicyStrict, fmt.Errorf("unsupported gateway.dns_mode %q (use \"strict\" or \"local\")", mode)
	}
}

func (p dnsPolicy) allowsDirectDNS() bool { return p == dnsPolicyLocal }

// dnsServerAddr appends the default DNS port unless the upstream already has one.
func dnsServerAddr(upstream string) string {
	if _, _, err := net.SplitHostPort(upstream); err == nil {
		return upstream
	}
	if strings.HasPrefix(upstream, "[") && strings.HasSuffix(upstream, "]") {
		return upstream + ":53"
	}
	return net.JoinHostPort(upstream, "53")
}

// dohURLFor turns a configured upstream into a DoH endpoint. A value that is
// already a URL is validated and used unchanged; otherwise an explicit port is
// preserved (the default 443 is omitted), IPv6 literals are bracketed and
// /dns-query is appended. Invalid input is a controlled error: a malformed
// endpoint must never become a nil request or a direct-DNS fallback.
func dohURLFor(upstream string) (string, error) {
	up := strings.TrimSpace(upstream)
	if up == "" {
		return "", fmt.Errorf("empty DNS upstream")
	}
	if strings.HasPrefix(up, "https://") || strings.HasPrefix(up, "http://") {
		parsed, err := url.Parse(up)
		if err != nil {
			return "", fmt.Errorf("invalid DoH URL %q: %w", up, err)
		}
		if parsed.Scheme != "https" && parsed.Scheme != "http" {
			return "", fmt.Errorf("invalid DoH URL %q: unsupported scheme %q", up, parsed.Scheme)
		}
		if parsed.Host == "" {
			return "", fmt.Errorf("invalid DoH URL %q: missing host", up)
		}
		return up, nil
	}
	host, port := up, ""
	if h, p, err := net.SplitHostPort(up); err == nil {
		host, port = h, p
	}
	if host == "" {
		return "", fmt.Errorf("invalid DNS upstream %q", upstream)
	}
	authority := host
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		authority = "[" + host + "]"
	}
	if port != "" && port != "443" {
		authority += ":" + port
	}
	return "https://" + authority + "/dns-query", nil
}

// buildDoHURLs validates every configured upstream before the DNS listener is
// started. One malformed endpoint rejects the whole set instead of silently
// running with a partially working resolver.
func buildDoHURLs(upstreams []string) ([]string, error) {
	urls := make([]string, 0, len(upstreams))
	for _, up := range upstreams {
		u, err := dohURLFor(up)
		if err != nil {
			return nil, err
		}
		urls = append(urls, u)
	}
	return urls, nil
}

// dnsWarmupTimeout bounds how long startup waits for the resolver to prove it
// can answer a query through the tunnel. A bound port is not readiness: DoH
// through a freshly started tunnel can fail while the handshake completes.
const dnsWarmupTimeout = 20 * time.Second

// dohRequestTimeout bounds one DoH exchange. Without a bound, a resolver whose
// :443 path silently drops packets stalls the forwarder indefinitely, so the
// local policy's direct UDP fallback is never attempted.
const dohRequestTimeout = 8 * time.Second

// udpQueryTimeout bounds one direct UDP attempt under the local policy.
const udpQueryTimeout = 4 * time.Second

// dnsForwardBudget is the longest a single query can occupy the forwarder:
// every upstream gets a DoH attempt, and under the local policy every upstream
// also gets one direct UDP attempt. Readiness has to outlast that budget, or it
// gives up while the forwarder is still working and reports a false failure.
func dnsForwardBudget(upstreams []string, allowDirect bool) time.Duration {
	budget := time.Duration(len(upstreams)) * dohRequestTimeout
	if allowDirect {
		budget += time.Duration(len(upstreams)) * udpQueryTimeout
	}
	return budget + time.Second
}

// dnsWarmup is the readiness budget for this configuration: the floor, or the
// forwarder's own worst case when that is longer.
func (gw *Gateway) dnsWarmup() time.Duration {
	allowDirect := false
	if policy, err := parseDNSMode(gw.config.Gateway.DNSMode); err == nil {
		allowDirect = policy.allowsDirectDNS()
	}
	warmup := dnsForwardBudget(gw.config.Gateway.DNSUpstream, allowDirect)
	if warmup < dnsWarmupTimeout {
		warmup = dnsWarmupTimeout
	}
	return warmup
}

// verifyDNSReady sends a real query to bypath's own resolver and requires a
// success answer. Without this, the gateway can report CONNECTED while clients
// receive SERVFAIL — the exact "gateway is up but nothing resolves" failure.
// Each attempt is bounded by the remaining warmup deadline rather than a
// per-query constant, so one complete forwarder path can finish.
func (gw *Gateway) verifyDNSReady(timeout time.Duration) error {
	addr := fmt.Sprintf("127.0.0.1:%d", gw.dnsPort)
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		if err := gw.ctx.Err(); err != nil {
			return err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("DNS proxy did not answer a tunneled query within %s: %w", timeout, lastErr)
		}
		client := &dns.Client{Net: "udp", Timeout: remaining}
		query := new(dns.Msg)
		query.SetQuestion("example.com.", dns.TypeA)
		resp, _, err := client.ExchangeContext(gw.ctx, query, addr)
		if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0 {
			log.Printf("  ✅ DNS resolves through the tunnel (%s answered)", addr)
			return nil
		}
		switch {
		case err != nil:
			lastErr = err
		default:
			lastErr = fmt.Errorf("resolver answered %s without records", dns.RcodeToString[resp.Rcode])
		}
		select {
		case <-gw.ctx.Done():
			return gw.ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (gw *Gateway) startDNS() error {
	log.Printf("🔀 Starting DNS proxy on :%d...", gw.dnsPort)

	policy, err := parseDNSMode(gw.config.Gateway.DNSMode)
	if err != nil {
		return err
	}
	if policy.allowsDirectDNS() {
		log.Printf("  ⚠️  DNS policy: local — direct upstream queries are explicitly permitted")
	} else {
		log.Printf("  🔒 DNS policy: strict — queries resolve through the tunnel; failures return SERVFAIL (no direct fallback)")
	}

	// Stop systemd-resolved if it is occupying port 53 (gateway mode only).
	stopped, err := gw.disableSystemdResolved()
	if err != nil {
		return fmt.Errorf("freeing port 53: %w", err)
	}
	if stopped {
		gw.resolvedStopped = true
	}
	// Also stop dnsmasq: it binds port 53 at boot on many Armbian/Debian setups and
	// causes dns2socks to fail silently (waitForPort returns true because dnsmasq is
	// already there, so bypath thinks dns2socks started when it actually crashed).
	if err := gw.stopDnsmasq(); err != nil {
		return err
	}

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

	// When local_dns rules are configured, dns2socks cannot handle per-domain routing —
	// it forwards everything to a single upstream through the tunnel. Skip it and use
	// the built-in DNS forwarder which routes local suffixes directly to the home DNS.
	if len(gw.config.Gateway.LocalDNS) > 0 {
		log.Printf("  ℹ️  local_dns configured — using built-in DNS for per-domain routing")
		return gw.startBuiltinDNS(upstream, policy)
	}

	// Try dns2socks first (routes DNS through the tunnel — preferred).
	// dns2socks takes a single upstream; use the first configured one.
	dns2socksPath, err := exec.LookPath("dns2socks")
	if err == nil {
		gw.dnsProc = exec.CommandContext(gw.ctx, dns2socksPath,
			"-l", fmt.Sprintf("0.0.0.0:%d", gw.dnsPort),
			"-d", dnsServerAddr(upstream[0]),
			"-s", fmt.Sprintf("socks5://127.0.0.1:%d", gw.socksPort),
			"-f", "-c",
		)
		if err := gw.dnsProc.Start(); err != nil {
			return fmt.Errorf("starting dns2socks: %w", err)
		}
		if err := waitForPortContext(gw.ctx, gw.dnsPort, 5*time.Second); err != nil {
			return fmt.Errorf("dns2socks didn't start: %w", err)
		}
		// Verify dns2socks itself is still alive — waitForPort can return true because
		// another process (dnsmasq, systemd-resolved) was already on the port, masking
		// the fact that dns2socks exited immediately after failing to bind.
		if _, statErr := os.Stat(fmt.Sprintf("/proc/%d", gw.dnsProc.Process.Pid)); statErr != nil {
			return fmt.Errorf("dns2socks exited immediately (another process may still hold port %d)", gw.dnsPort)
		}
		trackChildPID(gw.dnsProc.Process.Pid)
		log.Printf("  ✅ dns2socks running on :%d → %s (DNS through tunnel)", gw.dnsPort, upstream[0])
		return nil
	}

	// dnsmasq forwards DNS directly, which leaks queries outside the tunnel. It
	// is only usable when the operator has explicitly selected the local policy.
	if policy.allowsDirectDNS() {
		if dnsmasqPath, err := exec.LookPath("dnsmasq"); err == nil {
			args := []string{"--no-daemon", "--no-resolv", "--listen-address=0.0.0.0", "--bind-interfaces"}
			for _, ns := range upstream {
				args = append(args, "--server="+ns)
			}
			gw.dnsProc = exec.CommandContext(gw.ctx, dnsmasqPath, args...)
			if err := gw.dnsProc.Start(); err != nil {
				return fmt.Errorf("starting dnsmasq: %w", err)
			}
			trackChildPID(gw.dnsProc.Process.Pid)
			log.Printf("  ⚠️  dnsmasq running → %v (DNS policy local: direct DNS explicitly allowed)", upstream)
			return nil
		}
	}

	// Last resort: built-in DNS forwarder (no external tool needed). In strict
	// mode it resolves DoH through the proxy and never falls back to UDP.
	return gw.startBuiltinDNS(upstream, policy)
}

// startBuiltinDNS starts a DNS forwarder using DoH (DNS-over-HTTPS) routed through
// the SOCKS5 proxy. This avoids ISP DNS hijacking/poisoning for blocked sites.
// In strict policy a failed DoH lookup is answered with SERVFAIL; direct UDP is
// only used when the operator explicitly selected the local policy. Declared
// local_dns suffixes are always sent to their configured home DNS server.
func (gw *Gateway) startBuiltinDNS(upstreams []string, policy dnsPolicy) error {
	// Build DoH URLs from the configured upstreams. An explicit URL is validated
	// and used as given; an address gains the standard /dns-query path, keeping a
	// non-443 port and bracketing IPv6 literals so the URL is always well formed.
	dohURLs, err := buildDoHURLs(upstreams)
	if err != nil {
		return fmt.Errorf("built-in DNS: %w", err)
	}

	// HTTP client that tunnels through SOCKS5 (xray) — avoids ISP DNS hijacking.
	socksAddr := fmt.Sprintf("127.0.0.1:%d", gw.socksPort)
	proxyHTTP := &http.Client{
		Timeout: dohRequestTimeout,
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

	// Fallback: plain UDP client (direct, no proxy). Used only under the local
	// policy; forwardDNS never reaches it in strict mode.
	udpClient := &dns.Client{Net: "udp", Timeout: udpQueryTimeout}

	// Local DNS clients: per-domain, sent directly to the declared home DNS.
	var localDNS []localDNSEntry
	for _, entry := range gw.config.Gateway.LocalDNS {
		if entry.Server != "" && len(entry.Domains) > 0 {
			localDNS = append(localDNS, localDNSEntry{
				suffixes: entry.Domains,
				server:   entry.Server,
			})
		}
	}
	if len(localDNS) > 0 {
		log.Printf("  ℹ️  local_dns: %d suffix rule(s) resolve via their configured home DNS (explicit policy)", len(localDNS))
		if !policy.allowsDirectDNS() {
			log.Printf("  ⚠️  local_dns bypasses the tunnel by design: only the declared suffixes are sent directly; every other query stays on DoH via the proxy")
		}
	}

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		resp := forwardDNS(gw.ctx, r, proxyHTTP, udpClient, dohURLs, upstreams, localDNS, policy)
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
	mode := "strict: DoH via proxy, no direct fallback"
	if policy.allowsDirectDNS() {
		mode = "local: DoH via proxy, direct UDP permitted"
	}
	log.Printf("  ✅ Built-in DNS forwarder on :%d → %s (%v)", gw.dnsPort, mode, upstreams)
	return nil
}

// localDNSEntry routes a set of domain suffixes to one explicitly configured
// home DNS server. Direct access is part of the declared policy.
type localDNSEntry struct {
	suffixes []string
	server   string
}

// forwardDNS resolves one query. DoH through the proxy is always tried first.
// Direct UDP is attempted only when the policy explicitly allows it, so a
// disconnect or DoH failure yields SERVFAIL instead of a DNS leak.
func forwardDNS(ctx context.Context, r *dns.Msg, proxyHTTP *http.Client, udpClient *dns.Client, dohURLs, upstreams []string, localDNS []localDNSEntry, policy dnsPolicy) *dns.Msg {
	// Check local DNS rules first — private TLDs (e.g. .home) go directly to the
	// home DNS server declared by the operator, bypassing the tunnel entirely.
	if len(r.Question) > 0 && len(localDNS) > 0 {
		qname := strings.TrimSuffix(strings.ToLower(r.Question[0].Name), ".")
		for _, entry := range localDNS {
			for _, suffix := range entry.suffixes {
				sfx := strings.ToLower(suffix)
				if qname == sfx || strings.HasSuffix(qname, "."+sfx) {
					resp, _, err := udpClient.ExchangeContext(ctx, r, dnsServerAddr(entry.server))
					if err == nil {
						return resp
					}
					// Local DNS unreachable — return NXDOMAIN so clients don't hang.
					log.Printf("⚠️  local DNS %s unreachable for %s: %v", entry.server, qname, err)
					nxd := new(dns.Msg)
					nxd.SetRcode(r, dns.RcodeNameError)
					return nxd
				}
			}
		}
	}

	packed, err := r.Pack()
	if err == nil {
		for _, dohURL := range dohURLs {
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, dohURL,
				bytes.NewReader(packed))
			if reqErr != nil {
				// A malformed endpoint is a configuration error. Skipping it must
				// never turn into a nil request or a direct-DNS fallback.
				log.Printf("⚠️  invalid DoH endpoint %q: %v", dohURL, reqErr)
				continue
			}
			req.Header.Set("Content-Type", "application/dns-message")
			req.Header.Set("Accept", "application/dns-message")
			resp, err := proxyHTTP.Do(req)
			if err == nil {
				body, readErr := io.ReadAll(resp.Body)
				resp.Body.Close()
				m := new(dns.Msg)
				if readErr == nil && m.Unpack(body) == nil {
					return m
				}
			}
		}
	}

	if !policy.allowsDirectDNS() {
		return nil
	}
	// Local policy: proxy unavailable — fall back to direct UDP.
	for _, up := range upstreams {
		resp, _, err := udpClient.ExchangeContext(ctx, r, dnsServerAddr(up))
		if err == nil {
			return resp
		}
	}
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

// tun2socksCandidate is one resolvable tun2socks binary and the cleanup its
// source needs when extraction produced a temporary file.
type tun2socksCandidate struct {
	path    string
	source  string
	resolve func() (string, string, error) // lazy lookup, used when path is empty
	cleanup func()
}

// tun2socksCandidates returns the binaries to try, most trusted first: the
// embedded copy (full build), then the pinned managed download, then an
// operator-installed binary. The managed copy makes Lite self-contained instead
// of depending on a manually installed helper. It is resolved lazily so an
// embedded binary never triggers a network fetch.
//
// A build that embeds the helper must not fall back when that payload is
// unusable: silently running a download or PATH binary instead would hide a
// packaging defect and change which executable the gateway runs.
func (gw *Gateway) tun2socksCandidates() ([]tun2socksCandidate, error) {
	if embedbin.HasEmbedded() {
		extracted, err := embedbin.ExtractTun2socks()
		if err != nil {
			return nil, fmt.Errorf("embedded tun2socks is not usable: %w", err)
		}
		// The embedded helper is the only binary this build verified. A helper
		// that extracts but cannot exec is a packaging or filesystem defect, and
		// falling back to a download or a PATH binary would hide it.
		return []tun2socksCandidate{{
			path:    extracted,
			source:  "embedded",
			cleanup: func() { os.Remove(extracted) },
		}}, nil
	}
	var out []tun2socksCandidate
	if gw.engineMgr != nil {
		manager := gw.engineMgr
		out = append(out, tun2socksCandidate{
			source: "managed",
			resolve: func() (string, string, error) {
				eng, err := manager.EnsureManaged("tun2socks")
				if err != nil {
					return "", "", err
				}
				return eng.Path, "managed (" + eng.Source + ")", nil
			},
		})
	}
	if path, err := exec.LookPath("tun2socks"); err == nil {
		out = append(out, tun2socksCandidate{path: path, source: "system"})
	}
	return out, nil
}

func (gw *Gateway) startTun() error {
	if runtime.GOOS == "windows" {
		return fmt.Errorf("TUN gateway mode not supported on Windows (use proxy mode)")
	}

	log.Printf("🔧 Setting up TUN device...")

	candidates, err := gw.tun2socksCandidates()
	if err != nil {
		return err
	}
	defer func() {
		for _, c := range candidates {
			if c.cleanup != nil {
				c.cleanup()
			}
		}
	}()
	if len(candidates) == 0 {
		return fmt.Errorf("no tun2socks binary available (embedded, pinned managed download, or PATH)")
	}

	// Never delete an interface bypath cannot prove it owns. A leftover tun0
	// from this same run is recreated; any other tun0 is a hard error.
	if linkExists("tun0") {
		if !gw.tunCreated {
			return fmt.Errorf("tun0 already exists and is not owned by this bypath run; refusing to delete it")
		}
		if err := run("ip", "link", "del", "tun0"); err != nil {
			return fmt.Errorf("removing previous bypath tun0: %w", err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	st, err := gw.ensureRunState("legacy")
	if err != nil {
		return err
	}
	st.TunCreated = true
	if err := saveGatewayState(st); err != nil {
		return fmt.Errorf("recording tun0 ownership: %w", err)
	}

	// Create TUN
	if err := run("ip", "tuntap", "add", "mode", "tun", "dev", "tun0"); err != nil {
		st.TunCreated = false
		if saveErr := saveGatewayState(st); saveErr != nil {
			return fmt.Errorf("creating tun0: %w (recording rollback state also failed: %v)", err, saveErr)
		}
		return fmt.Errorf("creating tun0: %w", err)
	}
	gw.tunCreated = true
	if err := run("ip", "addr", "add", "10.0.0.1/24", "dev", "tun0"); err != nil {
		return fmt.Errorf("assigning IP to tun0: %w", err)
	}
	if err := run("ip", "link", "set", "tun0", "up"); err != nil {
		return fmt.Errorf("bringing up tun0: %w", err)
	}

	// Start tun2socks. A binary that cannot open the TUN device (no /dev/net/tun,
	// noexec temp dir) exits immediately, so each candidate is given a short
	// liveness window before it is accepted.
	var lastErr error
	for _, c := range candidates {
		if c.path == "" && c.resolve != nil {
			path, source, err := c.resolve()
			if err != nil {
				log.Printf("  ⚠️  tun2socks %s unavailable: %v", c.source, err)
				lastErr = fmt.Errorf("%s: %w", c.source, err)
				continue
			}
			c.path, c.source = path, source
		}
		proc := exec.CommandContext(gw.ctx, c.path,
			"-device", "tun0",
			"-proxy", fmt.Sprintf("socks5://127.0.0.1:%d", gw.socksPort),
		)
		if err := proc.Start(); err != nil {
			lastErr = fmt.Errorf("%s (%s): %w", c.path, c.source, err)
			continue
		}
		waiter := engine.WaitAsync(proc)
		trackChildPID(proc.Process.Pid)
		select {
		case <-waiter.Done():
			lastErr = fmt.Errorf("%s (%s) exited during startup: %v", c.path, c.source, waiter.Err())
			continue
		case <-gw.ctx.Done():
			_ = proc.Process.Kill()
			waiter.Wait(5 * time.Second)
			return gw.ctx.Err()
		case <-time.After(1500 * time.Millisecond):
		}

		gw.tunProc = proc
		gw.setTunWaiter(waiter)
		log.Printf("  ✅ tun2socks running from %s (tun0 → socks5://127.0.0.1:%d)", c.source, gw.socksPort)
		return nil
	}
	return fmt.Errorf("starting tun2socks: %w", lastErr)
}

// setupRouting applies host networking as a transaction. Every operation that
// can be undone is recorded in the ownership state before it is applied, and
// the first failure aborts startup so the caller can roll back exactly what was
// changed.
func (gw *Gateway) setupRouting() error {
	if !gw.config.Gateway.Enabled {
		return nil
	}
	log.Printf("🔧 Configuring routing...")

	mode := "legacy"
	if gw.nativeTUN {
		mode = "native"
	}
	st, err := gw.ensureRunState(mode)
	if err != nil {
		return err
	}
	gw.networkMutated = true
	gw.legacyRoutingActive = !gw.nativeTUN

	// Containment first: the guard chain drops every forwarded packet from the
	// LAN while the real chains are flushed and rebuilt. A retained chain from a
	// previous run is adopted here, so a restart never has an uncontained gap.
	if err := ensureGuardContainment(gw.iface); err != nil {
		return fmt.Errorf("installing fail-closed forwarding guard: %w", err)
	}

	// IPv6 containment is applied before any IPv4 routing is installed, in both
	// gateway modes: a partially configured startup must never leave LAN IPv6
	// able to leave via the host route. On failure nothing else has changed yet,
	// so the rollback has no IPv4 state to undo.
	if err := gw.setupIPv6Isolation(st); err != nil {
		return err
	}

	// Enable IP forwarding (needed in both modes). Recorded so cleanup only
	// restores the previous value when bypath actually changed it.
	if err := gw.enableIPv4Forwarding(st); err != nil {
		return fmt.Errorf("enabling IPv4 forwarding: %w", err)
	}

	// Only bypath-owned chains are created and later removed. Built-in chains
	// (PREROUTING/POSTROUTING/FORWARD) are never flushed.
	if err := ensureChainE("nat", chainNat); err != nil {
		return err
	}
	if err := flushChainE("nat", chainNat); err != nil {
		return err
	}
	if err := ensureChainE("filter", chainForward); err != nil {
		return err
	}
	if err := flushChainE("filter", chainForward); err != nil {
		return err
	}

	if gw.nativeTUN {
		// Native TUN mode: sing-box's auto_route handles policy routing using
		// bypath's reserved table and rule index. Start recorded ownership before
		// the engine ran; this is a defensive re-assert for callers that build a
		// Gateway directly.
		log.Printf("  ℹ️  Native TUN: skipping fwmark/policy routing (sing-box auto_route owns reserved table %d)", tunnel.NativeRouteTable)
		if !st.NativeRules || st.NativeRuleTable != tunnel.NativeRouteTable {
			st.NativeRules = true
			st.NativeRuleTable = tunnel.NativeRouteTable
			if err := saveGatewayState(st); err != nil {
				return fmt.Errorf("recording sing-box policy-rule ownership: %w", err)
			}
		}

		if err := run("iptables", "-t", "nat", "-A", chainNat, "-o", gw.iface, "-j", "MASQUERADE"); err != nil {
			return err
		}
		if err := ensureJumpE("nat", "POSTROUTING", chainNat); err != nil {
			return err
		}

		// FORWARD rules: allow traffic between LAN interface and tun0
		if err := run("iptables", "-A", chainForward, "-i", gw.iface, "-o", "tun0", "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := run("iptables", "-A", chainForward, "-i", "tun0", "-o", gw.iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := run("iptables", "-A", chainForward, "-i", gw.iface, "-o", gw.iface, "-j", "ACCEPT"); err != nil {
			return err
		}
		// Fail closed: every remaining forwarded LAN packet is bound for the WAN.
		// That is exactly the leak that appears when tun0 disappears, so it is
		// dropped instead of being accepted or routed by the main table. The
		// catch-all comes last because a packet has a single output interface and
		// iptables accepts only one -o per rule.
		if err := run("iptables", "-A", chainForward, "-i", gw.iface, "-j", "DROP"); err != nil {
			return err
		}
		// Intercept LAN DNS so DHCP-configured DNS doesn't bypass the tunnel.
		if err := gw.setupDNSIntercept(); err != nil {
			return err
		}

		log.Printf("  ✅ Routing configured (native TUN: LAN ↔ tun0 via sing-box auto_route)")
	} else {
		// Legacy mode: full policy routing with fwmark + route table 100.
		// Table 100 is never flushed: only routes bypath recorded are removed.
		if err := gw.applyRoute(st, "route", "add", "default", "via", "10.0.0.1", "dev", "tun0", "table", "100"); err != nil {
			return err
		}
		// The tunnel default disappears with tun0. Keep a blackhole at a higher
		// metric in the same table so marked packets are dropped instead of
		// falling through to the main table and leaving through the WAN. While
		// tun0 exists its metric-0 route wins; the blackhole is only reachable
		// during an outage, which is exactly when fail-closed is required.
		if err := gw.applyRoute(st, "route", "add", "blackhole", "default", "metric", "4096", "table", "100"); err != nil {
			return err
		}
		if err := gw.applyRoute(st, "route", "add", gw.subnet, "dev", gw.iface, "table", "100"); err != nil {
			return err
		}

		// Mark packets from LAN (not destined to LAN) with fwmark 0x1.
		// Whitelist (geoip IR → direct) is handled inside sing-box, no ipset.
		if err := ensureChainE("mangle", chainMangle); err != nil {
			return err
		}
		if err := flushChainE("mangle", chainMangle); err != nil {
			return err
		}
		if err := run("iptables", "-t", "mangle", "-A", chainMangle,
			"-i", gw.iface,
			"-s", gw.subnet,
			"!", "-d", gw.subnet,
			"-j", "MARK", "--set-mark", "0x1"); err != nil {
			return err
		}
		if err := ensureJumpE("mangle", "PREROUTING", chainMangle); err != nil {
			return err
		}

		// Route marked traffic through table 100. A pre-existing rule is reused
		// and never claimed; only a rule bypath added is removed on cleanup.
		if err := gw.applyFwmarkRule(st); err != nil {
			return err
		}

		if err := run("iptables", "-t", "nat", "-A", chainNat, "-o", "tun0", "-j", "MASQUERADE"); err != nil {
			return err
		}
		if err := run("iptables", "-t", "nat", "-A", chainNat, "-o", gw.iface, "-j", "MASQUERADE"); err != nil {
			return err
		}
		if err := ensureJumpE("nat", "POSTROUTING", chainNat); err != nil {
			return err
		}

		if err := run("iptables", "-A", chainForward, "-i", gw.iface, "-o", "tun0", "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := run("iptables", "-A", chainForward, "-i", "tun0", "-o", gw.iface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := run("iptables", "-A", chainForward, "-i", gw.iface, "-o", gw.iface, "-j", "ACCEPT"); err != nil {
			return err
		}
		// Fail closed: marked LAN traffic that is bound for neither the LAN nor
		// tun0 would leave unencrypted through the WAN. The blackhole route in
		// table 100 already drops it; this catch-all keeps the filter path closed
		// too, including the window before the route changes. It comes last
		// because iptables accepts only one -o per rule.
		if err := run("iptables", "-A", chainForward, "-i", gw.iface, "-j", "DROP"); err != nil {
			return err
		}
		if err := ensureJumpE("filter", "FORWARD", chainForward); err != nil {
			return err
		}

		// Intercept LAN DNS so DHCP-configured DNS doesn't bypass the tunnel.
		if err := gw.setupDNSIntercept(); err != nil {
			return err
		}

		routeStyle := "whitelist via geo databases"
		if len(gw.config.Routing.Rules) > 0 {
			routeStyle = fmt.Sprintf("%d routing rule(s), default → %s", len(gw.config.Routing.Rules), defaultOutboundLabel(gw.config))
		}
		log.Printf("  ✅ Routing configured (LAN → tun0 → tunnel, %s)", routeStyle)
	}

	// The FORWARD jump must be the first rule evaluated: an earlier ACCEPT rule
	// owned by another service would let LAN traffic bypass the fail-closed
	// catch-all. It is verified by reading the effective list, not by trusting
	// the command that generated it.
	if err := ensureJumpFirst("iptables", "filter", "FORWARD", chainForward); err != nil {
		return fmt.Errorf("installing fail-closed FORWARD jump: %w", err)
	}
	if err := verifyJumpFirst("iptables", "filter", "FORWARD", chainForward); err != nil {
		return err
	}
	// The real chain is now in place and first, so the placeholder may go. A
	// guard left behind would also drop LAN-to-LAN forwarding.
	if err := removeGuardContainment(); err != nil {
		return fmt.Errorf("removing fail-closed forwarding guard: %w", err)
	}
	if st.ContainmentRetained {
		st.ContainmentRetained = false
		st.ContainmentIface = ""
		if err := saveGatewayState(st); err != nil {
			return fmt.Errorf("recording adopted containment: %w", err)
		}
	}

	// Both data paths rewrite the host resolver, so both must pin the tunnel
	// server's hostname first: after resolv.conf points at bypath, the engine
	// could no longer resolve its own endpoint without this record.
	link := gw.currentActiveLink()
	if link == nil && gw.profileMgr != nil {
		link = gw.profileMgr.GetActiveLink()
	}
	if link != nil && link.Address != "" && (gw.engineProc != nil || gw.embeddedEngine != nil) {
		if _, err := gw.pinHostToEtcHosts(link.Address); err != nil {
			return err
		}
	}
	if err := gw.setResolvConf("127.0.0.1"); err != nil {
		return err
	}

	return nil
}

// setupIPv6Isolation drops forwarded IPv6 arriving from the LAN. Without it a
// dual-stack client would bypass the tunnel entirely because tun0 carries only
// IPv4. The dedicated chain is removed by cleanupBypathChains.
//
// The jump is inserted at the head of FORWARD and then verified by reading the
// effective rule list: an appended jump behind an earlier ACCEPT would leave
// IPv6 uncontained, so verification failure aborts startup instead of logging
// success.
func (gw *Gateway) setupIPv6Isolation(st *gatewayRunState) error {
	if err := ensureChain6E("filter", chainV6Drop); err != nil {
		return err
	}
	if err := flushChain6E("filter", chainV6Drop); err != nil {
		return err
	}
	for _, rule := range ipv6IsolationRules(gw.iface) {
		if err := run(rule[0], rule[1:]...); err != nil {
			return err
		}
	}

	st.V6Isolated = true
	if err := saveGatewayState(st); err != nil {
		return err
	}
	// Fail closed when the containment chain cannot be placed first.
	if err := ensureJump6Top("filter", "FORWARD", chainV6Drop); err != nil {
		return fmt.Errorf("installing IPv6 isolation jump: %w", err)
	}
	if err := verifyJump6First("filter", "FORWARD", chainV6Drop); err != nil {
		return err
	}
	log.Printf("  🛡️  IPv6 isolation: forwarded IPv6 on %s dropped (not tunneled, verified first in FORWARD)", gw.iface)
	return nil
}

// ipv6IsolationRules is the ordered ip6tables rule list that prevents a
// dual-stack LAN client from escaping the IPv4-only tunnel. It is separate
// from execution so the policy can be asserted without root or a live host.
func ipv6IsolationRules(iface string) [][]string {
	return [][]string{
		{"ip6tables", "-t", "filter", "-A", chainV6Drop, "-i", iface, "-j", "DROP"},
	}
}

// pinHostToEtcHosts resolves hostname bypassing /etc/resolv.conf (which may
// be ISP-poisoned) and writes a static entry to /etc/hosts. This lets
// xray/sing-box reach the tunnel server after resolv.conf is switched to 127.0.0.1.
// Returns the resolved IP on success, or "" if resolution failed or hostname is already an IP.
// resolveHostDirect resolves a server hostname through the configured upstream
// DNS (bypassing a poisoned system resolver) without touching /etc/hosts.
func (gw *Gateway) resolveHostDirect(ctx context.Context, hostname string) string {
	addrs := lookupServerAddresses(gw, ctx, hostname)
	if len(addrs) == 0 {
		return ""
	}
	return addrs[0]
}

// dnsUpstreams returns the configured resolvers, defaulting to the public
// pair when none is configured. Only IP literals can be dialed directly.
func (gw *Gateway) dnsUpstreams() []string {
	if gw.config != nil && len(gw.config.Gateway.DNSUpstream) > 0 {
		return gw.config.Gateway.DNSUpstream
	}
	return []string{"1.1.1.1", "8.8.8.8"}
}

// resolveHostDirectAll is resolveHostDirect without the single-answer
// assumption: a round-robin record can return several addresses and some of
// them may be unusable, so every validated address is returned (IPv4 first).
// The first upstream that answers wins; failure on one upstream falls through
// to the next, as before.
func (gw *Gateway) resolveHostDirectAll(ctx context.Context, hostname string) []string {
	if net.ParseIP(hostname) != nil {
		return nil
	}
	for _, ns := range gw.dnsUpstreams() {
		if err := ctx.Err(); err != nil {
			log.Printf("⚠️  Server resolution canceled for %s: %v", hostname, err)
			return nil
		}
		if addrs := gw.resolveHostFromUpstream(ctx, hostname, ns); len(addrs) > 0 {
			return addrs
		}
	}
	log.Printf("⚠️  Could not resolve %s via any upstream DNS", hostname)
	return nil
}

// resolveHostFromUpstream queries one configured resolver directly. Only an
// address upstream can be dialed; a hostname upstream would have to be
// resolved first, which is exactly what this path exists to avoid.
func (gw *Gateway) resolveHostFromUpstream(ctx context.Context, hostname, ns string) []string {
	if err := ctx.Err(); err != nil {
		return nil
	}
	host := ns
	if h, _, err := net.SplitHostPort(ns); err == nil {
		host = h
	}
	if net.ParseIP(host) == nil {
		log.Printf("⚠️  Skipping non-IP DNS upstream %q for direct server resolution", ns)
		return nil
	}
	addr := dnsServerAddr(ns)
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			return (&net.Dialer{}).DialContext(dialCtx, "udp", addr)
		},
	}
	addrs, err := r.LookupHost(ctx, hostname)
	if err != nil || len(addrs) == 0 {
		return nil
	}
	usable := usableServerIPs(addrs)
	if len(usable) == 0 {
		// Reject obviously-intercepted addresses: private/loopback ranges are
		// used by ISPs to redirect blocked hostnames.
		log.Printf("⚠️  Rejected intercepted addresses %v for %s (from %s)", addrs, hostname, ns)
		return nil
	}
	return usable
}

// pinHostToEtcHosts records ownership before writing /etc/hosts. A persistence
// failure aborts the pin: bypath must not mutate the host without a durable
// inverse. A failed write leaves the ownership flag in place so recovery removes
// any partial entry.
func (gw *Gateway) pinHostToEtcHosts(hostname string) (string, error) {
	if net.ParseIP(hostname) != nil {
		return "", nil
	}
	// The pin exists only to keep the engine resolvable after the host resolver
	// is switched to bypath. Namespaced runs never switch it, and /etc/hosts is
	// still the host's file.
	if networkNamespaceIsolated() {
		return "", nil
	}
	ip := gw.resolveHostDirect(gw.ctx, hostname)
	if ip == "" {
		return "", nil
	}

	st, err := gw.ensureRunState("")
	if err != nil {
		return "", err
	}
	st.HostsPinned = true
	if err := saveGatewayState(st); err != nil {
		st.HostsPinned = false
		return "", fmt.Errorf("recording /etc/hosts ownership: %w", err)
	}

	marker := "# bypath-pin"
	entry := fmt.Sprintf("%s %s %s\n", ip, hostname, marker)

	current, err := os.ReadFile(hostsFilePath)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("reading %s: %w", hostsFilePath, err)
	}
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

	if err := os.WriteFile(hostsFilePath, []byte(newContent), 0644); err != nil {
		return "", fmt.Errorf("pinning %s in %s: %w", hostname, hostsFilePath, err)
	}
	log.Printf("🔧 Pinned %s → %s in %s", hostname, ip, hostsFilePath)
	return ip, nil
}

// unpinHostsFromEtcHosts removes all bypath-pin entries added by
// pinHostToEtcHosts. A missing file is already clean; any other read or write
// failure is returned so the ownership flag survives for the next attempt.
func (gw *Gateway) unpinHostsFromEtcHosts() error {
	marker := "# bypath-pin"
	current, err := os.ReadFile(hostsFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading %s: %w", hostsFilePath, err)
	}
	var filtered []string
	changed := false
	for _, line := range strings.Split(string(current), "\n") {
		if strings.Contains(line, marker) {
			changed = true
			continue
		}
		filtered = append(filtered, line)
	}
	if !changed {
		return nil
	}
	if err := os.WriteFile(hostsFilePath, []byte(strings.Join(filtered, "\n")), 0644); err != nil {
		return fmt.Errorf("restoring %s: %w", hostsFilePath, err)
	}
	return nil
}

var (
	resolvBackup = "/etc/resolv.conf.bypath-backup"
	// resolvLinkBackup remembers the systemd-resolved stub symlink target so
	// cleanup restores the exact host resolver configuration.
	resolvLinkBackup = "/etc/resolv.conf.bypath-link"
)

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
// then overwrites it with bypath's nameserver. Ownership is recorded first so a
// crash mid-write still leaves an exact restoration path.
func (gw *Gateway) setResolvConf(nameserver string) error {
	// The mount namespace is shared even when the network stack is not: this
	// file belongs to the host, and rewriting it would blackhole host DNS while
	// the listener only exists inside the private namespace.
	if networkNamespaceIsolated() {
		log.Printf("🌐 Network namespace detected: leaving %s untouched", resolvConfPath)
		return nil
	}
	if resolvConfPinned() {
		return permanent(fmt.Errorf("gateway mode cannot manage %s: it is a bind mount (a container runtime owns it); use proxy-only mode, or install bypath on the LAN host itself", resolvConfPath))
	}
	st, err := gw.ensureRunState("")
	if err != nil {
		return err
	}
	st.ResolvChanged = true
	if err := saveGatewayState(st); err != nil {
		st.ResolvChanged = false
		return fmt.Errorf("recording resolver ownership: %w", err)
	}

	exec.Command("chattr", "-i", resolvConfPath).Run()

	// Back up whatever the DHCP client wrote — we'll restore it on stop. A
	// backup that cannot be written aborts before the live file is changed.
	// A live file that cannot be read is also fatal: overwriting it would
	// destroy the only copy of the host's resolver configuration.
	orig, readErr := os.ReadFile(resolvConfPath)
	switch {
	case readErr == nil:
		if !strings.Contains(string(orig), "127.0.0.1") {
			if err := writeFileAtomic(resolvBackup, orig, 0644); err != nil {
				return fmt.Errorf("saving the resolver backup: %w", err)
			}
		}
	case !os.IsNotExist(readErr):
		return fmt.Errorf("reading %s before replacing it: %w", resolvConfPath, readErr)
	}

	content := fmt.Sprintf("nameserver %s\n", nameserver)
	if err := writeResolvConf(resolvConfPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("updating %s: %w", resolvConfPath, err)
	}

	if err := exec.Command("chattr", "+i", resolvConfPath).Run(); err != nil {
		log.Printf("⚠️  chattr +i failed (non-ext4?): %v", err)
	}

	log.Printf("🔧 %s → nameserver %s (immutable)", resolvConfPath, nameserver)
	return nil
}

// restoreResolvConf removes the immutable flag and restores the original
// DHCP-assigned resolv.conf. It reports every failure so the ownership flag is
// retained and the next recovery attempt retries the restoration.
func (gw *Gateway) restoreResolvConf() error {
	exec.Command("chattr", "-i", resolvConfPath).Run()

	// Restore the original systemd-resolved stub symlink when we detached it.
	linkTarget, linkErr := os.ReadFile(resolvLinkBackup)
	if linkErr != nil && !os.IsNotExist(linkErr) {
		return fmt.Errorf("reading the systemd-resolved stub record: %w", linkErr)
	}
	if len(linkTarget) > 0 {
		link := strings.TrimSpace(string(linkTarget))
		if err := os.Remove(resolvConfPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing %s: %w", resolvConfPath, err)
		}
		if err := os.Symlink(link, resolvConfPath); err != nil {
			return fmt.Errorf("restoring the systemd-resolved symlink: %w", err)
		}
		os.Remove(resolvLinkBackup)
		os.Remove(resolvBackup)
		log.Printf("🔧 %s restored (systemd-resolved symlink)", resolvConfPath)
		return nil
	}

	backup, backupErr := os.ReadFile(resolvBackup)
	if backupErr != nil && !os.IsNotExist(backupErr) {
		return fmt.Errorf("reading the resolver backup: %w", backupErr)
	}
	if len(backup) > 0 {
		// A previous attempt may have failed after the file was already intact
		// (a bind-mounted resolver cannot be renamed at all). Treat an identical
		// live file as restored so recovery cannot block forever.
		if current, readErr := os.ReadFile(resolvConfPath); readErr == nil && bytes.Equal(current, backup) {
			os.Remove(resolvBackup)
			log.Printf("🔧 %s already matches the backup; nothing to restore", resolvConfPath)
			return nil
		}
		if err := writeResolvConf(resolvConfPath, backup, 0644); err != nil {
			return fmt.Errorf("restoring the DHCP resolver backup: %w", err)
		}
		os.Remove(resolvBackup)
		log.Printf("🔧 %s restored (DHCP original)", resolvConfPath)
		return nil
	}

	// No backup: only replace the value bypath itself wrote. An untouched
	// resolv.conf is left exactly as the host configured it.
	content, err := os.ReadFile(resolvConfPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading %s during restoration: %w", resolvConfPath, err)
	}
	if strings.TrimSpace(string(content)) == "nameserver 127.0.0.1" {
		if err := writeResolvConf(resolvConfPath, []byte("nameserver 8.8.8.8\nnameserver 1.1.1.1\n"), 0644); err != nil {
			return fmt.Errorf("replacing the bypath resolver value: %w", err)
		}
		log.Printf("🔧 %s restored (bypath value replaced)", resolvConfPath)
		return nil
	}
	return nil
}

// setupDNSIntercept redirects all DNS queries (port 53) arriving on the LAN
// interface to bypath's own DNS proxy, regardless of what DNS server the
// DHCP gave the client. This is the transparent DNS hijack that makes bypath
// work without the user ever touching their DNS settings.
func (gw *Gateway) setupDNSIntercept() error {
	dnsPort := fmt.Sprintf("%d", gw.dnsPort)
	// Redirect UDP and TCP DNS from LAN clients to our local DNS proxy.
	// Only applies to traffic arriving on the LAN interface so we don't
	// redirect bypath's own DNS queries (those originate from lo/tun0).
	// Rules live in a dedicated chain so cleanup never flushes PREROUTING.
	if err := ensureChainE("nat", chainDNS); err != nil {
		return err
	}
	if err := flushChainE("nat", chainDNS); err != nil {
		return err
	}
	if err := run("iptables", "-t", "nat", "-A", chainDNS,
		"-i", gw.iface,
		"-s", gw.subnet,
		"-p", "udp", "--dport", "53",
		"-j", "REDIRECT", "--to-port", dnsPort); err != nil {
		return err
	}
	if err := run("iptables", "-t", "nat", "-A", chainDNS,
		"-i", gw.iface,
		"-s", gw.subnet,
		"-p", "tcp", "--dport", "53",
		"-j", "REDIRECT", "--to-port", dnsPort); err != nil {
		return err
	}
	if err := ensureJumpE("nat", "PREROUTING", chainDNS); err != nil {
		return err
	}
	log.Printf("🔀 DNS intercept active: LAN :53 → :%s (DHCP DNS ignored)", dnsPort)
	return nil
}

// needsNetworkCleanup reports whether host networking may have been changed
// by this instance or by a crashed gateway run. Proxy-only runs must leave
// host DNS, routes, interfaces and firewall untouched.
func (gw *Gateway) needsNetworkCleanup() bool {
	if gw.networkMutated {
		return true
	}
	_, err := os.Stat(gatewayStateFile())
	return err == nil
}

// cleanupRouting applies the inverse of every host change bypath recorded and
// reports whether the rollback finished. A returned error means the ownership
// record was retained and the next start must retry the remaining work.
func (gw *Gateway) cleanupRouting() error {
	if !gw.needsNetworkCleanup() {
		return nil
	}

	st := gw.run
	if st == nil {
		loaded, err := loadGatewayState()
		if err != nil {
			// Keep the record: it is the only description of whatever bypath
			// changed, and deleting it would make the damage unrecoverable.
			log.Printf("⚠️  Cannot read the ownership record: %v", err)
			gw.run = nil
			gw.networkMutated = false
			gw.legacyRoutingActive = false
			gw.tunCreated = false
			gw.resolvedStopped = false
			gw.dnsmasq = dnsmasqPriorState{}
			return fmt.Errorf("incomplete network cleanup: %w", err)
		}
		st = loaded
	}
	cleanupComplete := true
	containmentRetained := false
	var cleanupErr error
	if st != nil {
		// Firewall containment is deferred until every route, rule, interface
		// and resolver change has been reversed; a stopped run that keeps
		// forwarding enabled by another service (Docker, libvirt) must never
		// expose an uncontained window or disable that forwarding.
		keepChains := hostFirewallAvailable() && !st.LegacyFormat
		if err := gw.undoNetworkStateWith(st, keepChains, false); err != nil {
			cleanupComplete = false
			cleanupErr = fmt.Errorf("incomplete network cleanup: %w", err)
			log.Printf("⚠️  Incomplete network cleanup: %v", err)
		} else if keepChains {
			retained, err := gw.finishStopContainment(st)
			if err != nil {
				cleanupComplete = false
				cleanupErr = fmt.Errorf("incomplete containment handover: %w", err)
				log.Printf("⚠️  Incomplete containment handover: %v", err)
			}
			containmentRetained = retained
		}
	} else {
		// No ownership record: remove only bypath-named chains. Routes,
		// interfaces, resolver files and services are left untouched because
		// nothing proves this process changed them.
		if err := cleanupBypathChains(); err != nil {
			cleanupErr = fmt.Errorf("incomplete chain cleanup: %w", err)
			log.Printf("⚠️  Incomplete chain cleanup: %v", err)
		}
	}

	// Keep the pruned record when an inverse failed; it names the remaining work
	// for the next recovery attempt. Services are restored inside the record's
	// inverse pass, only when it proves bypath stopped them. A retained
	// containment record is also kept so the next start or an explicit teardown
	// owns the chains that were deliberately left behind.
	if cleanupComplete && !containmentRetained {
		clearGatewayState()
	}
	gw.run = nil
	gw.networkMutated = false
	gw.legacyRoutingActive = false
	gw.tunCreated = false
	gw.resolvedStopped = false
	gw.dnsmasq = dnsmasqPriorState{}
	return cleanupErr
}

// finishStopContainment decides what survives a stop. When the host still
// forwards because another service owns ip_forward, the fail-closed DROP
// chains are kept: LAN client traffic can never fall through to the WAN after
// bypath is gone. When forwarding is off, every bypath chain is removed.
func (gw *Gateway) finishStopContainment(st *gatewayRunState) (bool, error) {
	if st.Mode != "legacy" && st.Mode != "native" {
		return false, cleanupBypathChains()
	}
	enabled, err := ipv4ForwardingEnabled()
	if err != nil {
		// An unreadable forwarding setting cannot prove forwarding is off:
		// keep the fail-closed chains rather than open a direct path.
		enabled = true
	}
	if !enabled {
		st.ContainmentRetained = false
		return false, cleanupBypathChains()
	}

	// Only the fail-closed FORWARD and IPv6 chains may remain; DNS redirection,
	// NAT and packet marking reference a data path that no longer exists.
	if err := cleanupInterceptChains(); err != nil {
		return true, err
	}
	iface := gw.iface
	if iface == "" {
		iface = st.ContainmentIface
	}
	if iface == "" {
		// A crashed run never recorded its interface, but the installed chain
		// still names it.
		installed, discovered, err := forwardContainmentInstalled()
		if err != nil {
			return true, err
		}
		if installed {
			iface = discovered
		}
	}
	if iface == "" {
		return true, fmt.Errorf("cannot retain forwarding containment without a LAN interface")
	}
	if err := retainForwardContainment(iface); err != nil {
		return true, err
	}
	st.ContainmentRetained = true
	st.ContainmentIface = iface
	if err := saveGatewayState(st); err != nil {
		return true, fmt.Errorf("recording retained containment: %w", err)
	}
	log.Printf("🛡️  Forwarding remains enabled by another service: fail-closed LAN containment kept on %s", iface)
	return true, nil
}

// prepareNativeOwnership reserves bypath's routing table before sing-box can
// create auto_route policy objects, and persists that ownership first. The
// reserved table must be empty and unreferenced; anything else means another
// component owns it and native mode cannot be started safely. This turns the
// engine's routing into a deterministic, recoverable resource instead of the
// engine's private defaults.
func (gw *Gateway) prepareNativeOwnership() error {
	table := strconv.Itoa(tunnel.NativeRouteTable)
	rules, err := commandOutput("ip", "rule", "show")
	if err != nil {
		return fmt.Errorf("inspecting policy rules: %w", err)
	}
	if strings.Contains(rules, "lookup "+table) {
		return fmt.Errorf("reserved native route table %s is already referenced by a policy rule; refusing to start", table)
	}
	routes, err := routesInTable(table)
	if err != nil {
		return fmt.Errorf("inspecting reserved native route table %s: %w", table, err)
	}
	if strings.TrimSpace(routes) != "" {
		return fmt.Errorf("reserved native route table %s already contains routes; refusing to start", table)
	}

	st, err := gw.ensureRunState("native")
	if err != nil {
		return err
	}
	if !st.NativeRules || st.NativeRuleTable != tunnel.NativeRouteTable {
		st.NativeRules = true
		st.NativeRuleTable = tunnel.NativeRouteTable
		if err := saveGatewayState(st); err != nil {
			return fmt.Errorf("recording native route ownership: %w", err)
		}
	}
	log.Printf("  🔒 Native routing reserved: table %d, rule index %d (ownership recorded before engine start)", tunnel.NativeRouteTable, tunnel.NativeRuleIndex)
	return nil
}

// pkillCommand is injectable so lifecycle tests never signal host processes.
var pkillCommand = func(pattern string) {
	exec.Command("pkill", "-f", pattern).Run()
}

// cleanupPreviousRun kills leftover child processes and restores network state
// from any previous crashed or kill-9'd bypath instance. Called unconditionally
// at the start of Start() so every startup begins from a known-clean state.
// Cleanup is driven by the persisted ownership record: nothing is deleted,
// flushed or restarted unless the record proves bypath changed it. Any failure
// is returned and must abort startup.
func (gw *Gateway) cleanupPreviousRun() error {
	log.Println("🧹 Cleaning up state from previous run...")

	// Kill child processes from the previous instance.
	// Engine processes: kill by config-path pattern (safe — only matches bypath's own).
	// The runtime directory is /run/bypath; the /tmp/bypath pattern covers
	// leftovers from builds that used a per-process temp directory. pkill does
	// not exist on Windows; there the job object reaps engines when the daemon
	// dies, and the children file covers the rest.
	if runtime.GOOS != "windows" {
		pkillCommand("xray run -c /run/bypath")
		pkillCommand("sing-box run -c /run/bypath")
		pkillCommand("xray run -c /tmp/bypath")
		pkillCommand("sing-box run -c /tmp/bypath")
	}
	// dns2socks / tun2socks: kill only tracked PIDs to avoid killing user processes.
	killTrackedChildren()

	// Allow processes to exit before cleaning up network state.
	time.Sleep(300 * time.Millisecond)

	// The previous engine is now stopped and reaped, so any remaining gen-*
	// directory holds stale credentials and is safe to remove (D6).
	if removed, err := tunnel.RemoveStaleGenerations(paths.Get().TmpDir, ""); err != nil {
		log.Printf("⚠️  Could not remove stale generation directories: %v", err)
	} else if removed > 0 {
		log.Printf("🧹 Removed %d stale generation directorie(s)", removed)
	}

	// A retried Start on the same instance must not inherit in-memory ownership
	// from the failed attempt; the recovered record is the authority.
	gw.run = nil
	gw.networkMutated = false

	st, err := loadGatewayState()
	if err != nil {
		// A record that exists but cannot be read might still describe live host
		// changes. Refusing startup keeps a new run from layering unowned state on
		// top of an unknown rollback.
		return fmt.Errorf("reading the previous-run ownership record: %w", err)
	}
	if st == nil {
		// A proxy-only run must leave unrelated host networking untouched. Only
		// a run that requested gateway mode may remove bypath-named chains, and
		// even then only its own chains (never built-in ones).
		if gw.config.Gateway.Enabled {
			if err := cleanupBypathChains(); err != nil {
				return fmt.Errorf("cleaning up bypath firewall chains: %w", err)
			}
		}
		return nil
	}
	var recoverErr error
	if gw.config.Gateway.Enabled {
		// A gateway restart must not open an uncontained window: the firewall
		// containment and the forwarding ownership are adopted by setupRouting
		// a few seconds later.
		recoverErr = gw.recoverStateKeepingContainment(st)
	} else {
		recoverErr = gw.recoverState(st)
	}
	if recoverErr != nil {
		// The pruned record keeps naming what failed. Startup must abort: a new
		// run on top of an interrupted rollback would layer unowned changes.
		return fmt.Errorf("incomplete cleanup of previous run: %w", recoverErr)
	}
	// Keep the record when the next setupRouting must inherit ownership of
	// forwarding, IPv6 isolation or retained containment. Otherwise the
	// recovery is complete and the record is cleared.
	if gw.config.Gateway.Enabled && (st.ForwardingWasOff || st.V6Isolated || st.ContainmentRetained) {
		if err := saveGatewayState(st); err != nil {
			return fmt.Errorf("persisting adopted ownership: %w", err)
		}
		return nil
	}
	clearGatewayState()
	return nil
}

// --- Accessors for API ---

func (gw *Gateway) GetProfileManager() *profile.Manager { return gw.profileMgr }
func (gw *Gateway) GetTunnelManager() *tunnel.Manager   { return gw.tunnelMgr }
func (gw *Gateway) GetActiveEngine() string             { return gw.activeEngine }

// --- Helpers ---

func localDNSChanged(a, b []config.LocalDNSEntry) bool {
	if len(a) != len(b) {
		return true
	}
	for i := range a {
		if a[i].Server != b[i].Server {
			return true
		}
		if strings.Join(a[i].Domains, ",") != strings.Join(b[i].Domains, ",") {
			return true
		}
	}
	return false
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
	return waitForPortContext(context.Background(), port, timeout)
}

// waitForPortContext polls until the port accepts a connection or the deadline
// or context ends. Shutdown does not wait for the full poll timeout.
func waitForPortContext(ctx context.Context, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("port %d not ready after %v", port, timeout)
}

// waitForTUNDevice polls for a network interface to appear within the given timeout.
// It checks every 500ms using net.InterfaceByName until the interface exists or timeout is reached.
func waitForTUNDevice(name string, timeout time.Duration) error {
	return waitForTUNDeviceContext(context.Background(), name, timeout)
}

func waitForTUNDeviceContext(ctx context.Context, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := net.InterfaceByName(name)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("TUN device %q not found after %v", name, timeout)
}

// routingChanged reports whether the inputs that are compiled into the engine
// routing configuration differ. A reload alone cannot republish them.
func routingChanged(a, b *config.Config) bool {
	if len(a.Routing.Rules) != len(b.Routing.Rules) {
		return true
	}
	for i := range a.Routing.Rules {
		if a.Routing.Rules[i].Match != b.Routing.Rules[i].Match ||
			a.Routing.Rules[i].Outbound != b.Routing.Rules[i].Outbound {
			return true
		}
	}
	if len(a.Routing.ExternalOutbounds) != len(b.Routing.ExternalOutbounds) {
		return true
	}
	for name, url := range a.Routing.ExternalOutbounds {
		if b.Routing.ExternalOutbounds[name] != url {
			return true
		}
	}
	return strings.Join(a.Whitelist.Countries, ",") != strings.Join(b.Whitelist.Countries, ",") ||
		strings.Join(a.Whitelist.GeositeCountries, ",") != strings.Join(b.Whitelist.GeositeCountries, ",") ||
		strings.Join(a.Whitelist.BypassDomains, ",") != strings.Join(b.Whitelist.BypassDomains, ",") ||
		strings.Join(a.Whitelist.ForceProxyDomains, ",") != strings.Join(b.Whitelist.ForceProxyDomains, ",")
}
