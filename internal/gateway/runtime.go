package gateway

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/tunnel"
)

// RuntimeState is the externally visible lifecycle state of the tunnel.
type RuntimeState string

const (
	StateConnecting   RuntimeState = "CONNECTING"
	StateConnected    RuntimeState = "CONNECTED"
	StateDegraded     RuntimeState = "DEGRADED"
	StateRecovering   RuntimeState = "RECOVERING"
	StateDisconnected RuntimeState = "DISCONNECTED"
	StateFailed       RuntimeState = "FAILED"
)

// RuntimeStatus is the live view returned by /api/v1/status. ActiveLink is the
// link actually carrying traffic, which may differ from the link the operator
// originally selected after a startup or runtime fallback.
type RuntimeStatus struct {
	State           RuntimeState `json:"state"`
	ActiveLink      string       `json:"active_link,omitempty"`
	ActiveGroup     string       `json:"active_group,omitempty"`
	Protocol        string       `json:"protocol,omitempty"`
	Engine          string       `json:"engine,omitempty"`
	Restarts        int          `json:"restarts"`
	TunRestarts     int          `json:"tun_restarts"`
	RecoveryAttempt int          `json:"recovery_attempt"`
	LastError       string       `json:"last_error,omitempty"`
	LastHealth      string       `json:"last_health,omitempty"`
	// Health evidence separates a forwarding failure from an identity
	// verification failure. HealthTunnelAnswered records that the probe
	// endpoints replied through the tunnel even when the exit could not be
	// proven, so the UI never presents an unverified exit as a dead VPN.
	HealthCode           string `json:"health_code,omitempty"`
	HealthDetail         string `json:"health_detail,omitempty"`
	HealthTunnelAnswered bool   `json:"health_tunnel_answered"`
	HealthExitIP         string `json:"health_exit_ip,omitempty"`
	HealthUplinkSamples  int    `json:"health_uplink_samples"`
	// FallbackFrom is the link that failed during startup, kept after another
	// group link took over. The tunnel is healthy but not on the requested
	// link, and the operator must be able to see why.
	FallbackFrom  string `json:"fallback_from,omitempty"`
	FallbackError string `json:"fallback_error,omitempty"`
}

const (
	// maxRecoveryAttempts bounds automatic recovery so a permanently broken
	// link settles in FAILED instead of restarting forever.
	maxRecoveryAttempts = 5
	// maxTunRecoveryAttempts bounds data-path-only recovery before the watchdog
	// falls back to restarting the tunnel engine.
	maxTunRecoveryAttempts = 3
	// healthFailureThreshold is how many consecutive failed health checks mark
	// the tunnel degraded and start recovery.
	healthFailureThreshold = 2
)

func recoveryBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := recoveryBackoffBase.Load() << (attempt - 1)
	if limit := recoveryBackoffMax.Load(); d > limit || d <= 0 {
		d = limit
	}
	return d
}

// initRuntimeLocked prepares supervision for a new Start. The caller holds mu.
// A retry loop reuses the same Gateway after a canceled run, so the context is
// recreated instead of leaving every later start with "context canceled".
//
// It reports true when an AbortStartup was requested before this start reached
// the lifecycle lock. The pending abort is consumed there, so a later explicit
// Start (for example after an ApplyActiveLink timeout) is not blocked forever.
func (gw *Gateway) initRuntimeLocked() bool {
	gw.rtMu.Lock()
	defer gw.rtMu.Unlock()

	if gw.shutdown {
		gw.stopping = true
		if gw.cancel != nil {
			gw.cancel()
		}
		return true
	}
	if gw.ctx == nil || gw.ctx.Err() != nil {
		gw.ctx, gw.cancel = context.WithCancel(context.Background())
	}
	if gw.abortPending {
		gw.abortPending = false
		gw.stopping = true
		if gw.cancel != nil {
			gw.cancel()
		}
		return true
	}

	gw.stopping = false
	gw.operatorStop = false
	gw.watchStop = nil
	gw.recoverCtx = nil
	gw.recoverCancel = nil
	gw.runtime = RuntimeStatus{State: StateConnecting}
	gw.health = HealthEvidence{}
	gw.lastStartErr = ""
	return false
}

func (gw *Gateway) setRuntimeState(state RuntimeState, errMsg string) {
	gw.rtMu.Lock()
	defer gw.rtMu.Unlock()
	gw.runtime.State = state
	if errMsg != "" {
		gw.runtime.LastError = errMsg
	}
	if state == StateConnected {
		gw.runtime.LastError = ""
		gw.runtime.RecoveryAttempt = 0
	}
}

func (gw *Gateway) setRuntimeEngine(name string) {
	gw.rtMu.Lock()
	gw.runtime.Engine = name
	gw.rtMu.Unlock()
}

func (gw *Gateway) setRuntimeAttempt(state RuntimeState, attempt int, errMsg string) {
	gw.rtMu.Lock()
	defer gw.rtMu.Unlock()
	gw.runtime.State = state
	gw.runtime.RecoveryAttempt = attempt
	if errMsg != "" {
		gw.runtime.LastError = errMsg
	}
}

func (gw *Gateway) recordActiveLink(link *profile.Link) {
	if link == nil {
		return
	}
	gw.rtMu.Lock()
	gw.activeLinkRef = link
	gw.runtime.ActiveLink = link.Remark
	gw.runtime.ActiveGroup = link.Group
	gw.runtime.Protocol = link.Protocol
	gw.rtMu.Unlock()
}

func (gw *Gateway) currentActiveLink() *profile.Link {
	gw.rtMu.Lock()
	defer gw.rtMu.Unlock()
	return gw.activeLinkRef
}

// recordFallback keeps a successful startup fallback explainable: traffic runs
// on the active link, but the requested link stays visible with its cause.
func (gw *Gateway) recordFallback(failedLink string, cause error) {
	gw.rtMu.Lock()
	defer gw.rtMu.Unlock()
	gw.runtime.FallbackFrom = failedLink
	gw.runtime.FallbackError = ""
	if cause != nil {
		gw.runtime.FallbackError = cause.Error()
	}
}

func (gw *Gateway) clearFallbackNotice() {
	gw.rtMu.Lock()
	gw.runtime.FallbackFrom = ""
	gw.runtime.FallbackError = ""
	gw.rtMu.Unlock()
}

func (gw *Gateway) setEngineWaiter(w *engine.ExitWaiter) {
	gw.rtMu.Lock()
	gw.engineWaiter = w
	gw.rtMu.Unlock()
}

func (gw *Gateway) engineWaiterRef() *engine.ExitWaiter {
	gw.rtMu.Lock()
	defer gw.rtMu.Unlock()
	return gw.engineWaiter
}

func (gw *Gateway) setTunWaiter(w *engine.ExitWaiter) {
	gw.rtMu.Lock()
	gw.tunWaiter = w
	gw.rtMu.Unlock()
}

func (gw *Gateway) tunWaiterRef() *engine.ExitWaiter {
	gw.rtMu.Lock()
	defer gw.rtMu.Unlock()
	return gw.tunWaiter
}

// tunExited reports whether the supervised tun2socks died. Native TUN runs have
// no tun2socks process and are supervised through the engine waiter instead.
func (gw *Gateway) tunExited() bool {
	w := gw.tunWaiterRef()
	if w == nil {
		return false
	}
	select {
	case <-w.Done():
		return true
	default:
		return false
	}
}

func (gw *Gateway) noteStartError(err error) {
	if err == nil {
		return
	}
	gw.rtMu.Lock()
	gw.lastStartErr = err.Error()
	gw.rtMu.Unlock()
}

func (gw *Gateway) lastStartError() string {
	gw.rtMu.Lock()
	defer gw.rtMu.Unlock()
	return gw.lastStartErr
}

// GetRuntimeStatus returns a consistent snapshot for the API.
func (gw *Gateway) GetRuntimeStatus() RuntimeStatus {
	gw.rtMu.Lock()
	defer gw.rtMu.Unlock()
	return gw.runtime
}

func (gw *Gateway) isStopping() bool {
	gw.rtMu.Lock()
	defer gw.rtMu.Unlock()
	return gw.stopping
}

// StopTunnel is an explicit operator disconnect: it tears the tunnel down but
// keeps the process (and therefore the management surface) alive, and it tells
// the run loop not to reconnect on its own. Start clears the flag.
func (gw *Gateway) StopTunnel() {
	gw.rtMu.Lock()
	gw.operatorStop = true
	gw.rtMu.Unlock()
	gw.Stop()
}

// OperatorStopped reports whether the operator explicitly disconnected.
func (gw *Gateway) OperatorStopped() bool {
	gw.rtMu.Lock()
	defer gw.rtMu.Unlock()
	return gw.operatorStop
}

// startContext returns the context engine startup should honor. During a
// watchdog restart it is the recoverable context, so Stop can abort an attempt
// without waiting for the full startup timeout.
func (gw *Gateway) startContext() context.Context {
	gw.rtMu.Lock()
	defer gw.rtMu.Unlock()
	if gw.recoverCtx != nil {
		return gw.recoverCtx
	}
	return gw.ctx
}

// lifetimeContext is the process-lifetime context for background checks. It is
// read under rtMu so the watchdog never races Stop replacing or canceling it.
func (gw *Gateway) lifetimeContext() context.Context {
	gw.rtMu.Lock()
	defer gw.rtMu.Unlock()
	if gw.ctx == nil {
		return context.Background()
	}
	return gw.ctx
}

// signalStop marks shutdown as in progress and interrupts supervision. Stop
// calls it before taking mu so a recovery attempt cannot block shutdown.
//
// It also cancels the gateway context up front. Startup holds mu for the whole
// fallback chain, so waiting for Stop to reach stopLocked would leave DNS
// lookups, engine handshakes and connectivity probes running to their timeouts.
// initRuntimeLocked recreates the context if the same Gateway starts again.
func (gw *Gateway) signalStop() {
	gw.rtMu.Lock()
	cancel := gw.signalStopLocked()
	gw.rtMu.Unlock()

	if cancel != nil {
		cancel()
	}
}

// signalStopLocked records the shutdown request and returns the context
// cancel function. The caller holds rtMu and must invoke the cancel function
// after releasing it. AbortStartup uses it to abort a start atomically with the
// in-flight check.
func (gw *Gateway) signalStopLocked() context.CancelFunc {
	if gw.stopping {
		return nil
	}
	gw.stopping = true
	if gw.recoverCancel != nil {
		gw.recoverCancel()
		gw.recoverCancel = nil
	}
	if gw.watchStop != nil {
		close(gw.watchStop)
		gw.watchStop = nil
	}
	return gw.cancel
}

func (gw *Gateway) startWatchdog() {
	gw.rtMu.Lock()
	if gw.watchStop != nil || gw.stopping {
		gw.rtMu.Unlock()
		return
	}
	stop := make(chan struct{})
	gw.watchStop = stop
	gw.rtMu.Unlock()
	go gw.watchLoop(stop)
}

// stopEngineLocked kills and reaps the current engine, removes its generated
// config, and clears engine bookkeeping. The caller holds mu.
func (gw *Gateway) stopEngineLocked() {
	if gw.embeddedEngine != nil {
		gw.embeddedEngine.Stop() //nolint:errcheck
		gw.embeddedEngine = nil
	}
	gw.setEmbedded(nil)
	if gw.engineProc != nil && gw.engineProc.Process != nil {
		_ = gw.engineProc.Process.Kill()
	}
	if w := gw.engineWaiterRef(); w != nil {
		// The process is reaped by the waiter exactly once; a bare Wait here
		// would race the waiter goroutine.
		w.Wait(5 * time.Second)
	}
	gw.engineProc = nil
	gw.setEngineWaiter(nil)
	gw.activeEngine = ""
	gw.setRuntimeEngine("")
	if gw.configFile != "" {
		tunnel.RemoveGenerationDir(paths.Get().TmpDir, gw.configFile)
		gw.configFile = ""
	}
}

// engineExited reports whether the supervised engine has terminated.
func (gw *Gateway) engineExited() bool {
	gw.rtMu.Lock()
	embedded := gw.embeddedRef
	w := gw.engineWaiter
	gw.rtMu.Unlock()

	if embedded != nil {
		return !embedded.IsRunning()
	}
	if w == nil {
		return false
	}
	select {
	case <-w.Done():
		return true
	default:
		return false
	}
}

// engineAliveAndDataPathHealthy is the health decision that matters for client
// traffic: a supervised engine that has not exited plus a verified local
// forwarding contract. Upstream reachability is reported separately because a
// failing probe does not prove the data plane is broken.
func (gw *Gateway) engineAliveAndDataPathHealthy() bool {
	if gw.engineExited() {
		return false
	}
	healthy, _ := callDataPathProbe(gw)
	return healthy
}

func (gw *Gateway) setEmbedded(r engine.EmbeddedRunner) {
	gw.rtMu.Lock()
	gw.embeddedRef = r
	gw.rtMu.Unlock()
}

// watchLoop monitors engine liveness, the local data path and health. It owns
// recovery so the state reported through the API is accurate throughout.
//
// It also exits when the gateway lifetime context ends: cancellation alone must
// never leave a supervisor polling the host for a gateway that is gone.
func (gw *Gateway) watchLoop(stop <-chan struct{}) {
	lifetime := gw.lifetimeContext()
	tick := time.NewTicker(watchdogInterval.Load())
	defer tick.Stop()

	healthEnabled, interval, _ := gw.healthSettings()
	var healthTick *time.Ticker
	var healthC <-chan time.Time
	if healthEnabled {
		healthTick = time.NewTicker(interval)
		healthC = healthTick.C
		defer healthTick.Stop()
	}

	healthFailures := 0
	outageLogged := false
	ticks := 0
	for {
		select {
		case <-stop:
			return
		case <-lifetime.Done():
			return
		case <-tick.C:
			if gw.engineExited() {
				log.Printf("⚠️  Engine process exited unexpectedly")
				if !callEngineRecovery(gw, "engine process exited") {
					return
				}
				healthFailures = 0
				continue
			}
			if gw.tunExited() {
				log.Printf("⚠️  tun2socks exited unexpectedly")
				if !gw.recoverTunPath("tun2socks exited") {
					return
				}
				healthFailures = 0
				outageLogged = false
				continue
			}

			ticks++
			if ticks%dataPathCheckEvery != 0 {
				continue
			}
			state := gw.GetRuntimeStatus().State
			if state != StateConnected && state != StateDegraded {
				continue
			}
			if healthy, reason := callDataPathProbe(gw); !healthy {
				log.Printf("⚠️  Gateway data path unhealthy: %s", reason)
				gw.setRuntimeState(StateDegraded, reason)
				if !gw.recoverDataPath(reason) {
					return
				}
				healthFailures = 0
				outageLogged = false
			}
		case <-healthC:
			state := gw.GetRuntimeStatus().State
			if state != StateConnected && state != StateDegraded {
				healthFailures = 0
				continue
			}
			ok, errMsg := callHealthProbe(gw)
			if ok {
				healthFailures = 0
				outageLogged = false
				gw.markHealthy()
				continue
			}
			healthFailures++
			// A failed upstream probe is not evidence that the data plane is
			// broken. Only the local contract decides: if the engine is alive and
			// clients can still be forwarded, the tunnel stays CONNECTED and no
			// recovery or fallback runs.
			if gw.engineAliveAndDataPathHealthy() {
				if !outageLogged {
					log.Printf("⚠️  Upstream health probes are failing while the engine and data path are alive; reporting DEGRADED and keeping the tunnel up: %s", errMsg)
					outageLogged = true
				}
				// The data path is alive, so no recovery runs; the reported state
				// must still say the tunnel is unverified instead of claiming
				// CONNECTED with a stale health timestamp.
				gw.setRuntimeState(StateDegraded, errMsg)
				healthFailures = 0
				continue
			}
			gw.setRuntimeState(StateDegraded, errMsg)
			if healthFailures < healthFailureThreshold {
				continue
			}
			log.Printf("⚠️  Health check failed %d times: %s", healthFailures, errMsg)
			if !gw.recoverRuntime(errMsg) {
				return
			}
			healthFailures = 0
			outageLogged = false
		}
	}
}

// recoverTunPath restarts only the transparent data path. The engine and its
// tunnel are unaffected by a tun2socks crash, so restarting the engine here
// would drop a working tunnel for no reason. After a bounded number of local
// attempts it falls back to full engine recovery.
func (gw *Gateway) recoverTunPath(reason string) bool {
	for attempt := 1; attempt <= maxTunRecoveryAttempts; attempt++ {
		if attempt > 1 && !gw.sleepRecovery(recoveryBackoff(attempt-1)) {
			return false
		}
		if gw.isStopping() {
			return false
		}
		gw.setRuntimeState(StateDegraded, reason)
		log.Printf("🔄 Restarting tun2socks data path (attempt %d/%d)...", attempt, maxTunRecoveryAttempts)
		err := callRestartTunPath(gw)
		if err == nil {
			if healthy, detail := callDataPathProbe(gw); !healthy {
				err = fmt.Errorf("data path still unhealthy after restart: %s", detail)
			}
		}
		if err == nil {
			gw.rtMu.Lock()
			gw.runtime.TunRestarts++
			gw.rtMu.Unlock()
			gw.setRuntimeState(StateConnected, "")
			log.Printf("✅ tun2socks recovered without restarting the tunnel engine")
			return true
		}
		log.Printf("  ❌ tun2socks restart failed: %v", err)
	}
	log.Printf("⚠️  tun2socks recovery exhausted — restarting the tunnel engine")
	return callEngineRecovery(gw, reason)
}

// restartTunPath kills any leftover tun2socks, recreates tun0 through the
// normal start path and restores the policy routes bound to the old device.
// The caller holds no lock; startTun and route setup run under mu like startup.
func (gw *Gateway) restartTunPath() error {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	return gw.restartTunPathLocked()
}

func (gw *Gateway) restartTunPathLocked() error {
	if gw.isStopping() {
		return context.Canceled
	}
	if gw.tunProc != nil {
		if gw.tunProc.Process != nil {
			_ = gw.tunProc.Process.Kill()
		}
		if w := gw.tunWaiterRef(); w != nil {
			w.Wait(5 * time.Second)
		}
		gw.tunProc = nil
		gw.setTunWaiter(nil)
	}
	if err := gw.startTun(); err != nil {
		return err
	}
	return gw.restoreLegacyRoutes()
}

func (gw *Gateway) markHealthy() {
	gw.rtMu.Lock()
	gw.runtime.LastHealth = time.Now().UTC().Format(time.RFC3339)
	gw.runtime.LastError = ""
	gw.runtime.State = StateConnected
	gw.runtime.HealthCode = HealthVerified
	gw.runtime.HealthDetail = ""
	gw.rtMu.Unlock()
}

// recordHealth publishes the latest verdict together with the evidence behind
// it. healthCheck calls it for every attempt, including failures, so a DEGRADED
// state can always explain whether forwarding or identity verification failed.
func (gw *Gateway) recordHealth(ev HealthEvidence) {
	exitIP := ""
	if len(ev.ExitIPs) > 0 {
		exitIP = ev.ExitIPs[0]
	}
	gw.rtMu.Lock()
	gw.health = ev
	gw.runtime.HealthCode = ev.Code
	gw.runtime.HealthDetail = ev.Detail
	gw.runtime.HealthTunnelAnswered = ev.TunnelAnswered
	gw.runtime.HealthExitIP = exitIP
	gw.runtime.HealthUplinkSamples = len(ev.Uplink)
	gw.rtMu.Unlock()
}

// healthSettings snapshots the operator-configured health check. Values are
// read under mu so a SIGHUP reload cannot race the watchdog.
func (gw *Gateway) healthSettings() (bool, time.Duration, string) {
	gw.mu.Lock()
	enabled := gw.config.HealthCheck.Enabled
	interval := gw.config.HealthCheck.Interval
	url := strings.TrimSpace(gw.config.HealthCheck.URL)
	gw.mu.Unlock()

	d, err := time.ParseDuration(interval)
	if err != nil || d < healthIntervalFloor.Load() {
		d = 60 * time.Second
	}
	if url == "" {
		url = "https://cp.cloudflare.com"
	}
	return enabled, d, url
}

// healthCheck probes the local data path first, then several independent
// endpoints through the tunnel, then the exit identity. The local check
// distinguishes "engine answers but clients cannot be forwarded" from an
// upstream outage, and the identity checks distinguish "the tunnel answered but
// its exit could not be proven" from "nothing traversed the tunnel at all".
func (gw *Gateway) healthCheck() (bool, string) {
	ev := gw.observeHealth()
	gw.recordHealth(ev)
	if ev.Healthy() {
		return true, ""
	}
	return false, "health check failed: " + ev.Detail
}

// observeHealth gathers the raw evidence without publishing it, so the
// classification stays testable and the caller decides when to record it.
func (gw *Gateway) observeHealth() HealthEvidence {
	obs := HealthObservation{DataPathOK: true}
	if healthy, reason := callDataPathProbe(gw); !healthy {
		obs.DataPathOK = false
		obs.DataPathDetail = reason
		return classifyHealth(obs)
	}

	targets := gw.healthTargets()
	ctx, cancel := context.WithTimeout(gw.lifetimeContext(), 12*time.Second)
	answered := profile.TestAnyURL(ctx, gw.socksPort, targets)
	cancel()
	obs.Answered = answered
	obs.TargetCount = len(targets)
	if answered {
		// A response is not proof the tunnel carried it: a DIRECT routing rule
		// answers the probe either way. The exit and the direct uplink are
		// sampled independently, and an unverifiable identity downgrades the
		// claim without pretending the tunnel is down.
		exits, uplink, attempts := gw.observeIdentity(gw.lifetimeContext())
		obs.Exits, obs.Uplink, obs.UplinkAttempts = exits, uplink, attempts
	}
	return classifyHealth(obs)
}

// healthTargets lists the configured endpoint first, then two independent
// fallbacks. Duplicates are removed by the probe, so the default configuration
// still performs two distinct checks.
func (gw *Gateway) healthTargets() []string {
	_, _, configured := gw.healthSettings()
	targets := []string{configured}
	for _, fallback := range []string{
		"https://cp.cloudflare.com",
		"https://www.gstatic.com/generate_204",
	} {
		if fallback != configured {
			targets = append(targets, fallback)
		}
	}
	return targets
}

// recoverRuntime restarts the engine with bounded exponential backoff. It
// returns false when recovery is exhausted (FAILED) or shutdown interrupted it.
func (gw *Gateway) recoverRuntime(reason string) bool {
	gw.setRuntimeState(StateDisconnected, reason)
	gw.mu.Lock()
	gw.stopEngineLocked()
	gw.mu.Unlock()

	for attempt := 1; attempt <= maxRecoveryAttempts; attempt++ {
		if !gw.sleepRecovery(recoveryBackoff(attempt)) {
			return false
		}
		gw.setRuntimeAttempt(StateConnecting, attempt, "")
		log.Printf("🔄 Engine recovery attempt %d/%d...", attempt, maxRecoveryAttempts)
		if gw.restartEngineForRecovery() {
			if healthy, detail := callDataPathProbe(gw); !healthy {
				gw.noteStartError(fmt.Errorf("recovered engine but the data path is unusable: %s", detail))
				continue
			}
			gw.rtMu.Lock()
			gw.runtime.Restarts++
			gw.rtMu.Unlock()
			gw.setRuntimeState(StateConnected, "")
			log.Printf("✅ Engine recovered on attempt %d", attempt)
			return true
		}
		if gw.isStopping() {
			return false
		}
	}
	errMsg := reason
	if last := gw.lastStartError(); last != "" {
		errMsg = last
	}
	gw.setRuntimeState(StateFailed, errMsg)
	log.Printf("❌ Engine recovery failed after %d attempts: %s", maxRecoveryAttempts, errMsg)
	return false
}

func (gw *Gateway) sleepRecovery(d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return !gw.isStopping()
	case <-gw.ctx.Done():
		return false
	}
}

// restartEngineForRecovery serializes with Stop/Reload through mu and verifies
// the SOCKS port is free before starting, so a dying engine can never overlap
// its replacement on the same listener.
//
// On success the recovery context stays alive: it is the lifetime context of
// the restarted engine and canceling it here would terminate the process that
// was just revived. stopEngineLocked / signalStop own its cancellation.
func (gw *Gateway) restartEngineForRecovery() bool {
	if gw.isStopping() {
		return false
	}

	gw.rtMu.Lock()
	// A failed or superseded attempt may still own a live lifetime context.
	if gw.recoverCancel != nil {
		gw.recoverCancel()
	}
	ctx, cancel := context.WithCancel(gw.ctx)
	gw.recoverCtx = ctx
	gw.recoverCancel = cancel
	gw.rtMu.Unlock()

	restarted := func() bool {
		gw.mu.Lock()
		defer gw.mu.Unlock()
		if gw.isStopping() {
			return false
		}
		if !waitForPortFree(gw.socksPort, 3*time.Second) {
			gw.noteStartError(errors.New("previous engine still holds the SOCKS listener"))
			return false
		}

		link := gw.currentActiveLink()
		if link == nil {
			link = gw.getActiveLink()
		}
		if link == nil {
			gw.noteStartError(errors.New("no active link available for recovery"))
			return false
		}

		// Preserve the data path chosen at startup. Switching a tun2socks run to
		// an engine that happens to create its own TUN would leave bypath's
		// legacy routes and chains pointing at an interface nothing fills.
		if gw.legacyRoutingActive {
			origNative := gw.config.Gateway.NativeTUN
			gw.config.Gateway.NativeTUN = false
			err := gw.startEngineWithLinkFallback(link)
			gw.config.Gateway.NativeTUN = origNative
			if err != nil {
				gw.noteStartError(err)
				return false
			}
			if err := gw.ensureTunPath(); err != nil {
				gw.noteStartError(err)
				return false
			}
			return true
		}

		err := gw.startEngineWithLinkFallback(link)
		if err != nil {
			gw.noteStartError(err)
			return false
		}
		if gw.config.Gateway.Enabled && gw.config.Gateway.NativeTUN && !gw.nativeTUN {
			gw.noteStartError(errors.New("restarted engine did not provide the native TUN device"))
			gw.stopEngineLocked()
			return false
		}
		return true
	}()

	if !restarted {
		cancel()
		gw.clearRecoveryContext()
	}
	return restarted
}

// ensureTunPath restarts tun2socks when recovery finds it dead and rebuilds the
// routes attached to the recreated TUN device.
func (gw *Gateway) ensureTunPath() error {
	if gw.tunProc != nil && !gw.tunExited() {
		return nil
	}
	gw.tunProc = nil
	gw.setTunWaiter(nil)
	log.Printf("🔄 Restarting tun2socks data path...")
	if err := gw.startTun(); err != nil {
		return err
	}
	return gw.restoreLegacyRoutes()
}

// restoreLegacyRoutes re-adds the policy routes that live on tun0. Removing and
// recreating the device also removes every route the kernel attached to it, so
// the fwmark table's default route must be rebuilt or LAN traffic blackholes.
func (gw *Gateway) restoreLegacyRoutes() error {
	if !gw.legacyRoutingActive {
		return nil
	}
	if err := run("ip", "route", "replace", "default", "via", "10.0.0.1", "dev", "tun0", "table", "100"); err != nil {
		return fmt.Errorf("restoring the fwmark table default route: %w", err)
	}
	if err := run("ip", "route", "replace", gw.subnet, "dev", gw.iface, "table", "100"); err != nil {
		return fmt.Errorf("restoring the LAN route in the fwmark table: %w", err)
	}
	return nil
}

func (gw *Gateway) clearRecoveryContext() {
	gw.rtMu.Lock()
	defer gw.rtMu.Unlock()
	gw.recoverCtx = nil
	gw.recoverCancel = nil
}

// waitForPortFree waits until nothing accepts connections on port.
func waitForPortFree(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	for {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return true
		}
		conn.Close()
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
}
