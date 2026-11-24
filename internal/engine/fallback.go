package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/geo"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
)

// startupReadyPoll is how often readiness is re-evaluated while waiting for an
// engine to accept traffic. OpenVPN needs a real HTTPS probe on every poll.
const startupReadyPoll = 300 * time.Millisecond

// httpsProbeBudget caps a single readiness HTTPS probe. It matches TestHTTPS's
// own 10s ceiling: a UDP-based tunnel can lose the first handshake packets and
// legitimately need several seconds, so a tighter cap would reject a tunnel
// that is merely retransmitting. The probe is still bounded by the startup
// deadline, and the retry loop keeps polling until that deadline.
const httpsProbeBudget = 10 * time.Second

// OpenVPNMinStartup is the smallest readiness window granted to an OpenVPN
// link. The default engine timeout is tuned for plain SOCKS links; a real
// OpenVPN handshake routinely takes longer than that on a slow route, so the
// bounded retry loop gets a floor wide enough to complete one. The gateway
// budget for an OpenVPN link is derived from this value so a second endpoint
// candidate still gets a full window after the first one fails.
const OpenVPNMinStartup = 60 * time.Second

// openVPNReadyProbe is an HTTPS endpoint addressed by IP so the readiness
// check itself performs no DNS lookup inside the tunnel.
const openVPNReadyProbe = "https://1.1.1.1"

var (
	errEngineExitedDuringStartup = errors.New("engine exited during startup")
	errStartupDeadline           = errors.New("startup deadline exceeded")
)

// ErrLocalConfig marks a start failure caused by the stored link or the
// generated configuration. Waiting cannot fix it: the operator must correct the
// profile or its credentials.
var ErrLocalConfig = errors.New("local configuration error")

// ConfigGeneratorIface is the subset of tunnel.ConfigGenerator used by FallbackController.
// Defined here to avoid an import cycle (engine ← tunnel ← engine is forbidden).
type ConfigGeneratorIface interface {
	Generate(eng *Engine, link *profile.Link) (string, error)
}

// GenerationCleaner is optionally implemented by generators that own temporary
// config/secret artifacts. Failed attempts must remove them immediately instead
// of leaving private keys behind.
type GenerationCleaner interface {
	DiscardGeneration()
	DiscardConfig(configFile string)
}

func (fc *FallbackController) discardLast() {
	if c, ok := fc.configGen.(GenerationCleaner); ok {
		c.DiscardGeneration()
	}
}

func (fc *FallbackController) discardConfig(configFile string) {
	if c, ok := fc.configGen.(GenerationCleaner); ok {
		c.DiscardConfig(configFile)
	}
}

// FallbackResult contains the outcome of a successful fallback-aware engine start.
type FallbackResult struct {
	Engine     *Engine
	Process    *exec.Cmd
	Waiter     *ExitWaiter
	ConfigFile string
	EngineName string
	// WasFallback is true if a secondary engine was used instead of the primary.
	WasFallback bool
	Attempts    []AttemptRecord
}

// AttemptRecord logs a single engine start attempt.
type AttemptRecord struct {
	EngineName string
	Err        error
	Duration   time.Duration
}

// FallbackController manages engine startup with automatic fallback.
type FallbackController struct {
	engineMgr *Manager
	configGen ConfigGeneratorIface
	cfg       config.FallbackConfig
	socksPort int
}

// NewFallbackController creates a controller with the given manager, configGen, and fallback config.
func NewFallbackController(mgr *Manager, cfg config.FallbackConfig, configGen ConfigGeneratorIface, socksPort int) *FallbackController {
	return &FallbackController{
		engineMgr: mgr,
		configGen: configGen,
		cfg:       cfg,
		socksPort: socksPort,
	}
}

// StartWithFallback tries engines in order until one starts and its SOCKS port is ready.
// If fallback is disabled only the first engine in Order is tried.
// If a preferred engine is configured via PreferredEngine it is placed first.
// XHTTP/SplitHTTP links force xray first (sing-box has no reliable XHTTP transport).
//
// ctx bounds startup only. The engine process lives as long as the caller keeps
// it; callers that also bound startup with a deadline should use
// StartWithLifetime so the process outlives the attempt.
func (fc *FallbackController) StartWithFallback(ctx context.Context, link *profile.Link, preferredEngine string) (*FallbackResult, error) {
	return fc.StartWithLifetime(ctx, ctx, link, preferredEngine)
}

// StartWithLifetime is StartWithFallback with the process lifetime separated
// from the bounded startup context. An engine started successfully under a
// per-attempt deadline must not be killed when that attempt returns.
func (fc *FallbackController) StartWithLifetime(start, lifetime context.Context, link *profile.Link, preferredEngine string) (*FallbackResult, error) {
	if preferredEngine == "" && RequiresXray(link) {
		preferredEngine = "xray"
		if link.EncryptedVLESS() {
			log.Printf("  ℹ️  VLESS Encryption requires xray")
		} else {
			log.Printf("  ℹ️  Link uses %s transport — preferring xray", link.Network)
		}
	}
	order := fc.engineOrder(preferredEngine)
	if hard := hardEngineFor(link); hard != "" {
		if preferredEngine != "" && preferredEngine != hard {
			log.Printf("  ⚠️  %s requires %s; ignoring configured engine %q", linkFeature(link), hard, preferredEngine)
		}
		order = []string{hard}
	}
	timeout := fc.timeout()

	var attempts []AttemptRecord

	for i, engineName := range order {
		began := time.Now()
		proc, waiter, configFile, err := fc.tryEngine(start, lifetime, engineName, link, timeout)
		duration := time.Since(began)

		if err != nil {
			log.Printf("  ❌ %s failed: %v", engineName, err)
			attempts = append(attempts, AttemptRecord{EngineName: engineName, Err: err, Duration: duration})

			if !fc.cfg.Enabled && i == 0 {
				break // fallback disabled — don't try others
			}
			if i < len(order)-1 {
				log.Printf("  🔄 Falling back to %s...", order[i+1])
			}
			continue
		}

		log.Printf("  ✅ %s running on :%d (%.0fs)", engineName, fc.socksPort, duration.Seconds())
		attempts = append(attempts, AttemptRecord{EngineName: engineName, Duration: duration})

		eng, _ := fc.engineMgr.Get(engineName)
		return &FallbackResult{
			Engine:      eng,
			Process:     proc,
			Waiter:      waiter,
			ConfigFile:  configFile,
			EngineName:  engineName,
			WasFallback: i > 0,
			Attempts:    attempts,
		}, nil
	}

	// All engines failed
	var errMsg string
	allLocal := len(attempts) > 0
	for _, a := range attempts {
		if a.Err != nil {
			errMsg += fmt.Sprintf("\n  • %s: %v", a.EngineName, a.Err)
		}
		if a.Err == nil || !errors.Is(a.Err, ErrLocalConfig) {
			allLocal = false
		}
	}
	if allLocal {
		// Every engine failed before it ever ran, so retrying the same stored
		// link cannot succeed. Preserve the sentinel for the caller's policy.
		return nil, fmt.Errorf("%w for link '%s':%s", ErrLocalConfig, link.Remark, errMsg)
	}
	return nil, fmt.Errorf("all engines failed for link '%s':%s", link.Remark, errMsg)
}

// tryEngine attempts to start a single engine and waits for its SOCKS port.
// Returns the started process, its exit waiter, and the generated config path.
//
// start bounds readiness; lifetime owns the process. Readiness is evaluated
// until the startup deadline: the SOCKS port must accept a connection, and
// OpenVPN additionally needs one real HTTPS round trip because the mixed
// inbound is listening long before the tunnel handshake completes. Early
// engine exit and context cancellation abort immediately.
func (fc *FallbackController) tryEngine(start, lifetime context.Context, engineName string, link *profile.Link, timeout time.Duration) (*exec.Cmd, *ExitWaiter, string, error) {
	eng, err := fc.engineMgr.Get(engineName)
	if err != nil {
		return nil, nil, "", fmt.Errorf("engine not available: %w", err)
	}

	// Fail fast when another process already owns the SOCKS port. Otherwise a
	// squatter would satisfy the readiness dial and bypath would report a
	// working tunnel that it never started.
	if conn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", fc.socksPort), 300*time.Millisecond); dialErr == nil {
		conn.Close()
		return nil, nil, "", fmt.Errorf("SOCKS port %d is already in use by another process", fc.socksPort)
	}

	configFile, err := fc.configGen.Generate(eng, link)
	if err != nil {
		fc.discardLast()
		return nil, nil, "", fmt.Errorf("%w: config generation failed: %v", ErrLocalConfig, err)
	}

	var args []string
	switch eng.Name {
	case "sing-box", "xray":
		args = []string{"run", "-c", configFile}
	default:
		args = []string{"-c", configFile}
	}

	proc := exec.CommandContext(lifetime, eng.Path, args...)
	// External xray searches for geoip.dat/geosite.dat next to its own binary.
	// Point it at the provisioned directory, otherwise a geoip: rule aborts
	// instance startup even though bypath downloaded the database.
	if eng.Name == "xray" && os.Getenv("xray.location.asset") == "" {
		if dir := geo.FindXrayAssetDir(paths.Get().EngineDir, paths.Get().GeoDir); dir != "" {
			proc.Env = append(os.Environ(), "xray.location.asset="+dir)
		}
	}
	if err := proc.Start(); err != nil {
		fc.discardConfig(configFile)
		return nil, nil, configFile, fmt.Errorf("start failed: %w", err)
	}
	waiter := WaitAsync(proc)
	// On Windows, bind the engine lifetime to this process so a forced stop of
	// the daemon cannot leave an orphan holding the SOCKS port.
	trackChildProcess(proc.Process.Pid)

	if link.Protocol == "openvpn" && timeout < OpenVPNMinStartup {
		timeout = OpenVPNMinStartup
	}
	deadline := time.Now().Add(timeout)
	portOpened := false
	var ownErr error
	ready := func() bool {
		conn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", fc.socksPort), 300*time.Millisecond)
		if dialErr != nil {
			return false
		}
		conn.Close()
		// Dialing proves that something answers. Ownership proves the engine
		// bypath launched is the process answering; without it a stale engine
		// or a port squatter would be reported as a healthy tunnel.
		owned, err := processOwnsTCPListener(proc.Process.Pid, fc.socksPort)
		if err != nil {
			ownErr = err
			return false
		}
		if !owned {
			return false
		}
		portOpened = true
		if link.Protocol != "openvpn" {
			return true
		}
		// An open SOCKS port only proves the inbound started, not that the
		// OpenVPN tunnel is usable. Retry the real HTTPS round trip until the
		// handshake completes instead of failing on the first probe.
		budget := httpsProbeBudget
		if remaining := time.Until(deadline); remaining < budget {
			budget = remaining
		}
		if budget <= 0 {
			return false
		}
		probeCtx, cancel := context.WithTimeout(start, budget)
		defer cancel()
		// An IP literal needs no resolver, so the probe does not itself queue a
		// DNS-over-tunnel request on an endpoint whose handshake is still in
		// progress. On UDP links that bootstrap traffic can starve the control
		// channel and keep the tunnel from ever becoming ready.
		return profile.TestURL(probeCtx, fc.socksPort, openVPNReadyProbe)
	}

	err = waitForEngineReady(start, deadline, waiter.Done(), waiter.Err, ready, startupReadyPoll)
	if err != nil {
		killAndReap(proc, waiter)
		fc.discardConfig(configFile)
		switch {
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return nil, waiter, configFile, fmt.Errorf("startup canceled: %w", err)
		case errors.Is(err, errEngineExitedDuringStartup):
			return nil, waiter, configFile, err
		case portOpened && link.Protocol == "openvpn":
			return nil, waiter, configFile, fmt.Errorf("OpenVPN endpoint did not pass the HTTPS health check within %s", timeout)
		case ownErr != nil:
			return nil, waiter, configFile, fmt.Errorf("cannot verify that %s owns port :%d within %s: %w", engineName, fc.socksPort, timeout, ownErr)
		default:
			return nil, waiter, configFile, fmt.Errorf("port :%d not ready within %s", fc.socksPort, timeout)
		}
	}
	return proc, waiter, configFile, nil
}

// waitForEngineReady polls ready until it reports success, the deadline
// passes, the context is canceled, or the process exits. Polling (rather than
// one blocking probe) bounds each attempt and makes early exit visible without
// racing the reaper.
func waitForEngineReady(ctx context.Context, deadline time.Time, exited <-chan struct{}, exitErr func() error, ready func() bool, poll time.Duration) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case <-exited:
			return engineExitError(exitErr)
		default:
		}
		if ready() {
			return nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errStartupDeadline
		}
		if poll > remaining {
			poll = remaining
		}
		timer := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-exited:
			timer.Stop()
			return engineExitError(exitErr)
		case <-timer.C:
		}
	}
}

func engineExitError(exitErr func() error) error {
	if exitErr != nil {
		if err := exitErr(); err != nil {
			return fmt.Errorf("%w: %v", errEngineExitedDuringStartup, err)
		}
	}
	return errEngineExitedDuringStartup
}

// killAndReap stops a startup attempt and waits for the reaper so no process
// can survive a failed attempt and race the next engine on the same port.
func killAndReap(proc *exec.Cmd, waiter *ExitWaiter) {
	if proc != nil && proc.Process != nil {
		_ = proc.Process.Kill()
	}
	waiter.Wait(5 * time.Second)
}

// EngineStartOrder returns the engine names the gateway would try for link,
// given the configured preferred engine, fallback order and fallback policy.
// It is shared with the benchmark runner so a benchmark row exercises the same
// engine selection and fallback as the live connection.
func EngineStartOrder(link *profile.Link, preferred string, order []string, fallbackEnabled bool) []string {
	if RequiresXray(link) {
		preferred = "xray"
	}
	names := order
	if len(names) == 0 {
		names = []string{"sing-box", "xray"}
	}
	if preferred != "" {
		reordered := []string{preferred}
		for _, name := range names {
			if name != preferred {
				reordered = append(reordered, name)
			}
		}
		names = reordered
	}
	if hard := hardEngineFor(link); hard != "" {
		names = []string{hard}
	}
	if !fallbackEnabled && len(names) > 1 {
		names = names[:1]
	}
	return names
}

// engineOrder returns the engine names to try, with preferredEngine first.
func (fc *FallbackController) engineOrder(preferredEngine string) []string {
	order := fc.cfg.Order
	if len(order) == 0 {
		order = []string{"sing-box", "xray"}
	}

	if preferredEngine == "" {
		return order
	}

	// Move preferredEngine to front, keeping relative order of the rest.
	result := []string{preferredEngine}
	for _, name := range order {
		if name != preferredEngine {
			result = append(result, name)
		}
	}
	return result
}

// timeout parses the configured timeout string, defaulting to 10s.
func (fc *FallbackController) timeout() time.Duration {
	if d, err := time.ParseDuration(fc.cfg.Timeout); err == nil {
		return d
	}
	return 10 * time.Second
}

// RequiresXray reports links that cannot be represented by sing-box.
func RequiresXray(link *profile.Link) bool {
	if link == nil {
		return false
	}
	if link.EncryptedVLESS() {
		return true
	}
	switch link.Network {
	case "xhttp", "splithttp":
		return true
	default:
		return false
	}
}

// FallbackCompatible reports whether candidate may replace selected without
// dropping a security requirement. When the selected link carries VLESS
// Encryption, the candidate must carry the identical non-secret encryption
// policy (handshake, appearance, resumption, padding). Being encrypted is not
// enough: switching native.0rtt to xorpub.1rtt, or to any other scheme, is a
// security change that requires an explicit policy or a Founder decision, so it
// fails closed here. The per-link authentication value is credential material
// and is intentionally not compared.
func FallbackCompatible(selected, candidate *profile.Link) bool {
	if selected == nil {
		return true
	}
	if !selected.EncryptedVLESS() {
		return true
	}
	if candidate == nil || !candidate.EncryptedVLESS() {
		return false
	}
	return selected.EncryptionParameters() == candidate.EncryptionParameters()
}

// hardEngineFor returns the only engine that can faithfully run the link.
// Falling back to another engine here would silently drop a security property
// (VLESS Encryption) or produce an unusable config (OpenVPN endpoints).
func hardEngineFor(link *profile.Link) string {
	if link == nil {
		return ""
	}
	if RequiresXray(link) {
		return "xray"
	}
	if link.Protocol == "openvpn" {
		return "sing-box"
	}
	return ""
}

func linkFeature(link *profile.Link) string {
	if link != nil && link.EncryptedVLESS() {
		return "VLESS Encryption"
	}
	if link != nil && link.Protocol == "openvpn" {
		return "OpenVPN profile"
	}
	return "profile"
}
