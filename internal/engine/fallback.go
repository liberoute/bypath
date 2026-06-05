package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/profile"
)

// ConfigGeneratorIface is the subset of tunnel.ConfigGenerator used by FallbackController.
// Defined here to avoid an import cycle (engine ← tunnel ← engine is forbidden).
type ConfigGeneratorIface interface {
	Generate(eng *Engine, link *profile.Link) (string, error)
}

// FallbackResult contains the outcome of a successful fallback-aware engine start.
type FallbackResult struct {
	Engine     *Engine
	Process    *exec.Cmd
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
func (fc *FallbackController) StartWithFallback(ctx context.Context, link *profile.Link, preferredEngine string) (*FallbackResult, error) {
	order := fc.engineOrder(preferredEngine)
	timeout := fc.timeout()

	var attempts []AttemptRecord

	for i, engineName := range order {
		start := time.Now()
		proc, configFile, err := fc.tryEngine(ctx, engineName, link, timeout)
		duration := time.Since(start)

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
			ConfigFile:  configFile,
			EngineName:  engineName,
			WasFallback: i > 0,
			Attempts:    attempts,
		}, nil
	}

	// All engines failed
	var errMsg string
	for _, a := range attempts {
		if a.Err != nil {
			errMsg += fmt.Sprintf("\n  • %s: %v", a.EngineName, a.Err)
		}
	}
	return nil, fmt.Errorf("all engines failed for link '%s':%s", link.Remark, errMsg)
}

// tryEngine attempts to start a single engine and waits for its SOCKS port.
// Returns the started process and generated config file path on success.
func (fc *FallbackController) tryEngine(ctx context.Context, engineName string, link *profile.Link, timeout time.Duration) (*exec.Cmd, string, error) {
	eng, err := fc.engineMgr.Get(engineName)
	if err != nil {
		return nil, "", fmt.Errorf("engine not available: %w", err)
	}

	configFile, err := fc.configGen.Generate(eng, link)
	if err != nil {
		return nil, "", fmt.Errorf("config generation failed: %w", err)
	}

	var args []string
	switch eng.Name {
	case "sing-box", "xray":
		args = []string{"run", "-c", configFile}
	default:
		args = []string{"-c", configFile}
	}

	proc := exec.CommandContext(ctx, eng.Path, args...)
	if err := proc.Start(); err != nil {
		return nil, configFile, fmt.Errorf("start failed: %w", err)
	}

	// Poll port until ready or timeout. If the process crashes, the port stays
	// closed and we'll hit the timeout — no double-Wait race with gateway cleanup.
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", fc.socksPort), 300*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return proc, configFile, nil
		}
		time.Sleep(300 * time.Millisecond)
	}

	proc.Process.Kill()
	proc.Wait() //nolint:errcheck
	return nil, configFile, fmt.Errorf("port :%d not ready within %s", fc.socksPort, timeout)
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
