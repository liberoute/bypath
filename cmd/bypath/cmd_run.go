package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/liberoute/bypath/internal/api"
	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/build"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/credential"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/gateway"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/pidfile"
	"github.com/liberoute/bypath/internal/proxyguard"
	"github.com/liberoute/bypath/internal/serviceop"
	"github.com/liberoute/bypath/internal/updater"
)

func cmdRun(args []string) {
	p := paths.Detect()
	p.EnsureDirs()

	configPath := p.ConfigFile
	for i, arg := range args {
		if (arg == "-c" || arg == "--config") && i+1 < len(args) {
			configPath = args[i+1]
		}
	}

	configPath, err := filepath.Abs(configPath)
	if err != nil {
		log.Fatal("Invalid config path")
	}
	operations := serviceop.New()

	// Setup logging
	setupLogging(p)

	// Keep the last events in memory for the TUI and web panel regardless of
	// where the log file lives. The ring buffer redacts secrets on read.
	logBuffer := app.NewLogBuffer(4000)
	log.SetOutput(io.MultiWriter(log.Writer(), logBuffer))

	// Auto-create config if it doesn't exist
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Printf("⚠️  Config file not found: %s — creating with defaults...", configPath)
		if err := createDefaultConfig(configPath); err != nil {
			log.Fatalf("❌ Could not create config: %v", err)
		}
		log.Printf("✅ Default config created: %s", configPath)
	}

	pidPath := paths.Get().PidFile

	// Atomically acquire the pidfile — only one instance can run at a time.
	if existingPID, err := pidfile.TryAcquire(pidPath); err != nil {
		log.Fatalf("❌ Gateway already running (PID: %d). Use 'bypath stop' first.", existingPID)
	}
	defer pidfile.Remove(pidPath)
	// A request left over from an earlier process must not stop this one.
	pidfile.ClearStopRequest(paths.Get().TmpDir)

	log.Printf("🚀 %s starting...", build.FullVersion())

	if err := operations.RecoverBeforeLoad(configPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("Service operation recovery failed: %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("❌ Config error: %v", err)
	}

	// Background update check against the configured release feed.
	feedURL := strings.TrimSpace(cfg.Update.URL)
	if feedURL == "" {
		feedURL = build.UpdateURL
	}
	go updater.CheckAndLog(feedURL)

	// Provision geo databases before the engine starts. Rule-set downloads are
	// validated before they replace a working copy, so a captive portal or a
	// truncated body cannot poison routing on the next restart.
	geoNeeds := collectGeoNeeds(cfg)
	runGeoDownload(cfg, geoNeeds, geoUpdateInterval(cfg))
	startGeoRefresh(cfg, geoNeeds)

	if err := proxyguard.Ensure(cfg); err != nil {
		log.Fatalf("Proxy firewall setup failed: %v", err)
	}
	defer func() {
		if err := proxyguard.Cleanup(); err != nil {
			log.Printf("Proxy firewall ownership retained: %v", err)
		}
	}()
	engineMgr := engine.NewManager(cfg.Engines)
	if err := engineMgr.Init(); err != nil {
		log.Fatalf("❌ Engine init error: %v", err)
	}

	gw, err := gateway.New(cfg, engineMgr)
	if err != nil {
		log.Fatalf("❌ Gateway init error: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	stopCh := make(chan struct{}, 1)
	requestStop := func() {
		select {
		case stopCh <- struct{}{}:
		default:
		}
	}

	// Session credentials belong to one daemon run. A crash or SIGKILL can leave
	// them behind, and app.NewLocal loads that directory; clear it before the
	// store opens so a previous run's secrets are never adopted.
	if err := credential.ClearSessionDir(filepath.Join(p.TmpDir, "session-credentials")); err != nil {
		log.Printf("⚠️  Could not clear leftover session credentials: %v", err)
	}

	// One application service owns profiles, credentials, settings and the
	// view of the live gateway. The API, the CLI and the TUI all run through it.
	svc, err := app.NewLocal(app.Options{
		Paths:             p,
		Config:            cfg,
		ConfigPath:        configPath,
		Profiles:          gw.GetProfileManager(),
		Runtime:           app.NewGatewayRuntime(gw, engineMgr, requestStop),
		Engines:           engineMgr,
		Logs:              logBuffer,
		ServiceOperations: operations,
	})
	if err != nil {
		log.Fatalf("Application service initialization failed: %v", err)
	}
	if err := operations.ResumeRecovery(context.Background()); err != nil {
		log.Printf("Service recovery worker unavailable: %v", err)
	}

	// Windows has no SIGTERM, so 'bypath stop' communicates through a request
	// file. Watching it on every platform also makes stop work when signals are
	// unavailable (e.g. a service wrapper that cannot deliver them).
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			pid, ok := pidfile.ReadStopRequest(paths.Get().TmpDir)
			if !ok {
				continue
			}
			if pid != os.Getpid() {
				continue
			}
			pidfile.ClearStopRequest(paths.Get().TmpDir)
			requestStop()
			return
		}
	}()

	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGHUP)
	go func() {
		for range reloadCh {
			log.Printf("♻️  SIGHUP received — reloading config from %s", configPath)
			if _, err := svc.ReloadConfig(); err != nil {
				log.Printf("❌ Config reload failed: %v", err)
			}
		}
	}()

	// The management surface comes up before the first tunnel attempt. An
	// operator must be able to see why every link is failing and to stop or
	// reconfigure the daemon; the control socket is the only path an
	// unprivileged account has, and waiting for a successful start would leave
	// it unreachable for exactly as long as it is needed.
	apiServer := api.NewServer(cfg, gw, engineMgr, svc)
	go apiServer.Start()

	// Retry loop: if no server is reachable on first start (e.g. all servers down),
	// wait and retry instead of exiting. Exiting causes systemd to restart
	// immediately, quickly exhausting StartLimitBurst and putting the service into
	// "failed" state that requires manual "systemctl reset-failed bypath".
	//
	// Start runs in a goroutine so SIGTERM and stop requests abort an in-flight
	// attempt immediately instead of waiting for engine startup timeouts.
retry:
	for {
		// An operator may have connected a working link over the control socket
		// while this loop was waiting. Retrying the original (failing) start
		// would tear that connection down, so the loop yields to the operator.
		// An explicit disconnect likewise stops automatic reconnection: the
		// daemon stays up so the panel remains reachable.
		if gw.GetRuntimeStatus().State == gateway.StateConnected {
			log.Printf("✅ Gateway is connected; automatic retries stopped")
			break retry
		}
		if gw.OperatorStopped() {
			log.Printf("⏸️  Gateway disconnected by the operator; automatic retries stopped")
			break retry
		}

		startDone := make(chan error, 1)
		go func() { startDone <- gw.Start() }()

		select {
		case err := <-startDone:
			if err == nil {
				break retry
			}
			log.Printf("❌ Gateway start error: %v", err)
			if gateway.IsPermanent(err) && !errors.Is(err, gateway.ErrNoActiveLink) {
				// The stored configuration cannot work until the operator edits
				// it. Retrying on a timer would hide the real cause forever.
				pidfile.Remove(pidPath)
				if err := credential.Default().ClearSession(); err != nil {
					log.Printf("⚠️  Could not clear session credentials: %v", err)
				}
				log.Fatalf("⛔ Not retrying: fix the configuration or credentials, then start again")
			}
			if errors.Is(err, gateway.ErrNoActiveLink) {
				// Not fatal: the panel is how the operator adds the first
				// connection, and a selection is picked up on the next attempt.
				log.Printf("⏳ No connection is selected yet. The panel and API stay available; select one and the gateway starts automatically.")
			} else {
				log.Printf("⏳ Retrying in 30s — run 'bypath bench' to find a working server")
			}
		case <-sigCh:
			shutdownWhileStarting(gw, startDone)
			return
		case <-stopCh:
			shutdownWhileStarting(gw, startDone)
			return
		}

		select {
		case <-time.After(30 * time.Second):
			// retry
		case <-sigCh:
			shutdownRunning(gw)
			return
		case <-stopCh:
			shutdownRunning(gw)
			return
		}
	}

	// Proxy-only runs own no DNS listener, so reporting one would be a lie.
	if cfg.Gateway.Enabled {
		log.Printf("✅ %s running. API: :%d | DNS: :%d", build.Name, cfg.Server.APIPort, cfg.Server.DNSPort)
	} else {
		log.Printf("✅ %s running. API: :%d | Proxy only (no DNS/TUN listeners)", build.Name, cfg.Server.APIPort)
	}

	select {
	case <-sigCh:
	case <-stopCh:
	}

	shutdownRunning(gw)

	fmt.Println() // ensure clean line after signal
}

// shutdownWhileStarting aborts an in-flight Start so SIGTERM does not wait for
// engine timeouts, then finishes through the normal Stop path. Start observes
// the canceled context at every stage (DNS, engine readiness, probes), so the
// wait is bounded by work already in flight rather than by a hard-coded timer.
func shutdownWhileStarting(gw *gateway.Gateway, startDone <-chan error) {
	log.Println("🛑 Shutting down (aborting startup)...")
	gw.ShutdownStartup()
	select {
	case <-startDone:
	case <-time.After(30 * time.Second):
		// Startup ignores cancellation past this bound; exit instead of waiting
		// forever. The ownership record persists, so the next start rolls back.
		log.Println("⚠️  Startup did not unwind within 30s; exiting without full rollback")
		return
	}
	shutdownRunning(gw)
}

// shutdownRunning waits for the real cleanup path. Stop cancels the gateway
// context before taking its lock, so in-flight startup work unwinds promptly
// and host state is still rolled back through the ownership record.
func shutdownRunning(gw *gateway.Gateway) {
	log.Println("🛑 Shutting down...")
	gw.Stop()
	// A "do not save" credential was only valid for the run it was entered
	// for; keep it from being reloaded by the next start of the daemon.
	if err := credential.Default().ClearSession(); err != nil {
		log.Printf("⚠️  Could not clear session credentials: %v", err)
	}
}
