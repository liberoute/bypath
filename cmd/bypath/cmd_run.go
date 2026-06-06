package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/liberoute/bypath/internal/api"
	"github.com/liberoute/bypath/internal/build"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/gateway"
	"github.com/liberoute/bypath/internal/geo"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/pidfile"
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

	// Setup logging
	setupLogging(p)

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

	log.Printf("🚀 %s starting...", build.FullVersion())

	// Background update check
	go updater.CheckAndLog()

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("❌ Config error: %v", err)
	}

	// Download geosite files if configured
	if len(cfg.Whitelist.GeositeCountries) > 0 {
		updateInterval, parseErr := time.ParseDuration(cfg.Whitelist.UpdateInterval)
		if parseErr != nil {
			updateInterval = 24 * time.Hour
		}
		geo.DownloadGeositeFiles(cfg.Whitelist.GeositeURL, cfg.Whitelist.GeositeCountries, paths.Get().GeoDir, updateInterval)
		validatedCountries := geo.ValidateGeositeFiles(cfg.Whitelist.GeositeCountries, paths.Get().GeoDir)
		if len(validatedCountries) < len(cfg.Whitelist.GeositeCountries) {
			log.Printf("⚠️  Geosite: only %d/%d country files available", len(validatedCountries), len(cfg.Whitelist.GeositeCountries))
		}
		cfg.Whitelist.GeositeCountries = validatedCountries
	}

	// Auto-download geoip rule-set files referenced in routing.rules
	if len(cfg.Routing.Rules) > 0 {
		updateInterval, parseErr := time.ParseDuration(cfg.Whitelist.UpdateInterval)
		if parseErr != nil || updateInterval == 0 {
			updateInterval = 24 * time.Hour
		}
		var geoipCountries []string
		for _, rule := range cfg.Routing.Rules {
			if strings.HasPrefix(rule.Match, "geoip:") {
				geoipCountries = append(geoipCountries, strings.TrimPrefix(rule.Match, "geoip:"))
			}
		}
		if len(geoipCountries) > 0 {
			geo.DownloadGeoipFiles(
				"https://github.com/SagerNet/sing-geoip/raw/rule-set/geoip-{country}.srs",
				geoipCountries, paths.Get().GeoDir, updateInterval)
			// xray engine needs geoip.dat/geosite.dat (xray format) — different from .srs files
			if build.Variant == "full" || cfg.Engines.PreferredEngine == "xray" {
				geo.DownloadXrayGeoFiles(paths.Get().EngineDir, updateInterval)
			}
		}
	}

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

	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGHUP)
	go func() {
		for range reloadCh {
			log.Printf("♻️  SIGHUP received — reloading config from %s", configPath)
			newCfg, err := config.Load(configPath)
			if err != nil {
				log.Printf("❌ Config reload failed: %v", err)
				continue
			}
			gw.Reload(newCfg)
		}
	}()

	// Retry loop: if no server is reachable on first start (e.g. all servers down),
	// wait and retry instead of exiting. Exiting causes systemd to restart
	// immediately, quickly exhausting StartLimitBurst and putting the service into
	// "failed" state that requires manual "systemctl reset-failed bypath".
	for {
		if err := gw.Start(); err == nil {
			break
		} else {
			log.Printf("❌ Gateway start error: %v", err)
			log.Printf("⏳ Retrying in 30s — run 'bypath bench' to find a working server")
		}
		select {
		case <-time.After(30 * time.Second):
			// retry
		case <-sigCh:
			log.Println("🛑 Shutting down...")
			return
		}
	}

	apiServer := api.NewServer(cfg, gw, engineMgr)
	go apiServer.Start()

	log.Printf("✅ %s running. API: :%d | DNS: :%d", build.Name, cfg.Server.APIPort, cfg.Server.DNSPort)

	<-sigCh

	log.Println("🛑 Shutting down...")
	gw.Stop()

	fmt.Println() // ensure clean line after signal
}
