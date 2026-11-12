package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/liberoute/bypath/internal/build"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/geo"
	"github.com/liberoute/bypath/internal/paths"
)

// geoipSRSURL is the pinned rule-set source. It serves binary sing-box rule
// sets; downloads are validated before they replace a working file.
const geoipSRSURL = "https://github.com/SagerNet/sing-geoip/raw/rule-set/geoip-{country}.srs"

// geoNeeds is the set of geo categories the active routing configuration needs.
type geoNeeds struct {
	geoip   []string
	geosite []string
}

func (n geoNeeds) empty() bool { return len(n.geoip) == 0 && len(n.geosite) == 0 }

// collectGeoNeeds unions the legacy whitelist lists with routing.rules
// references. Deny rules need their database just as direct rules do: a skipped
// matcher changes behaviour either way.
func collectGeoNeeds(cfg *config.Config) geoNeeds {
	var n geoNeeds
	seenIP := map[string]bool{}
	seenSite := map[string]bool{}
	add := func(dst *[]string, seen map[string]bool, v string) {
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		*dst = append(*dst, v)
	}
	for _, c := range cfg.Whitelist.Countries {
		add(&n.geoip, seenIP, c)
	}
	for _, c := range cfg.Whitelist.GeositeCountries {
		add(&n.geosite, seenSite, c)
	}
	for _, r := range cfg.Routing.Rules {
		if v, ok := strings.CutPrefix(strings.TrimSpace(r.Match), "geoip:"); ok {
			add(&n.geoip, seenIP, v)
		}
		if v, ok := strings.CutPrefix(strings.TrimSpace(r.Match), "geosite:"); ok {
			add(&n.geosite, seenSite, v)
		}
	}
	sort.Strings(n.geoip)
	sort.Strings(n.geosite)
	return n
}

func geoUpdateInterval(cfg *config.Config) time.Duration {
	d, err := time.ParseDuration(cfg.Whitelist.UpdateInterval)
	if err != nil || d <= 0 {
		return 24 * time.Hour
	}
	return d
}

func geoWantsXray(cfg *config.Config) bool {
	return build.Variant == "full" || strings.EqualFold(strings.TrimSpace(cfg.Engines.PreferredEngine), "xray")
}

// runGeoDownload provisions every needed asset. maxAge 0 forces a refresh;
// otherwise files younger than maxAge are kept. Failures are logged, never
// silently ignored: a missing direct rule falls back to the default outbound.
func runGeoDownload(cfg *config.Config, needs geoNeeds, maxAge time.Duration) {
	if needs.empty() {
		return
	}
	p := paths.Get()
	if len(needs.geosite) > 0 {
		if strings.TrimSpace(cfg.Whitelist.GeositeURL) == "" {
			log.Printf("⚠️  geosite rule sets are configured but whitelist.geosite_url is empty; those rules keep the default outbound")
		} else if err := geo.DownloadGeositeFiles(cfg.Whitelist.GeositeURL, needs.geosite, p.GeoDir, maxAge); err != nil {
			log.Printf("⚠️  geosite download: %v", err)
		}
		valid := geo.ValidateGeositeFiles(needs.geosite, p.GeoDir)
		if len(valid) < len(needs.geosite) {
			log.Printf("⚠️  geosite: only %d/%d rule sets are usable; unmatched traffic keeps the default outbound", len(valid), len(needs.geosite))
		}
	}
	if len(needs.geoip) > 0 {
		if err := geo.DownloadGeoipFiles(geoipSRSURL, needs.geoip, p.GeoDir, maxAge); err != nil {
			log.Printf("⚠️  geoip download: %v", err)
		}
		for _, c := range needs.geoip {
			if !geo.ValidSRSFile(filepath.Join(p.GeoDir, "geoip-"+c+".srs")) {
				log.Printf("⚠️  geoip:%s rule set unavailable; that rule keeps the default outbound", c)
			}
		}
	}
	if geoWantsXray(cfg) {
		if err := geo.DownloadXrayGeoFiles(p.EngineDir, maxAge); err != nil {
			log.Printf("⚠️  xray geo database: %v", err)
		}
	}
}

// startGeoRefresh re-downloads geo assets on the configured interval so a
// restart never depends on a stale cache. Engines load the files at start, so a
// refresh only affects the next start.
func startGeoRefresh(cfg *config.Config, needs geoNeeds) {
	interval := geoUpdateInterval(cfg)
	if needs.empty() || interval < time.Minute {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			runGeoDownload(cfg, needs, interval)
		}
	}()
}

func cmdGeo(args []string) {
	sub := "status"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "update":
		cmdGeoUpdate()
	case "status":
		cmdGeoStatus()
	default:
		fmt.Printf("Unknown geo action: %s\n\nUsage:\n  bypath geo update   Download/refresh geo databases\n  bypath geo status   Show installed databases and rule coverage\n", sub)
		os.Exit(1)
	}
}

func cmdGeoUpdate() {
	cfg, err := config.Load(paths.Get().ConfigFile)
	if err != nil {
		fmt.Printf("❌ Config error: %v\n", err)
		os.Exit(1)
	}
	needs := collectGeoNeeds(cfg)
	if needs.empty() {
		fmt.Println("No geoip/geosite matchers are configured; nothing to download.")
		return
	}
	runGeoDownload(cfg, needs, 0)
	if missing := geoMissingReport(cfg, needs); len(missing) > 0 {
		fmt.Println("❌ Some matchers have no usable database:")
		for _, m := range missing {
			fmt.Println("  -", m)
		}
		os.Exit(1)
	}
	fmt.Println("✅ Geo databases updated.")
}

func cmdGeoStatus() {
	p := paths.Get()
	cfg, err := config.Load(p.ConfigFile)
	if err != nil {
		fmt.Printf("❌ Config error: %v\n", err)
		os.Exit(1)
	}
	needs := collectGeoNeeds(cfg)

	fmt.Printf("Geo directory:    %s\n", p.GeoDir)
	fmt.Printf("Engine directory: %s\n", p.EngineDir)
	fmt.Println("\nFiles:")
	seen := map[string]bool{}
	for _, dir := range []string{p.GeoDir, p.EngineDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || seen[name] || !(strings.HasSuffix(name, ".srs") || strings.HasSuffix(name, ".dat")) {
				continue
			}
			seen[name] = true
			path := filepath.Join(dir, name)
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			state := "ok"
			switch {
			case strings.HasSuffix(name, ".srs"):
				if !geo.ValidSRSFile(path) {
					state = "INVALID (not a binary rule set)"
				}
			case strings.HasSuffix(name, ".dat"):
				cats := geo.ListXrayCategories(path)
				if len(cats) == 0 {
					state = "INVALID (no categories)"
				} else {
					state = fmt.Sprintf("ok (%d categories)", len(cats))
				}
			}
			fmt.Printf("  %-24s %8d bytes  %s  %s\n", name, info.Size(), info.ModTime().Format("2006-01-02 15:04"), state)
		}
	}
	if len(seen) == 0 {
		fmt.Println("  (none)")
	}

	fmt.Println("\nRule coverage:")
	if needs.empty() {
		fmt.Println("  no geoip/geosite matchers configured")
		return
	}
	for _, c := range needs.geoip {
		srs := geo.ValidSRSFile(filepath.Join(p.GeoDir, "geoip-"+c+".srs"))
		dat := xrayCategory(p.EngineDir, "geoip.dat", strings.ToUpper(c))
		fmt.Printf("  geoip:%-10s sing-box=%s  xray=%s\n", c, yesNo(srs), yesNo(dat))
	}
	for _, c := range needs.geosite {
		srs := geo.ValidSRSFile(filepath.Join(p.GeoDir, "geosite-"+c+".srs"))
		dat := xrayCategory(p.EngineDir, "geosite.dat", c)
		fmt.Printf("  geosite:%-8s sing-box=%s  xray=%s\n", c, yesNo(srs), yesNo(dat))
	}
	if missing := geoMissingReport(cfg, needs); len(missing) > 0 {
		fmt.Println("\n❌ Missing coverage (affected rules keep the default outbound):")
		for _, m := range missing {
			fmt.Println("  -", m)
		}
		os.Exit(1)
	}
}

func xrayCategory(dir, name, code string) bool {
	path := geo.FindXrayAsset(dir, name)
	return path != "" && geo.HasXrayCategory(path, code)
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "NO"
}

// geoMissingReport lists matchers that neither engine can satisfy. A family is
// only reported when the running configuration would select that engine; here
// that means reporting when *no* engine has the data.
func geoMissingReport(cfg *config.Config, needs geoNeeds) []string {
	p := paths.Get()
	var out []string
	for _, c := range needs.geoip {
		srs := geo.ValidSRSFile(filepath.Join(p.GeoDir, "geoip-"+c+".srs"))
		dat := xrayCategory(p.EngineDir, "geoip.dat", strings.ToUpper(c))
		if !srs && !dat {
			out = append(out, "geoip:"+c)
		}
	}
	for _, c := range needs.geosite {
		srs := geo.ValidSRSFile(filepath.Join(p.GeoDir, "geosite-"+c+".srs"))
		dat := xrayCategory(p.EngineDir, "geosite.dat", c)
		if !srs && !dat {
			out = append(out, "geosite:"+c)
		}
	}
	return out
}