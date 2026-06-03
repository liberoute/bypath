// Package build contains build-time branding and version information.
package build

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// These variables are set at build time via ldflags.
var (
	Name      = "Bypath"
	Version   = "2.5.6"
	Org       = "Liberoute"
	Commit    = "unknown"
	BuildDate = "unknown"
	Variant   = "lite" // "lite" or "full" — set by build tag init()
	UpdateURL = "https://api.github.com/repos/liberoute/bypath/releases/latest"
)

// FullVersion returns a formatted version string.
func FullVersion() string {
	return fmt.Sprintf("%s v%s (%s) [%s] built %s", Name, Version, shortCommit(), Variant, BuildDate)
}

// UserAgent returns the HTTP User-Agent string.
func UserAgent() string {
	return Name + "/" + Version
}

// EngineInfo holds detected engine information.
type EngineInfo struct {
	Name    string
	Path    string
	Version string
	Source  string // "embedded", "system", "local", "not found"
}

// PrintVersionInfo prints full version and system info.
func PrintVersionInfo() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("%s v%s\n", Name, Version))
	sb.WriteString(fmt.Sprintf("  Variant:    %s\n", Variant))
	sb.WriteString(fmt.Sprintf("  Commit:     %s\n", Commit))
	sb.WriteString(fmt.Sprintf("  Built:      %s\n", BuildDate))
	sb.WriteString(fmt.Sprintf("  Go:         %s\n", runtime.Version()))
	sb.WriteString(fmt.Sprintf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH))
	sb.WriteString(fmt.Sprintf("  Org:        %s\n", Org))
	sb.WriteString("\n")

	// Engines
	sb.WriteString("Engines:\n")
	engines := detectEngines()
	for _, eng := range engines {
		if eng.Source == "embedded" {
			sb.WriteString(fmt.Sprintf("  ✅ %-14s %s (embedded)\n", eng.Name, eng.Version))
		} else if eng.Source == "system" {
			sb.WriteString(fmt.Sprintf("  ✅ %-14s %s (%s)\n", eng.Name, eng.Version, eng.Path))
		} else if eng.Source == "local" {
			sb.WriteString(fmt.Sprintf("  ✅ %-14s %s (./engines/)\n", eng.Name, eng.Version))
		} else {
			sb.WriteString(fmt.Sprintf("  ❌ %-14s not found\n", eng.Name))
		}
	}

	// Gateway helpers (only relevant for lite builds — full build uses native TUN)
	if Variant == "lite" {
		sb.WriteString("\nGateway Helpers:\n")
		helpers := detectHelpers()
		for _, h := range helpers {
			sb.WriteString(fmt.Sprintf("  %s\n", h))
		}
	}

	// Geo data
	sb.WriteString("\nGeo Data:\n")
	geoFiles := detectGeoData()
	for _, gf := range geoFiles {
		if gf.Status == "" && gf.Info == "" {
			sb.WriteString("\n")
		} else if gf.Status == " " {
			sb.WriteString(fmt.Sprintf("  %s\n", gf.Info))
		} else {
			sb.WriteString(fmt.Sprintf("  %s %s\n", gf.Status, gf.Info))
		}
	}

	return sb.String()
}

// detectEngines checks for available engines on the system.
func detectEngines() []EngineInfo {
	type engineDef struct {
		name    string
		bins    []string
		verFlag string
	}

	defs := []engineDef{
		{"sing-box", []string{"sing-box"}, "version"},
		{"xray", []string{"xray"}, "version"},
		{"wireguard-go", []string{"wireguard-go"}, "--version"},
		{"openvpn", []string{"openvpn"}, "--version"},
		{"openconnect", []string{"openconnect"}, "--version"},
		{"clash-meta", []string{"mihomo", "clash-meta"}, "-v"},
	}

	var results []EngineInfo

	for _, def := range defs {
		info := EngineInfo{Name: def.name, Source: "not found"}

		// Check if embedded (full build sets this)
		if isEmbedded(def.name) {
			info.Source = "embedded"
			info.Version = "built-in"
			results = append(results, info)
			continue
		}

		// Check system PATH
		for _, bin := range def.bins {
			path, err := exec.LookPath(bin)
			if err == nil {
				info.Path = path
				info.Source = "system"
				info.Version = getEngineVersion(path, def.verFlag)
				break
			}
		}

		// Check local ./engines/ directory
		if info.Source == "not found" {
			for _, bin := range def.bins {
				localPath := "./engines/" + bin
				if runtime.GOOS == "windows" {
					localPath += ".exe"
				}
				if _, err := exec.LookPath(localPath); err == nil {
					info.Path = localPath
					info.Source = "local"
					info.Version = getEngineVersion(localPath, def.verFlag)
					break
				}
			}
		}

		results = append(results, info)
	}

	return results
}

type geoFileInfo struct {
	Status string
	Info   string
}

// KnownCountries is the list of country codes that bypath supports for geo-based routing.
var KnownCountries = []string{"ir", "cn", "us", "ru", "tr", "de", "fr", "gb", "ae"}

func detectGeoData() []geoFileInfo {
	// Standard .db/.dat files (used by sing-box/xray from system packages)
	stdFiles := []struct {
		name string
		locs []string
	}{
		{"geoip.db", []string{"/etc/bypath/geo/geoip.db", "/usr/share/sing-box/geoip.db", "./data/geo/geoip.db"}},
		{"geosite.db", []string{"/etc/bypath/geo/geosite.db", "/usr/share/sing-box/geosite.db", "./data/geo/geosite.db"}},
		{"geoip.dat", []string{"/etc/bypath/geo/geoip.dat", "/usr/local/share/xray/geoip.dat", "/usr/share/xray/geoip.dat", "./data/geo/geoip.dat"}},
		{"geosite.dat", []string{"/etc/bypath/geo/geosite.dat", "/usr/local/share/xray/geosite.dat", "/usr/share/xray/geosite.dat", "./data/geo/geosite.dat"}},
	}

	var results []geoFileInfo
	for _, p := range stdFiles {
		found := false
		for _, loc := range p.locs {
			if fileExists(loc) {
				results = append(results, geoFileInfo{"✅", fmt.Sprintf("%-14s %s", p.name, loc)})
				found = true
				break
			}
		}
		if !found {
			results = append(results, geoFileInfo{"❌", fmt.Sprintf("%-14s not found", p.name)})
		}
	}

	// Per-country .srs files (used by sing-box rule sets)
	srsDirs := []string{"/etc/bypath/geo", "./data/geo"}
	results = append(results, geoFileInfo{"", ""}) // separator
	results = append(results, geoFileInfo{" ", "Rule Sets (.srs) — per country:"})
	for _, country := range KnownCountries {
		geoipFile := fmt.Sprintf("geoip-%s.srs", country)
		geositeFile := fmt.Sprintf("geosite-%s.srs", country)
		geoipFound, geositeFound := false, false
		geoipPath, geositePath := "", ""

		for _, dir := range srsDirs {
			p := dir + "/" + geoipFile
			if fileExists(p) {
				geoipFound = true
				geoipPath = p
				break
			}
		}
		for _, dir := range srsDirs {
			p := dir + "/" + geositeFile
			if fileExists(p) {
				geositeFound = true
				geositePath = p
				break
			}
		}

		_ = geositePath
		_ = geoipPath

		var status, info string
		switch {
		case geoipFound && geositeFound:
			status = "✅"
			info = fmt.Sprintf("%-6s geoip ✅  geosite ✅", country)
		case geoipFound:
			status = "🟡"
			info = fmt.Sprintf("%-6s geoip ✅  geosite ❌", country)
		case geositeFound:
			status = "🟡"
			info = fmt.Sprintf("%-6s geoip ❌  geosite ✅", country)
		default:
			status = "❌"
			info = fmt.Sprintf("%-6s not downloaded", country)
		}
		results = append(results, geoFileInfo{status, info})
	}

	return results
}

// detectHelpers checks for gateway helper binaries (tun2socks, dns2socks).
// Also validates that found binaries are actually executable on this arch.
func detectHelpers() []string {
	type helperDef struct {
		name    string
		bins    []string
		purpose string
	}
	defs := []helperDef{
		{"tun2socks", []string{"tun2socks"}, "TUN gateway (legacy mode)"},
		{"dns2socks", []string{"dns2socks"}, "DNS-over-SOCKS (legacy mode)"},
	}

	var results []string
	for _, def := range defs {
		found := false
		for _, bin := range def.bins {
			path, err := exec.LookPath(bin)
			if err != nil {
				continue
			}
			// Validate it's actually executable (correct arch)
			cmd := exec.Command(path, "--version")
			if err2 := cmd.Run(); err2 != nil {
				// Check if it's an exec format error (wrong arch)
				if isExecFormatError(err2) {
					results = append(results, fmt.Sprintf("⚠️  %-14s found at %s but wrong architecture (exec format error)", def.name, path))
					found = true
					break
				}
			}
			results = append(results, fmt.Sprintf("✅ %-14s %s", def.name, path))
			found = true
			break
		}
		if !found {
			results = append(results, fmt.Sprintf("❌ %-14s not found — %s won't work", def.name, def.purpose))
		}
	}
	return results
}

func isExecFormatError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "exec format error")
}

func getEngineVersion(path, flag string) string {
	out, err := exec.Command(path, flag).Output()
	if err != nil {
		return "?"
	}
	// Take first line, trim
	lines := strings.Split(string(out), "\n")
	if len(lines) > 0 {
		v := strings.TrimSpace(lines[0])
		if len(v) > 60 {
			v = v[:60] + "..."
		}
		return v
	}
	return "?"
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	// A file with 0 or very few bytes is likely a stub or failed download
	return !info.IsDir() && info.Size() > 16
}

func shortCommit() string {
	if len(Commit) > 7 {
		return Commit[:7]
	}
	return Commit
}

// isEmbedded checks if an engine is compiled in (full build).
// This is overridden by embedded.go in full builds.
var embeddedEnginesList []string

func isEmbedded(name string) bool {
	for _, e := range embeddedEnginesList {
		if e == name {
			return true
		}
	}
	return false
}

// RegisterEmbeddedEngine is called by the full build to register embedded engines.
func RegisterEmbeddedEngine(name string) {
	embeddedEnginesList = append(embeddedEnginesList, name)
}
