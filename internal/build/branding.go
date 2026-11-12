// Package build contains build-time branding and version information.
package build

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/liberoute/bypath/internal/embedbin"
)

// These variables are set at build time via ldflags.
var (
	Name      = "Bypath"
	Version   = "3.0.0"
	Org       = "Liberoute"
	Commit    = "unknown"
	BuildDate = "unknown"
	Variant   = "lite" // "lite" or "full" — set by build tag init()
	// EmbeddedTun2socks is set by the full+embed_tun2socks build tag.
	EmbeddedTun2socks bool
	// UpdateURL is empty for this build: the upstream project publishes a
	// different release line, and self-updating from it would install an older
	// binary over a newer local build. Release builds may set it with -ldflags.
	UpdateURL = ""
)

// variantLabel distinguishes a full build that carries the transparent-gateway
// helper from one that has to obtain it at runtime.
func variantLabel() string {
	if EmbeddedTun2socks {
		return Variant + " (embedded tun2socks)"
	}
	return Variant
}

// FullVersion returns a formatted version string. The exact commit is part of
// the version so an installed binary can always be traced back to a revision,
// not just a release number.
func FullVersion() string {
	return fmt.Sprintf("%s %s [%s] built %s", Name, versionWithCommit(), strings.ToUpper(Variant), BuildDate)
}

// versionWithCommit tags the release version with the exact build commit, e.g.
// v3.0.0-8ed3a18d065f…. Unstamped development builds keep the bare version.
func versionWithCommit() string {
	v := versionStr()
	if Commit == "" || Commit == "unknown" {
		return v
	}
	return v + "-" + Commit
}

// versionStr returns the version with a single "v" prefix.
func versionStr() string {
	if strings.HasPrefix(Version, "v") {
		return Version
	}
	return "v" + Version
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

// PrintVersionInfo prints full version and system info. enginesDir is the
// configured engines.directory and preferSystem mirrors engines.prefer_system,
// so the report resolves engines the same way the runtime does.
func PrintVersionInfo(enginesDir string, preferSystem bool) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("%s %s\n", Name, versionWithCommit()))
	sb.WriteString(fmt.Sprintf("  Variant:    %s\n", variantLabel()))
	sb.WriteString(fmt.Sprintf("  Commit:     %s\n", Commit))
	sb.WriteString(fmt.Sprintf("  Built:      %s\n", BuildDate))
	sb.WriteString(fmt.Sprintf("  Go:         %s\n", runtime.Version()))
	sb.WriteString(fmt.Sprintf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH))
	sb.WriteString(fmt.Sprintf("  Org:        %s\n", Org))
	if a, ok := embedbin.EmbeddedTun2socksInfo(); ok {
		sb.WriteString(fmt.Sprintf("  Embedded:   tun2socks %s %s/%s %d bytes sha256:%s (commit %s)\n",
			a.Version, a.GOOS, a.GOARCH, a.Size, shortDigest(a.SHA256), shortDigest(a.Commit)))
	}
	sb.WriteString("\n")

	// Engines
	sb.WriteString(fmt.Sprintf("Engines (directory: %s):\n", enginesDir))
	engines := detectEngines(enginesDir, preferSystem)
	for _, eng := range engines {
		switch eng.Source {
		case "embedded":
			sb.WriteString(fmt.Sprintf("  ✅ %-14s %s (embedded)\n", eng.Name, eng.Version))
		case "system":
			sb.WriteString(fmt.Sprintf("  ✅ %-14s %s (%s)\n", eng.Name, eng.Version, eng.Path))
		case "local":
			sb.WriteString(fmt.Sprintf("  ✅ %-14s %s (%s)\n", eng.Name, eng.Version, eng.Path))
		default:
			sb.WriteString(fmt.Sprintf("  ❌ %-14s not found\n", eng.Name))
		}
	}

	// Gateway helpers: the lite build always needs them, a full build only
	// needs tun2socks for transparent mode and may carry it inside the binary.
	sb.WriteString("\nGateway Helpers:\n")
	helpers := detectHelpers(enginesDir, preferSystem)
	for _, h := range helpers {
		sb.WriteString(fmt.Sprintf("  %s\n", h))
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

// detectEngines checks for available engines on the system. The configured
// engines directory is consulted, so a local install that keeps binaries
// outside PATH is reported accurately.
func detectEngines(enginesDir string, preferSystem bool) []EngineInfo {
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

		for _, cand := range engineCandidates(def.bins, enginesDir, preferSystem) {
			info.Path = cand.path
			info.Source = cand.source
			info.Version = getEngineVersion(cand.path, def.verFlag)
			break
		}

		results = append(results, info)
	}

	return results
}

type engineCandidate struct {
	path   string
	source string
}

// engineCandidates returns the binary paths to try, in the order the runtime
// resolves them (engines.prefer_system selects PATH or the engines directory
// first).
func engineCandidates(bins []string, enginesDir string, preferSystem bool) []engineCandidate {
	var byPath, byDir []engineCandidate
	for _, bin := range bins {
		if path, err := exec.LookPath(bin); err == nil {
			byPath = append(byPath, engineCandidate{path: path, source: "system"})
		}
		if path := localBinary(enginesDir, bin); path != "" {
			byDir = append(byDir, engineCandidate{path: path, source: "local"})
		}
	}
	if preferSystem {
		return append(byPath, byDir...)
	}
	return append(byDir, byPath...)
}

// localBinary returns bin inside enginesDir, trying the platform suffix.
func localBinary(enginesDir, bin string) string {
	if enginesDir == "" {
		return ""
	}
	candidates := []string{filepath.Join(enginesDir, bin)}
	if runtime.GOOS == "windows" {
		candidates = append(candidates, filepath.Join(enginesDir, bin+".exe"))
	}
	for _, p := range candidates {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
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
// Embedded helpers are reported as such instead of being looked up, otherwise
// a full-embed build whose helper is compiled in would claim it is missing.
func detectHelpers(enginesDir string, preferSystem bool) []string {
	type helperDef struct {
		name    string
		bins    []string
		purpose string
	}
	defs := []helperDef{
		{"tun2socks", []string{"tun2socks"}, "TUN gateway (transparent mode)"},
		{"dns2socks", []string{"dns2socks"}, "DNS-over-SOCKS (legacy mode)"},
	}

	var results []string
	for _, def := range defs {
		if def.name == "tun2socks" && EmbeddedTun2socks {
			if a, ok := embedbin.EmbeddedTun2socksInfo(); ok {
				results = append(results, fmt.Sprintf("✅ %-14s embedded %s (%s/%s, %d bytes)",
					def.name, a.Version, a.GOOS, a.GOARCH, a.Size))
				continue
			}
		}
		found := false
		for _, cand := range engineCandidates(def.bins, enginesDir, preferSystem) {
			// Validate it's actually executable (correct arch)
			cmd := exec.Command(cand.path, "--version")
			if err := cmd.Run(); err != nil && isExecFormatError(err) {
				results = append(results, fmt.Sprintf("⚠️  %-14s found at %s but wrong architecture (exec format error)", def.name, cand.path))
				found = true
				break
			}
			results = append(results, fmt.Sprintf("✅ %-14s %s", def.name, cand.path))
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

// shortDigest abbreviates a hex digest for a human-readable version report.
func shortDigest(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// isEmbedded checks if an engine is compiled in (full build).
// This is overridden by embedded.go in full builds.
var embeddedEnginesList []string

// IsEmbeddedEngine reports whether name is compiled into this build.
func IsEmbeddedEngine(name string) bool {
	return isEmbedded(name)
}

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
