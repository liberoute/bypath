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
	Version   = "2.5.5"
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

	// Geo data
	sb.WriteString("\nGeo Data:\n")
	geoFiles := detectGeoData()
	for _, gf := range geoFiles {
		sb.WriteString(fmt.Sprintf("  %s %s\n", gf.Status, gf.Info))
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

func detectGeoData() []geoFileInfo {
	paths := []struct {
		name string
		locs []string
	}{
		{"geoip.db", []string{"./data/geo/geoip.db", "./engines/geoip.db", "/etc/bypath/geo/geoip.db", "/usr/share/sing-box/geoip.db"}},
		{"geosite.db", []string{"./data/geo/geosite.db", "./engines/geosite.db", "/etc/bypath/geo/geosite.db", "/usr/share/sing-box/geosite.db"}},
		{"geoip.dat", []string{"./data/geo/geoip.dat", "./engines/geoip.dat", "/etc/bypath/geo/geoip.dat", "/usr/share/xray/geoip.dat"}},
		{"geosite.dat", []string{"./data/geo/geosite.dat", "./engines/geosite.dat", "/etc/bypath/geo/geosite.dat", "/usr/share/xray/geosite.dat"}},
	}

	var results []geoFileInfo
	for _, p := range paths {
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
	return results
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
	return !info.IsDir()
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
