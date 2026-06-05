// Package paths resolves file paths based on installation mode.
//
// If bypath is installed system-wide (binary in /opt/bypath, /usr/local/bin, or /usr/bin),
// it uses standard Linux paths:
//   - Config:   /etc/bypath/config.yaml
//   - Profiles: /etc/bypath/profiles/
//   - Geo:      /etc/bypath/geo/
//   - Tmp:      /tmp/bypath-<random>/
//   - Logs:     /var/log/bypath/
//   - Engines:  /opt/bypath/engines/
//
// If bypath is running locally (./bypath or from a dev directory),
// it uses relative paths:
//   - Config:   configs/default.yaml
//   - Profiles: ./data/profiles/
//   - Geo:      ./data/geo/
//   - Tmp:      ./data/tmp/
//   - Logs:     (stdout only)
//   - Engines:  ./engines/
package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Mode represents the installation mode.
type Mode int

const (
	ModeLocal     Mode = iota // Running from local directory (dev/portable)
	ModeInstalled             // Installed system-wide
)

// Resolved holds all resolved paths for the current run.
type Resolved struct {
	Mode         Mode
	ConfigFile   string
	DataDir      string
	ProfileDir   string
	TmpDir       string
	GeoDir       string
	EngineDir    string
	LogDir       string
	PidFile      string
	ChildrenFile string // PIDs of child processes started by bypath (dns2socks, tun2socks)
}

var current *Resolved

// Detect determines the installation mode and resolves all paths.
// Call this once at startup.
func Detect() *Resolved {
	if current != nil {
		return current
	}

	mode := detectMode()

	if mode == ModeInstalled {
		// Use /tmp/bypath-<pid> for temp files
		tmpDir := fmt.Sprintf("/tmp/bypath-%d", os.Getpid())

		current = &Resolved{
			Mode:         ModeInstalled,
			ConfigFile:   "/etc/bypath/config.yaml",
			DataDir:      "/etc/bypath",
			ProfileDir:   "/etc/bypath/profiles",
			TmpDir:       tmpDir,
			GeoDir:       "/etc/bypath/geo",
			EngineDir:    "/opt/bypath/engines",
			LogDir:       "/var/log/bypath",
			PidFile:      "/var/run/bypath.pid",
			ChildrenFile: "/var/run/bypath.children",
		}
	} else {
		current = &Resolved{
			Mode:         ModeLocal,
			ConfigFile:   "configs/default.yaml",
			DataDir:      "./data",
			ProfileDir:   "./data/profiles",
			TmpDir:       "./data/tmp",
			GeoDir:       "./data/geo",
			EngineDir:    "./engines",
			LogDir:       "",
			PidFile:      "./bypath.pid",
			ChildrenFile: "./bypath.children",
		}
	}

	return current
}

// Get returns the current resolved paths. Panics if Detect() hasn't been called.
func Get() *Resolved {
	if current == nil {
		return Detect()
	}
	return current
}

// Reset clears the cached paths (useful for testing).
func Reset() {
	current = nil
}

// EnsureDirs creates all necessary directories.
func (r *Resolved) EnsureDirs() error {
	dirs := []string{r.ProfileDir, r.TmpDir, r.GeoDir, r.EngineDir}
	if r.LogDir != "" {
		dirs = append(dirs, r.LogDir)
	}
	if r.Mode == ModeInstalled {
		dirs = append(dirs, filepath.Dir(r.ConfigFile))
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0755); err != nil {
			return err
		}
	}
	return nil
}

// detectMode checks if we're running as an installed system service.
func detectMode() Mode {
	exe, err := os.Executable()
	if err != nil {
		return ModeLocal
	}
	exe, _ = filepath.EvalSymlinks(exe)
	exe = filepath.Clean(exe)

	// Installed if binary is in known system paths
	installedPrefixes := []string{
		"/opt/bypath",
		"/usr/local/bin",
		"/usr/bin",
	}

	for _, prefix := range installedPrefixes {
		if strings.HasPrefix(exe, prefix) {
			return ModeInstalled
		}
	}

	// Also check if /etc/bypath/config.yaml exists (explicit installed mode)
	if _, err := os.Stat("/etc/bypath/config.yaml"); err == nil {
		return ModeInstalled
	}

	return ModeLocal
}
