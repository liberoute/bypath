// Package paths resolves file paths based on installation mode.
//
// If bypath is installed system-wide (binary in /opt/bypath, /usr/local/bin, or /usr/bin),
// it uses standard Linux paths:
//   - Config:   /etc/bypath/config.yaml
//   - Profiles: /etc/bypath/profiles/
//   - Geo:      /etc/bypath/geo/
//   - Tmp:      /run/bypath/
//   - Logs:     /var/log/bypath/
//   - Engines:  /opt/bypath/engines/
//
// If bypath is running locally (./bypath or from a dev directory),
// configuration and data use working-directory-relative paths:
//   - Config:   configs/default.yaml
//   - Profiles: ./data/profiles/
//   - Geo:      ./data/geo/
//   - Engines:  ./engines/
//
// Runtime state (pidfile, stop requests, crash-recovery records) is anchored to
// the executable's directory instead, so `bypath run` and `bypath stop` agree
// even when they are invoked from different working directories.
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
	// ControlSocket is the permissioned local socket the TUI/CLI use to reach
	// the running daemon without reading root-only configuration. Empty when
	// the platform has no Unix-domain socket support.
	ControlSocket string
	// RuntimeRoot is the daemon-owned directory the control socket lives
	// under, so the listener can keep the group able to traverse to it. Empty
	// when the socket is not nested in a runtime root (installed mode).
	RuntimeRoot string
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
		// A stable, root-owned runtime directory. A per-PID directory under
		// /tmp cannot hold crash-recovery state: the next process has a
		// different PID and would never find it.
		tmpDir := "/run/bypath"

		current = &Resolved{
			Mode:          ModeInstalled,
			ConfigFile:    "/etc/bypath/config.yaml",
			DataDir:       "/etc/bypath",
			ProfileDir:    "/etc/bypath/profiles",
			TmpDir:        tmpDir,
			GeoDir:        "/etc/bypath/geo",
			EngineDir:     "/opt/bypath/engines",
			LogDir:        "/var/log/bypath",
			PidFile:       "/var/run/bypath.pid",
			ChildrenFile:  "/var/run/bypath.children",
			ControlSocket: controlSocketPath(true, ""),
		}
	} else {
		runtimeRoot := localRuntimeRoot()
		current = &Resolved{
			Mode:          ModeLocal,
			ConfigFile:    "configs/default.yaml",
			DataDir:       "./data",
			ProfileDir:    "./data/profiles",
			TmpDir:        filepath.Join(runtimeRoot, "data", "tmp"),
			GeoDir:        "./data/geo",
			EngineDir:     "./engines",
			LogDir:        "",
			PidFile:       filepath.Join(runtimeRoot, "bypath.pid"),
			ChildrenFile:  filepath.Join(runtimeRoot, "bypath.children"),
			ControlSocket: controlSocketPath(false, runtimeRoot),
			RuntimeRoot:   runtimeRoot,
		}
	}

	return current
}

// localRuntimeRoot returns an absolute directory that identifies this
// installation regardless of the current working directory. Run and stop used
// to resolve the pidfile and stop-request directory against cwd, so stopping a
// daemon from another directory reported "no daemon" while bypath was still
// serving clients. The executable's directory is stable and writable for a
// local install; when it is read-only the per-user temp directory is used.
// BYPATH_RUNTIME_DIR overrides the location for isolated test runs and
// side-by-side installations.
func localRuntimeRoot() string {
	if dir := strings.TrimSpace(os.Getenv("BYPATH_RUNTIME_DIR")); dir != "" {
		if abs, err := filepath.Abs(dir); err == nil {
			return abs
		}
		return dir
	}
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		dir := filepath.Dir(exe)
		if probe, err := os.MkdirTemp(dir, ".bypath-probe-*"); err == nil {
			os.Remove(probe)
			return dir
		}
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("bypath-%d", os.Getuid()))
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
		// The temp directory holds per-run engine configs and secrets; it must
		// never be world-readable or group-readable.
		mode := os.FileMode(0755)
		if d == r.TmpDir {
			mode = 0700
		}
		if err := os.MkdirAll(d, mode); err != nil {
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
