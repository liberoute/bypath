//go:build !windows

package paths

import "path/filepath"

// controlSocketPath lives under a dedicated directory so the socket can be
// group-accessible while the secrets-bearing tmp directory stays 0700.
func controlSocketPath(installed bool, runtimeRoot string) string {
	if installed {
		return "/run/bypath-control/control.sock"
	}
	return filepath.Join(runtimeRoot, "bypath-control", "control.sock")
}
