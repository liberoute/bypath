//go:build windows

package paths

// controlSocketPath is empty on Windows: the TUI falls back to the loopback
// API, and the daemon does not create a Unix-domain socket.
func controlSocketPath(bool, string) string { return "" }
