//go:build !windows

package engine

// trackChildProcess is a no-op outside Windows. Unix daemons receive SIGTERM,
// and the gateway kills and reaps engines explicitly; no OS-level job is needed.
func trackChildProcess(pid int) {}
