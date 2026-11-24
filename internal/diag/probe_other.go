//go:build !linux

package diag

import (
	"net"
	"runtime"
	"time"
)

type portableHost struct{}

// DefaultHost returns the non-Linux probe implementation. Gateway checks report
// that the platform is unsupported instead of pretending to inspect it.
func DefaultHost() Host { return portableHost{} }

func (portableHost) GOOS() string { return runtime.GOOS }

func (portableHost) TUN() (bool, string) {
	return false, "native TUN inspection is implemented on Linux only"
}

func (portableHost) Listeners(int) []string { return nil }

func (portableHost) SystemdUnit(string) (bool, string) { return false, "unknown" }

func (portableHost) FirewallChain(string) (int, bool, string) {
	return 0, false, "firewall inspection is implemented on Linux only"
}

func (portableHost) IsRoot() bool { return false }

func (portableHost) Dial(addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	return conn.Close()
}
