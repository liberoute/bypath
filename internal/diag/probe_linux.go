//go:build linux

package diag

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type linuxHost struct{}

// DefaultHost returns the Linux probe implementation.
func DefaultHost() Host { return linuxHost{} }

func (linuxHost) GOOS() string { return "linux" }

func (linuxHost) TUN() (bool, string) {
	info, err := os.Stat("/dev/net/tun")
	if err != nil {
		return false, "/dev/net/tun: " + err.Error()
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return false, "/dev/net/tun exists but is not a character device"
	}
	return true, "/dev/net/tun is present"
}

func (linuxHost) Listeners(port int) []string {
	var out []string
	for _, entry := range []struct {
		path  string
		proto string
	}{
		{"/proc/net/tcp", "tcp"},
		{"/proc/net/tcp6", "tcp6"},
		{"/proc/net/udp", "udp"},
		{"/proc/net/udp6", "udp6"},
	} {
		out = append(out, readProcListeners(entry.path, entry.proto, port)...)
	}
	return out
}

// readProcListeners parses the kernel socket tables. It is read-only and works
// as an unprivileged user, unlike `ss -p` which needs root to name the process.
func readProcListeners(path, proto string, port int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		local := fields[1]
		state := fields[3]
		idx := strings.LastIndex(local, ":")
		if idx < 0 {
			continue
		}
		hexPort, err := strconv.ParseInt(local[idx+1:], 16, 32)
		if err != nil || int(hexPort) != port {
			continue
		}
		if strings.HasPrefix(proto, "tcp") && state != "0A" {
			continue
		}
		if strings.HasPrefix(proto, "udp") && state != "07" {
			continue
		}
		out = append(out, fmt.Sprintf("%s %s:%d", proto, decodeProcIP(local[:idx]), port))
	}
	return out
}

func decodeProcIP(raw string) string {
	if len(raw) == 8 {
		var b [4]byte
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(raw[i*2:i*2+2], 16, 8)
			if err != nil {
				return raw
			}
			b[3-i] = byte(v)
		}
		return net.IP(b[:]).String()
	}
	if len(raw) == 32 {
		var b [16]byte
		for i := 0; i < 4; i++ {
			// Each 32-bit word is stored in host byte order.
			for j := 0; j < 4; j++ {
				v, err := strconv.ParseUint(raw[(i*4+j)*2:(i*4+j)*2+2], 16, 8)
				if err != nil {
					return raw
				}
				b[i*4+(3-j)] = byte(v)
			}
		}
		return net.IP(b[:]).String()
	}
	return raw
}

func (linuxHost) SystemdUnit(name string) (bool, string) {
	installed := false
	for _, dir := range []string{
		"/etc/systemd/system",
		"/run/systemd/system",
		"/lib/systemd/system",
		"/usr/lib/systemd/system",
	} {
		if _, err := os.Stat(filepath.Join(dir, name+".service")); err == nil {
			installed = true
		}
	}
	state := "unknown"
	if _, err := exec.LookPath("systemctl"); err == nil {
		if out, err := exec.Command("systemctl", "is-active", name).Output(); err == nil {
			state = strings.TrimSpace(string(out))
		} else if ee, ok := err.(*exec.ExitError); ok {
			state = strings.TrimSpace(string(ee.Stderr))
			if state == "" {
				state = strings.TrimSpace(string(out))
			}
		}
	}
	return installed, state
}

func (linuxHost) FirewallChain(chain string) (int, bool, string) {
	bin := ""
	for _, candidate := range []string{"iptables", "iptables-nft", "iptables-legacy"} {
		if p, err := exec.LookPath(candidate); err == nil {
			bin = p
			break
		}
	}
	if bin == "" {
		return 0, false, "iptables not found"
	}
	out, err := exec.Command(bin, "-w", "2", "-S", chain).Output()
	if err != nil {
		return 0, true, "guard chain not installed"
	}
	count := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "-A ") {
			count++
		}
	}
	return count, true, ""
}

func (linuxHost) IsRoot() bool { return os.Geteuid() == 0 }

func (linuxHost) Dial(addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	return conn.Close()
}
