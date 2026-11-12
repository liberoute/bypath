package gateway

import (
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The bypath-owned resolver override lives under /run on purpose: the kernel
// clears it on reboot, so a host that lost power or was killed before cleanup
// can never boot with a drop-in that points at a listener nothing will start.
// The legacy /etc location is still swept, so a file written by an earlier
// build cannot survive an upgrade.
var (
	resolvedDropInPath       = "/run/systemd/resolved.conf.d/90-bypath.conf"
	legacyResolvedDropInPath = "/etc/systemd/resolved.conf.d/90-bypath.conf"
)

const resolvedDropInMarker = "# Managed by bypath; removed when the gateway stops."

var dropInDNSLine = regexp.MustCompile(`^DNS=127\.0\.0\.1:([0-9]{1,5})$`)

// managedDropInPort reports the listener port when data is exactly the file
// bypath writes. Anything else — an administrator's own snippet, or a bypath
// file that was edited after it was written — is not ours to remove.
func managedDropInPort(data []byte) (int, bool) {
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 4 {
		return 0, false
	}
	if strings.TrimSpace(lines[0]) != resolvedDropInMarker || strings.TrimSpace(lines[1]) != "[Resolve]" {
		return 0, false
	}
	m := dropInDNSLine.FindStringSubmatch(strings.TrimSpace(lines[2]))
	if m == nil || strings.TrimSpace(lines[3]) != "Domains=~." {
		return 0, false
	}
	port, err := strconv.Atoi(m[1])
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

// resolvedDropInContent is the exact file setResolvedDropIn writes. Ownership
// is decided by regenerating it, not by a substring match alone.
func resolvedDropInContent(port int) string {
	return fmt.Sprintf("%s\n[Resolve]\nDNS=127.0.0.1:%d\nDomains=~.\n", resolvedDropInMarker, port)
}

// dnsListenerServes reports whether something answers DNS on 127.0.0.1:port.
// The lifecycle hook uses it to step aside from a healthy gateway instead of
// tearing down resolver configuration that instance still needs.
var dnsListenerServes = func(port int) bool {
	conn, err := net.DialTimeout("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 300*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	// Minimal A query for localhost. Any answer proves a live DNS listener.
	query := []byte{0x42, 0x43, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x09, 'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x00, 0x00, 0x01, 0x00, 0x01}
	if _, err := conn.Write(query); err != nil {
		return false
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	return err == nil && n > 2
}

// RestoreHostDNS returns the host to its own upstream after a bypath run. The
// systemd unit invokes it as ExecStartPre and ExecStopPost, which covers a
// graceful stop, a failed start, SIGKILL and a supervised restart; it is safe
// to run by hand as well. It removes only a drop-in whose content is exactly
// what bypath writes, never overwrites or deletes an administrator's file, and
// leaves the configuration alone while the gateway listener is still healthy.
func RestoreHostDNS() error {
	return restoreManagedResolvedDropIn(true, false)
}

// restoreResolvedDropIn is the in-process rollback path. The daemon has already
// stopped its DNS listeners here, so it does not need the health guard, but it
// stays strict: a file that is no longer bypath's own is reported, not deleted.
func (gw *Gateway) restoreResolvedDropIn() error {
	return restoreManagedResolvedDropIn(false, true)
}

func restoreManagedResolvedDropIn(guardServing, strict bool) error {
	removed := false
	for _, path := range []string{resolvedDropInPath, legacyResolvedDropInPath} {
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		port, ok := managedDropInPort(data)
		if !ok {
			if strict && strings.Contains(string(data), resolvedDropInMarker) {
				return fmt.Errorf("%s was not written by bypath or was edited afterwards; refusing to remove it", path)
			}
			if strings.Contains(string(data), resolvedDropInMarker) {
				log.Printf("⚠️  leaving %s untouched: it carries the bypath marker but was edited, so it is not ours to remove", path)
			}
			continue
		}
		if guardServing && dnsListenerServes(port) {
			log.Printf("ℹ️  leaving %s in place: 127.0.0.1:%d is still serving DNS", path, port)
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing %s: %w", path, err)
		}
		removed = true
		log.Printf("🔧 removed %s; host DNS returns to its own upstream", path)
	}
	if !removed {
		return nil
	}
	return restartResolvedAfterRestore()
}

// restartResolvedAfterRestore reloads the still-enabled resolver. During
// shutdown a restart is pointless and can race systemd itself, so the file
// removal alone is enough: the next boot starts resolved without it.
func restartResolvedAfterRestore() error {
	// is-system-running exits non-zero for degraded/starting/stopping, so the
	// output is read regardless of the exit status.
	out, _ := systemctlOutput("is-system-running")
	switch state := strings.TrimSpace(string(out)); state {
	case "stopping", "offline", "unknown":
		log.Printf("ℹ️  system is %s; the drop-in stays removed for the next boot", state)
		return nil
	}
	out, err := systemctlOutput("is-active", "systemd-resolved")
	if err != nil || strings.TrimSpace(string(out)) != "active" {
		return nil
	}
	if err := systemctlRun("restart", "systemd-resolved"); err != nil {
		return fmt.Errorf("restarting systemd-resolved after removing the bypath drop-in: %w", err)
	}
	log.Printf("🔧 systemd-resolved restarted; host DNS restored")
	return nil
}

// removeLegacyResolvedDropIn deletes a managed file from the old /etc location
// before a new one is written to /run, so the resolver never carries two
// bypath upstreams at once after an upgrade.
func removeLegacyResolvedDropIn() error {
	data, err := os.ReadFile(legacyResolvedDropInPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading %s: %w", legacyResolvedDropInPath, err)
	}
	if _, ok := managedDropInPort(data); !ok {
		return nil
	}
	if err := os.Remove(legacyResolvedDropInPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing the legacy drop-in %s: %w", legacyResolvedDropInPath, err)
	}
	return nil
}
