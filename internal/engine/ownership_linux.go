//go:build linux

package engine

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// processOwnsTCPListener reports whether pid holds a LISTEN socket on port.
// A successful dial only proves that *some* process answers; this check proves
// the engine bypath just started is the one listening, so a stale engine or a
// port squatter cannot be mistaken for a working tunnel.
func processOwnsTCPListener(pid, port int) (bool, error) {
	inodes, err := listenerInodes(port)
	if err != nil {
		return false, err
	}
	if len(inodes) == 0 {
		return false, nil
	}
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", fdDir, err)
	}
	for _, e := range entries {
		target, err := os.Readlink(fdDir + "/" + e.Name())
		if err != nil {
			continue
		}
		if inodes[target] {
			return true, nil
		}
	}
	return false, nil
}

// listenerInodes collects the socket inodes in LISTEN state on port from
// /proc/net/tcp and /proc/net/tcp6, formatted as the "socket:[inode]" target
// that /proc/<pid>/fd links expose.
func listenerInodes(port int) (map[string]bool, error) {
	out := map[string]bool{}
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for i, line := range strings.Split(string(data), "\n") {
			if i == 0 {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 10 || fields[3] != "0A" {
				continue
			}
			local := fields[1]
			idx := strings.LastIndex(local, ":")
			if idx < 0 {
				continue
			}
			p, err := strconv.ParseInt(local[idx+1:], 16, 32)
			if err != nil || int(p) != port {
				continue
			}
			out["socket:["+fields[9]+"]"] = true
		}
	}
	return out, nil
}

// WaitForOwnedListener polls until pid owns a listening socket on port, the
// timeout elapses, or ctx is canceled.
func WaitForOwnedListener(ctx context.Context, pid, port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		owned, err := processOwnsTCPListener(pid, port)
		if err == nil && owned {
			return nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			if lastErr != nil {
				return fmt.Errorf("process %d does not own the listener on :%d: %w", pid, port, lastErr)
			}
			return fmt.Errorf("process %d does not own the listener on :%d", pid, port)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}
