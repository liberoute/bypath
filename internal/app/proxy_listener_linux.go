//go:build linux

package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Same-port rebinding must ignore the serving daemon's own engine sockets, not
// ignore arbitrary listeners. Descendants are pinned by kernel PPid records.
func checkSamePort(port int) error {
	owned := map[int]bool{os.Getpid(): true}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for changed := true; changed; {
		changed = false
		for _, entry := range entries {
			pid, e := strconv.Atoi(entry.Name())
			if e != nil || owned[pid] {
				continue
			}
			b, e := os.ReadFile(filepath.Join("/proc", entry.Name(), "status"))
			if e != nil {
				continue
			}
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "PPid:") {
					parent, _ := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
					if owned[parent] {
						owned[pid] = true
						changed = true
					}
					break
				}
			}
		}
	}
	inodes := map[string]bool{}
	for pid := range owned {
		fds, _ := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		for _, fd := range fds {
			link, e := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
			if e == nil && strings.HasPrefix(link, "socket:[") {
				inodes[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
			}
		}
	}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		b, e := os.ReadFile("/proc/net/" + name)
		if e != nil {
			return e
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			_, hex, ok := strings.Cut(fields[1], ":")
			if !ok {
				continue
			}
			p, _ := strconv.ParseInt(hex, 16, 32)
			if int(p) != port {
				continue
			}
			if strings.HasPrefix(name, "tcp") && fields[3] != "0A" {
				continue
			}
			if !inodes[fields[9]] {
				return fmt.Errorf("port %d has a listener not owned by the serving daemon", port)
			}
		}
	}
	return nil
}
