//go:build linux

package app

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// loadCeiling and memoryFloor follow spike S0.3: one sing-box instance costs
// roughly 60 MB, and a throughput transfer must not compete with a tunnel that
// is already saturating the CPU or squeezing memory.
const (
	memoryFloorMB = 200
)

// measureHostLoad reports whether a throughput job should be refused right now.
// The check is deliberately conservative: a false refusal costs a retry, a
// false start distorts the measurement and the serving tunnel.
func measureHostLoad() (bool, string) {
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			if load, err := strconv.ParseFloat(fields[0], 64); err == nil {
				if ceiling := float64(runtime.NumCPU()); load > ceiling {
					return true, fmt.Sprintf("load average %.1f exceeds %d CPUs", load, runtime.NumCPU())
				}
			}
		}
	}
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.HasPrefix(line, "MemAvailable:") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			kb, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				continue
			}
			if kb/1024 < memoryFloorMB {
				return true, fmt.Sprintf("only %d MB of memory is available", kb/1024)
			}
		}
	}
	return false, ""
}
