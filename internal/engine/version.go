package engine

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// versionToken matches the first dotted release in `<binary> version` output,
// e.g. "Xray 26.10.31 ..." or "sing-box version 1.14.4".
var versionToken = regexp.MustCompile(`\b(\d+\.\d+(?:\.\d+)?)\b`)

type versionProbe struct {
	raw string
	err error
}

// versionCache caches `<binary> version` per path; the binary cannot change
// while the process runs, and probing costs a subprocess spawn.
var versionCache sync.Map

// QueryVersion reports the release string printed by `<binary> version`.
func (e *Engine) QueryVersion() (string, error) {
	if e == nil || e.Path == "" {
		return "", fmt.Errorf("engine has no binary path")
	}
	if cached, ok := versionCache.Load(e.Path); ok {
		p := cached.(versionProbe)
		return p.raw, p.err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, e.Path, "version").CombinedOutput()
	raw := strings.TrimSpace(string(out))
	probe := versionProbe{raw: raw}
	if err != nil {
		probe.err = fmt.Errorf("probing %s version: %w", e.Name, err)
	}
	versionCache.Store(e.Path, probe)
	return probe.raw, probe.err
}

// RequireVersion rejects an engine release older than min. Engines without a
// binary path are descriptors (config tests, embedded modules); their version is
// fixed at build time, so the probe is skipped.
func (e *Engine) RequireVersion(min string) error {
	if e == nil {
		return fmt.Errorf("missing engine")
	}
	if e.Path == "" {
		return nil
	}
	raw, err := e.QueryVersion()
	if err != nil {
		return err
	}
	m := versionToken.FindStringSubmatch(raw)
	if m == nil {
		return fmt.Errorf("%s reported an unparsable version; need >= %s", e.Name, min)
	}
	if compareVersions(m[1], min) < 0 {
		return fmt.Errorf("%s %s is older than the required %s; update or reinstall the engine", e.Name, m[1], min)
	}
	return nil
}

// compareVersions compares dotted numeric releases. Missing segments count as 0,
// so "1.14" == "1.14.0".
func compareVersions(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(as) {
			av, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bv, _ = strconv.Atoi(bs[i])
		}
		if av != bv {
			if av < bv {
				return -1
			}
			return 1
		}
	}
	return 0
}
