package app

import (
	"context"
	"errors"

	"github.com/liberoute/bypath/internal/bench"
)

// BenchRequest selects the links a benchmark run covers. An empty group means
// every group.
type BenchRequest struct {
	Group string `json:"group,omitempty"`
}

// Bench benchmarks the stored links from inside the gateway process, which owns
// the profile files. It never changes the active link; the caller activates a
// row explicitly, exactly like the CLI does.
func (s *Local) Bench(ctx context.Context, req BenchRequest) (bench.Report, error) {
	if s.profiles == nil {
		return bench.Report{}, errorf(CodeUnavailable, "profile manager is not available")
	}
	// Benchmark listeners are numbered from a fixed base, so two runs inside
	// the same process must not overlap; the queue waits for the turn instead
	// of failing on a port collision.
	s.benchMu.Lock()
	defer s.benchMu.Unlock()
	hostKey := ""
	var preferred string
	var order []string
	fallback := false
	if cfg := s.Config(); cfg != nil {
		hostKey = cfg.Server.SSHHostKey
		preferred = cfg.Engines.PreferredEngine
		order = cfg.Engines.Fallback.Order
		fallback = cfg.Engines.Fallback.Enabled
	}
	opts := bench.Options{
		HostKeyPolicy:   hostKey,
		TmpDir:          s.paths.TmpDir,
		EngineDir:       s.paths.EngineDir,
		PreferredEngine: preferred,
		EngineOrder:     order,
		FallbackEnabled: fallback,
		ProfileDir:      s.paths.ProfileDir,
	}
	report, err := bench.Run(ctx, s.profiles, bench.Request{Group: req.Group}, opts)
	if err != nil {
		switch {
		case errors.Is(err, bench.ErrNoGroups):
			return bench.Report{}, errorf(CodeNotFound, "no groups found")
		case errors.Is(err, bench.ErrNoLinks):
			return bench.Report{}, errorf(CodeNotFound, "no testable links found in the selected scope")
		default:
			return bench.Report{}, errorf(CodeInternal, "benchmark failed: %v", err)
		}
	}
	return report, nil
}
