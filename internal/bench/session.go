package bench

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/tunnel"
)

// ErrSSHUnsupported reports that a long-lived benchmark session cannot be
// opened for an SSH link. The one-shot Relay still supports SSH; the test job
// runner reports such links Unavailable instead of claiming a proof it cannot
// produce.
var ErrSSHUnsupported = errors.New("ssh links have no reusable benchmark session")

// Session is one link running on a loopback-only proxy port for the lifetime
// of several requests. Callers must Close it; the context given to Open also
// terminates the engine when cancelled.
type Session struct {
	Link   *profile.Link
	Engine string
	Port   int
	// Config is the exact engine configuration that was started. The test path
	// audit parses these bytes; it is not a secret-bearing profile file.
	Config      []byte
	ConfigFile  string // exact engine-owned configuration path
	EngineOwned bool   // StartBenchmark verified listener ownership, not just TCP readiness

	inst *engine.BenchmarkEngine
	dir  string
}

// Open starts the link on an ephemeral loopback port, trying engines in the
// same order as the live gateway. Ports are allocated by the kernel, so two
// sessions (or a leftover process) cannot collide on a fixed base.
func Open(ctx context.Context, link *profile.Link, opts Options) (*Session, error) {
	if link == nil {
		return nil, errors.New("nil link")
	}
	if link.Protocol == "ssh" {
		return nil, ErrSSHUnsupported
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("allocating a loopback port: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	linkCopy := *link
	linkCopy.ListenPort = port
	resolver, err := endpointResolver(link, opts)
	if err != nil {
		return nil, &AttemptError{Category: "test_infrastructure_failure", Err: err}
	}
	var lookup func(context.Context, string) ([]net.IPAddr, error)
	if resolver != nil {
		lookup = resolver.LookupIPAddr
	}
	pinned, err := PinServer(ctx, link.Address, lookup)
	if err != nil {
		return nil, &AttemptError{Category: "unreachable_server", Err: err}
	}
	cfgDir := filepath.Join(opts.TmpDir, fmt.Sprintf("test-%d-%d", os.Getpid(), port))

	var lastErr error
	for _, engineName := range engine.EngineStartOrder(link, opts.PreferredEngine, opts.EngineOrder, opts.FallbackEnabled) {
		eng := &engine.Engine{Name: engineName}
		if binary, found := engine.FindBinary(engineName, opts.EngineDir); found {
			eng.Path = binary
		}
		cg := tunnel.NewConfigGenerator(cfgDir)
		cg.ProfileDir = opts.ProfileDir
		cg.PinnedHosts = pinned
		configFile, err := cg.Generate(eng, &linkCopy)
		if err != nil {
			lastErr = &AttemptError{Category: "unsupported_configuration", Err: err}
			cg.DiscardGeneration()
			continue
		}
		config, err := isolateConfigFile(configFile)
		if err != nil {
			lastErr = &AttemptError{Category: "test_infrastructure_failure", Err: err}
			cg.DiscardGeneration()
			continue
		}
		inst, err := engine.StartBenchmark(ctx, engineName, configFile, opts.EngineDir, port, benchmarkReadiness)
		if err != nil {
			lastErr = &AttemptError{Category: "test_infrastructure_failure", Err: err}
			cg.DiscardGeneration()
			continue
		}
		return &Session{Link: &linkCopy, Engine: engineName, Port: port, Config: config, ConfigFile: configFile, EngineOwned: true, inst: inst, dir: cfgDir}, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no engine could start the link")
	}
	os.RemoveAll(cfgDir)
	return nil, lastErr
}

// bootstrapResolver is a seam for offline tests of endpoint preparation.
var bootstrapResolver = HostBootstrapResolver

// endpointResolver pins the tunnel server's address before the tunnel exists.
// An IP literal needs no lookup at all; only hostnames require the host's
// bootstrap resolver, which the gateway may have replaced with its own DNS.
func endpointResolver(link *profile.Link, opts Options) (*net.Resolver, error) {
	if opts.EndpointResolver != nil {
		return opts.EndpointResolver, nil
	}
	if net.ParseIP(link.Address) != nil {
		return nil, nil
	}
	return bootstrapResolver()
}

// isolateConfigFile rewrites a generated engine config so an instance that is
// supposed to prove one link carries no inert direct outbound. The returned
// bytes are what the engine starts with and what the test path audit parses.
func isolateConfigFile(configFile string) ([]byte, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	isolated, err := tunnel.IsolateConfig(data)
	if err != nil {
		return nil, err
	}
	if string(isolated) != string(data) {
		if err := os.WriteFile(configFile, isolated, 0600); err != nil {
			return nil, err
		}
	}
	return isolated, nil
}

// Close stops the engine and removes the generated configuration. It is safe to
// call more than once.
func (s *Session) Close() {
	if s == nil {
		return
	}
	if s.inst != nil {
		s.inst.Stop()
		s.inst = nil
	}
	if s.dir != "" {
		os.RemoveAll(s.dir)
		s.dir = ""
	}
}

// Sample requests one URL through the session and returns how long the
// complete response took. The caller decides which URL carries the proof.
func (s *Session) Sample(ctx context.Context, target string, limit int64) (time.Duration, []byte, error) {
	start := time.Now()
	body, err := FetchHTTPSThroughProxy(ctx, s.Port, target, limit)
	elapsed := time.Since(start)
	if err != nil {
		return elapsed, nil, err
	}
	return elapsed, body, nil
}
