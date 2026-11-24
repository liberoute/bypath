package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/liberoute/bypath/internal/geo"
	"github.com/liberoute/bypath/internal/paths"
)

// benchmarkPoll is how often the benchmark listener is re-checked while an
// engine starts.
const benchmarkPoll = 200 * time.Millisecond

// BenchmarkEngine is one engine instance started for a local benchmark
// listener. It is stopped as soon as the row's probe finishes.
type BenchmarkEngine struct {
	Name     string
	Embedded bool
	runner   EmbeddedRunner
	cmd      *exec.Cmd
}

// Stop releases the listener and any process this benchmark started.
func (b *BenchmarkEngine) Stop() {
	if b == nil {
		return
	}
	if b.runner != nil {
		if err := b.runner.Stop(); err != nil {
			log.Printf("  ⚠️  benchmark %s stop: %v", b.Name, err)
		}
		b.runner = nil
	}
	if b.cmd != nil && b.cmd.Process != nil {
		_ = b.cmd.Process.Kill()
		_, _ = b.cmd.Process.Wait()
		b.cmd = nil
	}
}

// FindBinary resolves an engine binary from PATH or the managed engine
// directory. It never downloads: a benchmark must use the engines the
// installation already provides.
func FindBinary(name, engineDir string) (string, bool) {
	bin := name
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if path, err := exec.LookPath(bin); err == nil {
		return path, true
	}
	if engineDir == "" {
		return "", false
	}
	path := filepath.Join(engineDir, bin)
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		return path, true
	}
	return "", false
}

// StartBenchmark starts name for a single local benchmark listener using the
// same selection as the live gateway: an engine embedded in this build first,
// then the external binary. It returns once the listener is accepting
// connections, so the caller can probe it immediately.
func StartBenchmark(ctx context.Context, name, configFile, engineDir string, port int, readiness time.Duration) (*BenchmarkEngine, error) {
	// OpenVPN endpoints need the verified external sing-box; the embedded
	// runner does not carry the openvpn-client endpoint support.
	if factory, ok := GetEmbedded(name); ok && name != "openvpn" {
		inst, err := startEmbeddedBenchmark(ctx, name, configFile, port, readiness, factory)
		if err == nil {
			return inst, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		log.Printf("  ⚠️  benchmark: embedded %s unavailable: %v — falling back to binary", name, err)
	}

	binary, ok := FindBinary(name, engineDir)
	if !ok {
		return nil, fmt.Errorf("%s is not available: this build has no embedded %s and no %s binary was found in PATH or %s", name, name, name, engineDir)
	}
	return startBinaryBenchmark(ctx, name, binary, configFile, port, readiness)
}

func startEmbeddedBenchmark(ctx context.Context, name, configFile string, port int, readiness time.Duration, factory EmbeddedFactory) (*BenchmarkEngine, error) {
	runner, err := factory(configFile)
	if err != nil {
		return nil, err
	}
	if err := runner.Start(); err != nil {
		_ = runner.Stop()
		return nil, err
	}
	if err := waitBenchmarkListener(ctx, os.Getpid(), port, readiness); err != nil {
		_ = runner.Stop()
		return nil, err
	}
	return &BenchmarkEngine{Name: name, Embedded: true, runner: runner}, nil
}

func startBinaryBenchmark(ctx context.Context, name, binary, configFile string, port int, readiness time.Duration) (*BenchmarkEngine, error) {
	cmd := exec.CommandContext(ctx, binary, "run", "-c", configFile)
	// External xray looks for geoip.dat/geosite.dat next to its own binary.
	// Point it at the provisioned directory exactly like the gateway does.
	if name == "xray" && os.Getenv("xray.location.asset") == "" {
		if dir := geo.FindXrayAssetDir(paths.Get().EngineDir, paths.Get().GeoDir); dir != "" {
			cmd.Env = append(os.Environ(), "xray.location.asset="+dir)
		}
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if err := waitBenchmarkListener(ctx, cmd.Process.Pid, port, readiness); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, err
	}
	return &BenchmarkEngine{Name: name, cmd: cmd}, nil
}

// waitBenchmarkListener waits until pid owns the listening socket on port and
// the listener answers. Ownership proves the engine we started is the one
// serving the port instead of a squatter; the dial proves it accepts traffic.
func waitBenchmarkListener(ctx context.Context, pid, port int, readiness time.Duration) error {
	deadline := time.Now().Add(readiness)
	var lastErr error
	for {
		owned, err := processOwnsTCPListener(pid, port)
		if err != nil {
			lastErr = err
		} else if owned {
			conn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
			if dialErr == nil {
				conn.Close()
				return nil
			}
			lastErr = dialErr
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return fmt.Errorf("listener :%d not ready within %s: %w", port, readiness, lastErr)
			}
			return fmt.Errorf("listener :%d not ready within %s", port, readiness)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(benchmarkPoll):
		}
	}
}
