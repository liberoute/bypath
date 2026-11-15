package gateway

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
)

func TestRecoveryBackoffIsBounded(t *testing.T) {
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second}
	for i, w := range want {
		if got := recoveryBackoff(i + 1); got != w {
			t.Errorf("attempt %d: got %v, want %v", i+1, got, w)
		}
	}
	if got, limit := recoveryBackoff(maxRecoveryAttempts+10), recoveryBackoffMax.Load(); got != limit {
		t.Errorf("backoff must cap at %v, got %v", limit, got)
	}
}

func spawnExitingProcess() *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.Command("cmd", "/c", "exit")
	}
	return exec.Command("sh", "-c", "exit 0")
}

func TestEngineExitedReflectsWaiter(t *testing.T) {
	cmd := spawnExitingProcess()
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start helper process: %v", err)
	}
	waiter := engine.WaitAsync(cmd)

	gw := &Gateway{}
	gw.setEngineWaiter(waiter)
	if gw.engineExited() {
		t.Fatal("engine reported exited before the process ended")
	}
	if !waiter.Wait(5 * time.Second) {
		t.Fatal("helper process did not exit")
	}
	if !gw.engineExited() {
		t.Fatal("engine exit was not detected")
	}
}

func TestRuntimeStatusSnapshot(t *testing.T) {
	gw := &Gateway{}
	gw.rtMu.Lock()
	gw.runtime = RuntimeStatus{State: StateConnecting}
	gw.rtMu.Unlock()

	gw.recordActiveLink(&profile.Link{Remark: "fallback-link", Protocol: "vless"})
	gw.setRuntimeEngine("xray")
	gw.setRuntimeState(StateConnected, "stale error")
	gw.markHealthy()

	st := gw.GetRuntimeStatus()
	if st.State != StateConnected {
		t.Errorf("state = %q, want CONNECTED", st.State)
	}
	if st.ActiveLink != "fallback-link" || st.Protocol != "vless" {
		t.Errorf("active link = %q/%q, want fallback-link/vless", st.ActiveLink, st.Protocol)
	}
	if st.Engine != "xray" {
		t.Errorf("engine = %q, want xray", st.Engine)
	}
	if st.LastError != "" {
		t.Errorf("last_error = %q, want empty after a healthy mark", st.LastError)
	}
	if st.LastHealth == "" {
		t.Error("last_health was not set")
	}
}

func TestSignalStopIsIdempotentAndStopsRecovery(t *testing.T) {
	gw := &Gateway{}
	stop := make(chan struct{})
	gw.watchStop = stop
	canceled := false
	gw.recoverCancel = func() { canceled = true }

	gw.signalStop()
	if !gw.isStopping() {
		t.Fatal("stopping flag not set")
	}
	if !canceled {
		t.Fatal("recovery context was not canceled")
	}
	select {
	case <-stop:
	default:
		t.Fatal("watchdog stop channel was not closed")
	}
	gw.signalStop() // must not panic on an already-closed channel
}

func TestWaitForPortFree(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if waitForPortFree(port, 100*time.Millisecond) {
		t.Fatal("reported free while the port was still bound")
	}
	ln.Close()
	if !waitForPortFree(port, time.Second) {
		t.Fatal("port was not reported free after close")
	}
}

func TestTunRecoveryRestartsOnlyTheDataPath(t *testing.T) {
	gw := &Gateway{ctx: context.Background()}
	tunCalls := 0
	setRestartTunPathHook(t, func(*Gateway) error {
		tunCalls++
		return nil
	})
	setDataPathProbeHook(t, func(*Gateway) (bool, string) { return true, "" })
	setEngineRecoveryHook(t, func(*Gateway, string) bool {
		t.Fatal("a successful data-path restart must not restart the engine")
		return false
	})

	if !gw.recoverTunPath("tun2socks exited") {
		t.Fatal("data-path recovery reported failure")
	}
	if tunCalls != 1 {
		t.Fatalf("tun restart calls = %d, want 1", tunCalls)
	}
	st := gw.GetRuntimeStatus()
	if st.TunRestarts != 1 {
		t.Fatalf("tun_restarts = %d, want 1", st.TunRestarts)
	}
	if st.State != StateConnected {
		t.Fatalf("state = %q, want CONNECTED", st.State)
	}
}

func TestTunRecoveryFallsBackToEngineAfterBoundedAttempts(t *testing.T) {
	setDataPathProbeHook(t, func(*Gateway) (bool, string) { return true, "" })
	setDuration(t, &recoveryBackoffBase, time.Millisecond)
	setDuration(t, &recoveryBackoffMax, time.Millisecond)

	gw := &Gateway{ctx: context.Background()}
	tunCalls, engineCalls := 0, 0
	setRestartTunPathHook(t, func(*Gateway) error {
		tunCalls++
		return errors.New("no tun device")
	})
	setEngineRecoveryHook(t, func(*Gateway, string) bool {
		engineCalls++
		return true
	})

	if !gw.recoverTunPath("tun2socks exited") {
		t.Fatal("fallback engine recovery result was not returned")
	}
	if tunCalls != maxTunRecoveryAttempts {
		t.Fatalf("tun restart calls = %d, want %d", tunCalls, maxTunRecoveryAttempts)
	}
	if engineCalls != 1 {
		t.Fatalf("engine recovery calls = %d, want 1", engineCalls)
	}
}

func TestHealthTargetsIncludeIndependentFallbacks(t *testing.T) {
	gw := &Gateway{config: &config.Config{}}
	got := gw.healthTargets()
	want := []string{
		"https://cp.cloudflare.com",
		"https://www.gstatic.com/generate_204",
	}
	if len(got) != len(want) {
		t.Fatalf("targets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("targets = %v, want %v", got, want)
		}
	}

	gw.config.HealthCheck.URL = "https://health.example/ping"
	got = gw.healthTargets()
	if len(got) != 3 || got[0] != "https://health.example/ping" {
		t.Fatalf("configured target missing from %v", got)
	}
}
