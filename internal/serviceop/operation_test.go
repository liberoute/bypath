package serviceop

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/config"
)

func fixture(t *testing.T) (*Manager, string, string, *config.Config) {
	t.Helper()
	oldCheck := checkPath
	checkPath = func(string, bool) error { return nil }
	t.Cleanup(func() { checkPath = oldCheck })
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	active := filepath.Join(dir, ".active")
	raw := []byte("server:\n  listen: 127.0.0.1\n  socks_port: 2801\n  api_token: keep-private\ngateway:\n  enabled: false\n  native_tun: true\n")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(active, []byte("chosen\nselected"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server.SOCKSPort = 2901
	m := &Manager{Dir: state, Backend: Backend{Authorize: func(context.Context, string) (int, string, error) { return 123, "/usr/bin/bypath", nil }, BootID: func() string { return "boot1" }, Launch: func(context.Context, string) error { return nil }, Restart: func(context.Context) error { return nil }, Verify: func(context.Context, Job, bool) error { return nil }}}
	return m, path, active, cfg
}
func queue(t *testing.T, m *Manager, path, active string, cfg *config.Config) Operation {
	t.Helper()
	op, err := m.Queue(context.Background(), path, active, "/run/bypath/control.sock", "serving:node", "chosen:selected", cfg)
	if err != nil {
		t.Fatal(err)
	}
	j, err := m.load()
	if err != nil {
		t.Fatal(err)
	}
	j.Created = time.Now().Add(-time.Minute)
	if err = m.save(j); err != nil {
		t.Fatal(err)
	}
	return op
}
func TestPublishBeforeSupervisionAndServing(t *testing.T) {
	m, path, active, cfg := fixture(t)
	m.Backend.Launch = func(ctx context.Context, exe string) error {
		j, err := m.load()
		if err != nil {
			return err
		}
		if j.State != "queued" || exe != "/usr/bin/bypath" {
			t.Fatal("job not published")
		}
		if ctx.Err() != nil {
			t.Fatal("worker inherited caller cancellation")
		}
		now, _ := os.ReadFile(path)
		if !strings.Contains(string(now), "2901") {
			t.Fatal("configuration not staged before launch")
		}
		if !strings.Contains(string(j.OldConfig), "keep-private") {
			t.Fatal("old config not saved")
		}
		return nil
	}
	op := queue(t, m, path, active, cfg)
	restarts := 0
	m.Backend.Restart = func(context.Context) error { restarts++; return nil }
	m.Backend.Verify = func(ctx context.Context, j Job, rollback bool) error {
		if rollback || j.ServingID != "serving:node" || j.SelectedID != "chosen:selected" {
			t.Fatal("identities changed")
		}
		return nil
	}
	if err := m.Run(); err != nil {
		t.Fatal(err)
	}
	got, err := m.Get(op.ID)
	if err != nil || got.State != "serving" || restarts != 1 {
		t.Fatalf("%+v %v restarts=%d", got, err, restarts)
	}
	b, _ := os.ReadFile(active)
	if string(b) != "chosen\nselected" {
		t.Fatal("selection changed")
	}
	// A new daemon reads the same persisted public view without exposing secrets.
	replacement := &Manager{Dir: m.Dir}
	got, err = replacement.Get(op.ID)
	if err != nil || strings.Contains(got.Message, "keep-private") {
		t.Fatal("reload/poll contract failed")
	}
}
func TestHTTPSFailureRollsBackExactBytesIndependently(t *testing.T) {
	m, path, active, cfg := fixture(t)
	old, _ := os.ReadFile(path)
	op := queue(t, m, path, active, cfg)
	calls := 0
	m.Backend.Restart = func(ctx context.Context) error {
		if ctx.Err() != nil {
			t.Fatal("recovery context canceled")
		}
		calls++
		return nil
	}
	checks := 0
	m.Backend.Verify = func(ctx context.Context, j Job, rollback bool) error {
		checks++
		if !rollback {
			return errors.New("HTTPS forwarding failed although listener was up")
		}
		b, _ := os.ReadFile(path)
		a, _ := os.ReadFile(active)
		if string(b) != string(old) || string(a) != "chosen\nselected" {
			t.Fatal("rollback did not restore exact bytes")
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > Budget {
			t.Fatal("unbounded rollback")
		}
		return nil
	}
	if err := m.Run(); err != nil {
		t.Fatal(err)
	}
	got, _ := m.Get(op.ID)
	if got.State != "rolled_back" || calls != 2 || checks != 2 {
		t.Fatalf("%+v calls=%d checks=%d", got, calls, checks)
	}
}
func TestEngineFailureAndRecoveryFailureAreNotServing(t *testing.T) {
	m, path, active, cfg := fixture(t)
	op := queue(t, m, path, active, cfg)
	m.Backend.Restart = func(context.Context) error { return errors.New("engine failed") }
	if err := m.Run(); err != nil {
		t.Fatal(err)
	}
	got, _ := m.Get(op.ID)
	if got.State != "failed" {
		t.Fatalf("%+v", got)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), "2901") {
		t.Fatal("failed recovery did not restore old config")
	}
}
func TestLaunchFailureRestoresWithoutRestart(t *testing.T) {
	m, path, active, cfg := fixture(t)
	old, _ := os.ReadFile(path)
	m.Backend.Launch = func(context.Context, string) error { return errors.New("systemd-run failed") }
	op, err := m.Queue(context.Background(), path, active, "socket", "serving", "selected", cfg)
	if err == nil || op.State != "rolled_back" {
		t.Fatalf("%+v %v", op, err)
	}
	now, _ := os.ReadFile(path)
	if string(now) != string(old) {
		t.Fatal("launch failure lost old config")
	}
}
func TestWorkerCrashRestoresInsteadOfRetryingCandidate(t *testing.T) {
	m, path, active, cfg := fixture(t)
	op := queue(t, m, path, active, cfg)
	j, _ := m.load()
	j.State = "restarting"
	_ = m.save(j)
	calls := 0
	m.Backend.Restart = func(context.Context) error { calls++; return nil }
	m.Backend.Verify = func(_ context.Context, _ Job, rollback bool) error {
		if !rollback {
			t.Fatal("candidate retried after interruption")
		}
		return nil
	}
	if err := m.Run(); err != nil {
		t.Fatal(err)
	}
	got, _ := m.Get(op.ID)
	if calls != 1 || got.State != "rolled_back" {
		t.Fatalf("%+v calls=%d", got, calls)
	}
}
func TestRebootRecoveryBeforeConfigParsing(t *testing.T) {
	m, path, active, cfg := fixture(t)
	op := queue(t, m, path, active, cfg)
	m.Backend.BootID = func() string { return "boot2" }
	if err := os.WriteFile(path, []byte("invalid: ["), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.RecoverBeforeLoad(path); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(path); err != nil {
		t.Fatal("recovery did not precede parse", err)
	}
	j, _ := m.load()
	if !j.Recovering || j.State != "restarting" {
		t.Fatalf("%+v", j.Operation)
	}
	m.Backend.Verify = func(_ context.Context, _ Job, rollback bool) error {
		if !rollback {
			t.Fatal("boot recovery not classified")
		}
		return nil
	}
	if err := m.Run(); err != nil {
		t.Fatal(err)
	}
	got, _ := m.Get(op.ID)
	if got.State != "rolled_back" {
		t.Fatal(got)
	}
}
func TestInvalidConfigAndBusyNeverStage(t *testing.T) {
	m, path, active, cfg := fixture(t)
	old, _ := os.ReadFile(path)
	cfg.Server.SOCKSPort = 22
	if _, err := m.Queue(context.Background(), path, active, "sock", "serving", "selected", cfg); err == nil {
		t.Fatal("reserved port accepted")
	}
	now, _ := os.ReadFile(path)
	if string(now) != string(old) {
		t.Fatal("invalid config staged")
	}
	cfg.Server.SOCKSPort = 2901
	queue(t, m, path, active, cfg)
	if _, err := m.Queue(context.Background(), path, active, "sock", "serving", "selected", cfg); !errors.Is(err, ErrBusy) {
		t.Fatalf("%v", err)
	}
	if _, err := m.Get("../../escape"); !errors.Is(err, ErrNotFound) {
		t.Fatal("unsafe operation id")
	}
}
func TestUnsupportedDoesNotPretendToRestart(t *testing.T) {
	m := New()
	ok, _ := m.Supported(context.Background(), filepath.Join(t.TempDir(), "config"))
	if ok {
		t.Fatal("local test process claims installed service support")
	}
}
