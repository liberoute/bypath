package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/profile"
	"pgregory.net/rapid"
)

// testConfigGen is a stub ConfigGeneratorIface that always returns a fixed file path.
type testConfigGen struct{ path string }

func (g *testConfigGen) Generate(eng *Engine, link *profile.Link) (string, error) {
	return g.path, nil
}

// makeFakeManager builds a Manager with engines pointing to a nonexistent binary (fail-fast on Start).
func makeFakeManager(t *testing.T, names ...string) *Manager {
	t.Helper()
	mgr := NewManager(config.EnginesConfig{Directory: t.TempDir()})
	for _, name := range names {
		mgr.engines[name] = &Engine{
			Name:   name,
			Path:   filepath.Join(t.TempDir(), "bypath-nonexistent-"+name),
			Source: "test",
		}
	}
	return mgr
}

// makeTempFile creates a real temp file and returns its path + cleanup func.
func makeTempFile(t *testing.T) (string, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "bypath-fc-test-*.json")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	f.Close()
	return f.Name(), func() { os.Remove(f.Name()) }
}

// --- Property 1: timeout() parses any valid duration string correctly ---

func TestProperty1_TimeoutParsedFromConfig(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		seconds := rapid.IntRange(1, 300).Draw(t, "seconds")
		timeoutStr := fmt.Sprintf("%ds", seconds)

		fc := &FallbackController{cfg: config.FallbackConfig{Timeout: timeoutStr}}
		got := fc.timeout()
		want := time.Duration(seconds) * time.Second

		if got != want {
			t.Fatalf("timeout(%q) = %v, want %v", timeoutStr, got, want)
		}
	})
}

func TestTimeout_InvalidStringDefaultsTo10s(t *testing.T) {
	fc := &FallbackController{cfg: config.FallbackConfig{Timeout: "not-a-duration"}}
	if got := fc.timeout(); got != 10*time.Second {
		t.Fatalf("timeout(invalid) = %v, want 10s", got)
	}
}

func TestTimeout_EmptyStringDefaultsTo10s(t *testing.T) {
	fc := &FallbackController{cfg: config.FallbackConfig{}}
	if got := fc.timeout(); got != 10*time.Second {
		t.Fatalf("timeout(\"\") = %v, want 10s", got)
	}
}

// --- Property 7: engineOrder always puts preferred engine first ---

func TestProperty7_EngineOrderRespectsPreferredEngine(t *testing.T) {
	pool := []string{"sing-box", "xray", "v2fly", "clash"}
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(1, 4).Draw(t, "n")
		order := pool[:n]
		preferred := rapid.SampledFrom(pool).Draw(t, "preferred")

		fc := &FallbackController{cfg: config.FallbackConfig{Order: order}}
		result := fc.engineOrder(preferred)

		if len(result) == 0 {
			t.Fatal("engineOrder returned empty slice")
		}
		if result[0] != preferred {
			t.Fatalf("engineOrder: first element = %q, want preferred %q", result[0], preferred)
		}
	})
}

func TestEngineOrder_EmptyPreferredKeepsOriginalOrder(t *testing.T) {
	order := []string{"sing-box", "xray"}
	fc := &FallbackController{cfg: config.FallbackConfig{Order: order}}
	result := fc.engineOrder("")
	if len(result) != 2 || result[0] != "sing-box" || result[1] != "xray" {
		t.Fatalf("engineOrder(\"\") = %v, want %v", result, order)
	}
}

func TestEngineOrder_DefaultsWhenOrderEmpty(t *testing.T) {
	fc := &FallbackController{cfg: config.FallbackConfig{}}
	result := fc.engineOrder("")
	if len(result) != 2 || result[0] != "sing-box" || result[1] != "xray" {
		t.Fatalf("engineOrder with empty cfg.Order = %v, want [sing-box xray]", result)
	}
}

func TestEngineOrder_PreferredMovedFromMiddle(t *testing.T) {
	order := []string{"sing-box", "xray", "v2fly"}
	fc := &FallbackController{cfg: config.FallbackConfig{Order: order}}
	result := fc.engineOrder("xray")
	if result[0] != "xray" {
		t.Fatalf("expected xray first, got %v", result)
	}
	// sing-box and v2fly must still appear (in relative order)
	if len(result) != 3 {
		t.Fatalf("expected 3 engines, got %d: %v", len(result), result)
	}
}

// --- Property 2: fallback initiation when alternative engine is available ---

// TestProperty2_FallbackEnabled_AllEnginesTried verifies that when fallback is enabled,
// StartWithFallback iterates through all engines (even after the first fails).
func TestProperty2_FallbackEnabled_AllEnginesTried(t *testing.T) {
	cfgFile, cleanup := makeTempFile(t)
	defer cleanup()

	mgr := makeFakeManager(t, "sing-box", "xray")
	fc := NewFallbackController(mgr, config.FallbackConfig{
		Enabled: true,
		Timeout: "500ms",
		Order:   []string{"sing-box", "xray"},
	}, &testConfigGen{path: cfgFile}, 12801)

	_, err := fc.StartWithFallback(context.Background(), &profile.Link{Remark: "test"}, "")
	if err == nil {
		t.Fatal("expected error since both engines have nonexistent binaries")
	}
	// Both engines must appear in the error message (both were attempted)
	if !strings.Contains(err.Error(), "sing-box") {
		t.Errorf("error should mention sing-box attempt: %v", err)
	}
	if !strings.Contains(err.Error(), "xray") {
		t.Errorf("error should mention xray attempt: %v", err)
	}
}

// TestFallbackDisabled_OnlyFirstEngineTried verifies that when fallback is disabled,
// StartWithFallback stops after the first engine fails without trying others.
func TestFallbackDisabled_OnlyFirstEngineTried(t *testing.T) {
	cfgFile, cleanup := makeTempFile(t)
	defer cleanup()

	mgr := makeFakeManager(t, "sing-box", "xray")
	fc := NewFallbackController(mgr, config.FallbackConfig{
		Enabled: false,
		Timeout: "500ms",
		Order:   []string{"sing-box", "xray"},
	}, &testConfigGen{path: cfgFile}, 12802)

	_, err := fc.StartWithFallback(context.Background(), &profile.Link{Remark: "test"}, "")
	if err == nil {
		t.Fatal("expected error since engine binary does not exist")
	}
	// xray must NOT appear in the error (only sing-box was tried)
	if strings.Contains(err.Error(), "xray") {
		t.Errorf("xray should not be tried when fallback is disabled, but error contains it: %v", err)
	}
}
