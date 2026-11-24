package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/bench"
	"github.com/liberoute/bypath/internal/profile"
)

// The fixture pins the next-start selection to B. Every invocation that must
// not change state is checked against these exact bytes, so a rewrite of
// profiles/.active is caught even if the content happens to be equivalent.
const (
	benchFixtureActive = "lab\nB"
	benchFixtureLayer  = `{"schema_version":1,"group":"lab","remark":"B"}`
	benchFixtureGroup  = `{"name":"lab","type":"basic","links":[
		{"remark":"A","protocol":"vless","address":"127.0.0.1","port":443},
		{"remark":"B","protocol":"vless","address":"127.0.0.2","port":8443}]}`
)

type benchHarness struct {
	dir       string
	runCalls  int
	groupSeen string
	probes    []string
}

func newBenchHarness(t *testing.T) *benchHarness {
	t.Helper()
	h := &benchHarness{dir: t.TempDir()}
	write := func(name, data string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(h.dir, name), []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("lab.json", benchFixtureGroup, 0644)
	write(".active", benchFixtureActive, 0644)
	if err := os.MkdirAll(filepath.Join(h.dir, ".layer"), 0755); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(".layer", "selection.json"), benchFixtureLayer, 0600)
	return h
}

func (h *benchHarness) assertSelectionUntouched(t *testing.T) {
	t.Helper()
	if got, err := os.ReadFile(filepath.Join(h.dir, ".active")); err != nil || string(got) != benchFixtureActive {
		t.Fatalf(".active changed: %q (err %v), want %q", got, err, benchFixtureActive)
	}
	if got, err := os.ReadFile(filepath.Join(h.dir, ".layer", "selection.json")); err != nil || string(got) != benchFixtureLayer {
		t.Fatalf(".layer/selection.json changed: %q (err %v)", got, err)
	}
}

func (h *benchHarness) assertSelected(t *testing.T, remark string) {
	t.Helper()
	want := "lab\n" + remark
	if got, err := os.ReadFile(filepath.Join(h.dir, ".active")); err != nil || string(got) != want {
		t.Fatalf(".active = %q (err %v), want %q", got, err, want)
	}
}

// assertSelectionChangedTo proves the selection actually moved: the target must
// differ from what the fixture was seeded with, so a suppressed write cannot
// satisfy the assertion.
func (h *benchHarness) assertSelectionChangedTo(t *testing.T, remark string) {
	t.Helper()
	want := "lab\n" + remark
	if want == benchFixtureActive {
		t.Fatalf("fixture already selects %q; assertion cannot prove a write", remark)
	}
	h.assertSelected(t, remark)
}

func (h *benchHarness) report(best string) bench.Report {
	report := bench.Report{
		Groups: []string{"lab"},
		Rows: []bench.Row{
			{Group: "lab", Remark: "A", Protocol: "vless", Address: "127.0.0.1", Port: 443, Latency: 20, Passed: true, HTTPS: true},
			{Group: "lab", Remark: "B", Protocol: "vless", Address: "127.0.0.2", Port: 8443, Latency: 40, Passed: true, HTTPS: true},
		},
	}
	if best != "" {
		for i := range report.Rows {
			if report.Rows[i].Remark == best {
				report.Best = &report.Rows[i]
			}
		}
	}
	return report
}

// deps replaces the profile store with a scratch directory and the network
// with fakes that record calls, so approval handling is tested without
// opening a single socket.
func (h *benchHarness) deps(t *testing.T, best string) benchDeps {
	return benchDeps{
		newManager: func() (*profile.Manager, error) { return profile.NewManager(h.dir, "default") },
		options:    func() bench.Options { return bench.Options{} },
		runAll: func(_ context.Context, _ *profile.Manager, req bench.Request, _ bench.Options) (bench.Report, error) {
			h.runCalls++
			h.groupSeen = req.Group
			return h.report(best), nil
		},
		probe: func(_ context.Context, link *profile.Link, _ bench.Options) bench.Probe {
			h.probes = append(h.probes, link.Remark)
			return bench.Probe{PingOK: true, Passed: false}
		},
	}
}

// fatalBenchDeps fails the test on any attempt to open the profile store or
// the network. It proves help and rejected arguments short-circuit before the
// benchmark starts.
func fatalBenchDeps(t *testing.T) benchDeps {
	t.Helper()
	return benchDeps{
		newManager: func() (*profile.Manager, error) { t.Fatal("newManager called"); return nil, nil },
		options:    func() bench.Options { t.Fatal("options called"); return bench.Options{} },
		runAll: func(context.Context, *profile.Manager, bench.Request, bench.Options) (bench.Report, error) {
			t.Fatal("runAll called")
			return bench.Report{}, nil
		},
		probe: func(context.Context, *profile.Link, bench.Options) bench.Probe {
			t.Fatal("probe called")
			return bench.Probe{}
		},
	}
}

// D-928d993-1: 'bypath bench --help' used to fall through to a full sweep.
func TestBenchHelpIsSideEffectFree(t *testing.T) {
	for _, args := range [][]string{
		{"--help"},
		{"-h"},
		{"--help", "-g", "lab"},
		{"-g", "lab", "--help"},
		{"--single", "1", "--help"},
	} {
		for _, interactive := range []bool{false, true} {
			name := strings.Join(args, "_")
			if interactive {
				name += "_tty"
			}
			t.Run(name, func(t *testing.T) {
				h := newBenchHarness(t)
				var out bytes.Buffer
				code := runBench(args, strings.NewReader(""), &out, interactive, fatalBenchDeps(t))
				if code != 0 {
					t.Fatalf("runBench(%v) = %d, want 0\n%s", args, code, out.String())
				}
				if !strings.Contains(out.String(), "bypath bench [options]") {
					t.Fatalf("help output missing usage:\n%s", out.String())
				}
				h.assertSelectionUntouched(t)
			})
		}
	}
}

func TestBenchRejectsInvalidArguments(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--frobnicate"}, `unknown option "--frobnicate"`},
		{[]string{"-x"}, `unknown option "-x"`},
		{[]string{"--yes", "--nope"}, `unknown option "--nope"`},
		{[]string{"positional"}, `unexpected argument "positional"`},
		{[]string{"-g"}, "-g requires a value"},
		{[]string{"--group"}, "--group requires a value"},
		{[]string{"--single"}, "--single requires a value"},
		{[]string{"--single", "-1"}, "--single requires a value"},
		{[]string{"--single", "abc"}, `invalid link number "abc"`},
		{[]string{"--single", "0"}, `invalid link number "0"`},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.args, "_"), func(t *testing.T) {
			h := newBenchHarness(t)
			var out bytes.Buffer
			code := runBench(tc.args, strings.NewReader("y\n"), &out, true, fatalBenchDeps(t))
			if code != 1 {
				t.Fatalf("runBench(%v) = %d, want 1\n%s", tc.args, code, out.String())
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Fatalf("error output missing %q:\n%s", tc.want, out.String())
			}
			if !strings.Contains(out.String(), "Usage:") {
				t.Fatalf("error output missing usage:\n%s", out.String())
			}
			h.assertSelectionUntouched(t)
		})
	}
}

// --auto without --yes has to be refused before the benchmark starts; typed
// stdin is not approval when stdin is not a terminal.
func TestBenchAutoRequiresExplicitApprovalWhenNonInteractive(t *testing.T) {
	for _, stdin := range []string{"", "\n", "y\n", "yes\n"} {
		t.Run(strings.TrimSpace(stdin), func(t *testing.T) {
			h := newBenchHarness(t)
			var out bytes.Buffer
			code := runBench([]string{"--auto"}, strings.NewReader(stdin), &out, false, fatalBenchDeps(t))
			if code != 1 {
				t.Fatalf("runBench(--auto) = %d, want 1\n%s", code, out.String())
			}
			if !strings.Contains(out.String(), "--auto needs --yes when stdin is not a terminal") {
				t.Fatalf("missing refusal message:\n%s", out.String())
			}
			h.assertSelectionUntouched(t)
		})
	}
}

// A default benchmark run must never rewrite profiles/.active; EOF, an empty
// line and even a typed "y" are not approval without a terminal.
func TestBenchNonInteractiveNeverApproves(t *testing.T) {
	for _, stdin := range []string{"", "\n", "   \n", "y\n", "yes\n", "Y\n"} {
		t.Run(strings.TrimSpace(stdin), func(t *testing.T) {
			h := newBenchHarness(t)
			var out bytes.Buffer
			code := runBench(nil, strings.NewReader(stdin), &out, false, h.deps(t, "A"))
			if code != 0 {
				t.Fatalf("runBench() = %d, want 0\n%s", code, out.String())
			}
			if h.runCalls != 1 {
				t.Fatalf("runAll calls = %d, want 1", h.runCalls)
			}
			if !strings.Contains(out.String(), "Selection unchanged (non-interactive; pass --yes to select the best link).") {
				t.Fatalf("missing non-interactive refusal:\n%s", out.String())
			}
			if strings.Contains(out.String(), "Auto-select this link?") {
				t.Fatalf("prompted on a non-interactive run:\n%s", out.String())
			}
			h.assertSelectionUntouched(t)
		})
	}
}

func TestBenchInteractiveDeclinesWithoutAffirmativeAnswer(t *testing.T) {
	for _, stdin := range []string{"", "\n", "   \n", "n\n", "no\n", "maybe\n", "yy\n"} {
		t.Run(strings.TrimSpace(stdin), func(t *testing.T) {
			h := newBenchHarness(t)
			var out bytes.Buffer
			code := runBench(nil, strings.NewReader(stdin), &out, true, h.deps(t, "A"))
			if code != 0 {
				t.Fatalf("runBench() = %d, want 0\n%s", code, out.String())
			}
			if !strings.Contains(out.String(), "Auto-select this link? [y/N]: ") {
				t.Fatalf("missing confirmation prompt:\n%s", out.String())
			}
			if !strings.Contains(out.String(), "Selection unchanged.") {
				t.Fatalf("missing refusal:\n%s", out.String())
			}
			h.assertSelectionUntouched(t)
		})
	}
}

func TestBenchInteractiveAffirmativeSelects(t *testing.T) {
	for _, stdin := range []string{"y\n", "yes\n", " Y \n", "YES\n"} {
		t.Run(strings.TrimSpace(stdin), func(t *testing.T) {
			h := newBenchHarness(t)
			var out bytes.Buffer
			code := runBench(nil, strings.NewReader(stdin), &out, true, h.deps(t, "A"))
			if code != 0 {
				t.Fatalf("runBench() = %d, want 0\n%s", code, out.String())
			}
			if !strings.Contains(out.String(), "✅ Selected!") {
				t.Fatalf("missing selection confirmation:\n%s", out.String())
			}
			h.assertSelectionChangedTo(t, "A")
		})
	}
}

func TestBenchExplicitYesSelectsWithoutPrompt(t *testing.T) {
	h := newBenchHarness(t)
	var out bytes.Buffer
	code := runBench([]string{"--yes"}, strings.NewReader(""), &out, false, h.deps(t, "A"))
	if code != 0 {
		t.Fatalf("runBench(--yes) = %d, want 0\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "Auto-select this link?") {
		t.Fatalf("prompted despite --yes:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "✅ Selected!") {
		t.Fatalf("missing selection confirmation:\n%s", out.String())
	}
	h.assertSelectionChangedTo(t, "A")
}

func TestBenchAutoYesSelectsWhenNonInteractive(t *testing.T) {
	h := newBenchHarness(t)
	var out bytes.Buffer
	code := runBench([]string{"--auto", "--yes"}, strings.NewReader(""), &out, false, h.deps(t, "A"))
	if code != 0 {
		t.Fatalf("runBench(--auto --yes) = %d, want 0\n%s", code, out.String())
	}
	if strings.Contains(out.String(), "Auto-select this link?") {
		t.Fatalf("prompted despite --yes:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "✅ Selected!") {
		t.Fatalf("missing selection confirmation:\n%s", out.String())
	}
	h.assertSelectionChangedTo(t, "A")
}

func TestBenchGroupFlagReachesRunner(t *testing.T) {
	h := newBenchHarness(t)
	var out bytes.Buffer
	code := runBench([]string{"-g", "lab", "--yes"}, strings.NewReader(""), &out, false, h.deps(t, "A"))
	if code != 0 {
		t.Fatalf("runBench(-g lab) = %d, want 0\n%s", code, out.String())
	}
	if h.groupSeen != "lab" {
		t.Fatalf("runner saw group %q, want lab", h.groupSeen)
	}
}

func TestBenchSingleChecksOneRowWithoutSelection(t *testing.T) {
	h := newBenchHarness(t)
	var out bytes.Buffer
	code := runBench([]string{"--single", "2", "-g", "lab"}, strings.NewReader(""), &out, false, h.deps(t, "A"))
	if code != 0 {
		t.Fatalf("runBench(--single 2) = %d, want 0\n%s", code, out.String())
	}
	if h.runCalls != 0 {
		t.Fatalf("runAll calls = %d, want 0 for --single", h.runCalls)
	}
	if len(h.probes) != 1 || h.probes[0] != "B" {
		t.Fatalf("probes = %v, want [B]", h.probes)
	}
	text := out.String()
	if !strings.Contains(text, "B → 127.0.0.2:8443") {
		t.Fatalf("probe output missing the row:\n%s", text)
	}
	if !strings.Contains(text, "❌ Relay: failed") {
		t.Fatalf("probe output missing the relay result:\n%s", text)
	}
	if strings.Contains(text, "Auto-select this link?") {
		t.Fatalf("--single must never prompt for selection:\n%s", text)
	}
	h.assertSelectionUntouched(t)
}

func TestBenchSingleOutOfRangeFailsWithoutProbing(t *testing.T) {
	h := newBenchHarness(t)
	var out bytes.Buffer
	code := runBench([]string{"--single", "9", "-g", "lab"}, strings.NewReader(""), &out, false, h.deps(t, "A"))
	if code != 1 {
		t.Fatalf("runBench(--single 9) = %d, want 1\n%s", code, out.String())
	}
	if len(h.probes) != 0 {
		t.Fatalf("probes = %v, want none", h.probes)
	}
	if !strings.Contains(out.String(), "Link #9 not found in group 'lab'") {
		t.Fatalf("missing error:\n%s", out.String())
	}
	h.assertSelectionUntouched(t)
}

// The dispatch used to send 'bypath bench --help' into a live sweep; the
// production deps must never be reached from the help or error path.
func TestBenchHelpAndRejectionThroughDispatch(t *testing.T) {
	var help bytes.Buffer
	if code := runCLI([]string{"bench", "--help"}, &help, false); code != 0 {
		t.Fatalf("runCLI(bench --help) = %d, want 0\n%s", code, help.String())
	}
	if !strings.Contains(help.String(), "bypath bench [options]") {
		t.Fatalf("dispatch help missing usage:\n%s", help.String())
	}
	var bad bytes.Buffer
	if code := runCLI([]string{"bench", "--frobnicate"}, &bad, false); code != 1 {
		t.Fatalf("runCLI(bench --frobnicate) = %d, want 1\n%s", code, bad.String())
	}
	if !strings.Contains(bad.String(), `unknown option "--frobnicate"`) {
		t.Fatalf("dispatch error missing message:\n%s", bad.String())
	}
}
