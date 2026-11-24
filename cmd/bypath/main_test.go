package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/build"
)

// The CLI used to crash on --help (and on a bare launch without a terminal)
// when the binary was started in a non-interactive environment. Help must be a
// pure, side-effect-free path: no config load, no TUI, exit code zero.
func TestHelpVariantsPrintUsageAndExitZero(t *testing.T) {
	for _, args := range [][]string{
		{"--help"},
		{"-h"},
		{"help"},
		{"help", "run"},
		{"--help", "extra"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var out bytes.Buffer
			if code := runCLI(args, &out, true); code != 0 {
				t.Fatalf("runCLI(%v) = %d, want 0", args, code)
			}
			text := out.String()
			if !strings.Contains(text, "Usage:") || !strings.Contains(text, build.Name) {
				t.Fatalf("help output missing usage banner:\n%s", text)
			}
		})
	}
}

func TestNoArgsWithoutTerminalPrintsUsageInsteadOfTUI(t *testing.T) {
	var out bytes.Buffer
	if code := runCLI(nil, &out, false); code != 0 {
		t.Fatalf("runCLI(nil) = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Fatalf("expected usage text for a non-interactive launch, got %q", out.String())
	}
}

func TestUnknownCommandExitsOne(t *testing.T) {
	var out bytes.Buffer
	if code := runCLI([]string{"frobnicate"}, &out, false); code != 1 {
		t.Fatalf("runCLI(unknown) = %d, want 1", code)
	}
	if !strings.Contains(out.String(), "Unknown command: frobnicate") {
		t.Fatalf("missing unknown-command message: %q", out.String())
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("closed pipe")
}

func TestHelpIgnoresWriteErrors(t *testing.T) {
	if code := runCLI([]string{"--help"}, failingWriter{}, false); code != 0 {
		t.Fatalf("runCLI(--help) with a failing writer = %d, want 0", code)
	}
}

// A consumer that closes the pipe early (`bypath --help | head`) must not kill
// the process with SIGPIPE. The helper re-executes this test binary with its
// stdout connected to a pipe that has no reader.
func TestHelpStaysAliveWhenStdoutPipeCloses(t *testing.T) {
	if os.Getenv("BYPATH_HELP_PIPE_HELPER") == "1" {
		ignoreSIGPIPE()
		os.Exit(runCLI([]string{"--help"}, os.Stdout, false))
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestHelpStaysAliveWhenStdoutPipeCloses")
	cmd.Env = append(os.Environ(), "BYPATH_HELP_PIPE_HELPER=1")
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Start(); err != nil {
		r.Close()
		w.Close()
		t.Fatalf("start helper: %v", err)
	}
	w.Close()
	r.Close() // no reader remains; the helper's first write hits a broken pipe

	if err := cmd.Wait(); err != nil {
		t.Fatalf("help helper died when stdout closed early: %v", err)
	}
}
