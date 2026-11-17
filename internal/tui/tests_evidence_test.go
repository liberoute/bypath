package tui

import (
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/app"
)

// An inconclusive result that still measured a latency carried traffic; the
// presentation must not read like a dead connection.
func TestInconclusiveWithLatencyShowsConnectivity(t *testing.T) {
	res := app.TestResult{
		Status:    "inconclusive",
		Reason:    app.ReasonConfigNotIsolated,
		LatencyMS: 1126,
	}
	if note := connectivityNote(res); !strings.Contains(note, "1126 ms") {
		t.Fatalf("connectivity note missing the measurement: %q", note)
	}
	evidence := evidenceOf(res)
	if !strings.Contains(evidence, "answered") || !strings.Contains(evidence, "not isolated") {
		t.Fatalf("evidence must separate connectivity from isolation: %q", evidence)
	}
	if line := connectivityLine(res); !strings.Contains(line, "exit ownership unproven") {
		t.Fatalf("connectivity line: %q", line)
	}
}

func TestInconclusiveWithoutAnswerClaimsNoConnectivity(t *testing.T) {
	res := app.TestResult{
		Status: "inconclusive",
		Reason: app.ReasonIsolationUnverified,
	}
	if note := connectivityNote(res); note != "" {
		t.Fatalf("no latency must not claim an answer: %q", note)
	}
	if line := connectivityLine(res); !strings.Contains(line, "no answer recorded") {
		t.Fatalf("connectivity line: %q", line)
	}
	if evidence := evidenceOf(res); strings.Contains(evidence, "answered in") || strings.Contains(evidence, "tested instance") {
		t.Fatalf("evidence invented a measurement: %q", evidence)
	}
}

// An isolated instance that completed the HTTPS probe carried traffic even
// when the exit check bailed out before the latency samples were taken.
func TestInconclusiveTunneledHTTPSStillShowsConnectivity(t *testing.T) {
	res := app.TestResult{
		Status: "inconclusive",
		Reason: app.ReasonExitEqualsServing,
		Path:   &app.PathProof{TunneledHTTPS: true, Level: "L1+L2"},
	}
	if line := connectivityLine(res); !strings.Contains(line, "answered through the tested instance") {
		t.Fatalf("connectivity line: %q", line)
	}
	if evidence := evidenceOf(res); !strings.Contains(evidence, "answered through the tested instance") {
		t.Fatalf("evidence lost the connectivity fact: %q", evidence)
	}
}

func TestFailedResultSaysNoAnswer(t *testing.T) {
	res := app.TestResult{Status: "failed"}
	if line := connectivityLine(res); line != "no answer" {
		t.Fatalf("connectivity line: %q", line)
	}
}
