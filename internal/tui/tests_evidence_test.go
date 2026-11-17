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
	if line := connectivityLine(res); !strings.Contains(line, "no measurable answer") {
		t.Fatalf("connectivity line: %q", line)
	}
	if evidence := evidenceOf(res); strings.Contains(evidence, "answered in") {
		t.Fatalf("evidence invented a measurement: %q", evidence)
	}
}

func TestFailedResultSaysNoAnswer(t *testing.T) {
	res := app.TestResult{Status: "failed"}
	if line := connectivityLine(res); line != "no answer" {
		t.Fatalf("connectivity line: %q", line)
	}
}
