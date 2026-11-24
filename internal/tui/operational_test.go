package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/app"
)

// The terminal must show operational measurements as their own layer: real
// numbers, a MEASURED verdict, and an explicit statement that the exit is not
// proven. It must never render one as a verified path.

func measuredSpeed() app.TestResult {
	return app.TestResult{
		ConnectionID: "lab:shared-exit", Group: "lab", Remark: "shared-exit",
		Protocol: "vless", Kind: "speed", Status: app.TestStatusMeasured,
		Evidence: app.EvidenceOperational, HTTPSProven: true,
		MBps: 42.4, Bytes: 5_300_000, Seconds: 1.0, P50MS: 30,
		TestedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

func TestMeasuredResultRendersOperationalEvidence(t *testing.T) {
	res := measuredSpeed()
	verdict, _ := resultVerdict(res)
	if verdict != "MEASURED" {
		t.Fatalf("verdict = %q, want MEASURED", verdict)
	}
	if app.VerifiedTestResult(res) {
		t.Fatal("a measured row was treated as a verified path")
	}
	line := evidenceOf(res)
	for _, want := range []string{"42.4 Mbps", "5.30 MB/s", "exit unproven"} {
		if !strings.Contains(line, want) {
			t.Fatalf("evidence %q lost %q", line, want)
		}
	}
	if got := throughputLine(res); !strings.Contains(got, "MB/s") || !strings.Contains(got, "Mbps") {
		t.Fatalf("throughput line names only one unit: %q", got)
	}
}

func TestMeasuredLatencyKeepsMilliseconds(t *testing.T) {
	res := measuredSpeed()
	res.Kind, res.MBps, res.Bytes, res.Seconds = "latency", 0, 0, 0
	res.P50MS, res.LatencyMS = 118, 118
	if got := evidenceWithoutAge(res); !strings.Contains(got, "118 ms") || !strings.Contains(got, "exit unproven") {
		t.Fatalf("latency evidence = %q", got)
	}
}

func TestCompareRanksMeasuredSeparately(t *testing.T) {
	m := layoutMenu(secTests, 100, 30)
	m.tests.tab = testTabCompare
	m.tests.results = append(m.tests.results, app.TestResult{
		ConnectionID: "lab:shared-exit", Group: "lab", Remark: "shared-exit",
		Protocol: "vless", Kind: "latency", Status: app.TestStatusMeasured,
		Evidence: app.EvidenceOperational, HTTPSProven: true, P50MS: 19,
		TestedAt: time.Now().UTC().Format(time.RFC3339),
	})
	entries := m.compareEntries()
	section := ""
	ranked := 0
	for _, entry := range entries {
		if entry.heading != "" {
			section = entry.heading
		}
		if section == "Measured · operational (exit unproven)" && entry.res.ConnectionID == "lab:shared-exit" {
			ranked = entry.rank
			if app.VerifiedTestResult(entry.res) {
				t.Fatal("a measured row was ranked as verified")
			}
		}
	}
	if ranked != 1 {
		t.Fatalf("measured row was not ranked first in its own section (rank=%d)", ranked)
	}
	view := stripANSI(m.testsView(40))
	if !strings.Contains(view, "Measured · operational (exit unproven)") {
		t.Fatalf("compare view lost the operational section:\n%s", view)
	}
}
