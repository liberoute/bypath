package tui

import (
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/bench"
)

func bestRow() bench.Row {
	return bench.Row{
		Group: "default", Remark: "node-a", Protocol: "vless",
		Address: "192.0.2.4", Port: 443, Latency: 120, HTTPS: true, Passed: true,
	}
}

func TestBenchSectionRunsAndShowsRows(t *testing.T) {
	best := bestRow()
	svc := &stubService{benchReport: bench.Report{
		Groups: []string{"default"},
		Rows: []bench.Row{
			best,
			{Group: "default", Remark: "node-b", Protocol: "trojan", Address: "203.0.113.8", Port: 443, Latency: -1, Passed: false},
		},
		Best: &best,
	}}
	m := testMenu(t, svc)

	press(t, m, "7")
	if m.section != secBench {
		t.Fatalf("section 3: got %d, want the benchmark screen", m.section)
	}
	press(t, m, "r")
	if svc.lastBenchGroup != "" {
		t.Fatalf("default benchmark scope: got %q, want all groups", svc.lastBenchGroup)
	}
	if len(m.benchRows) != 2 {
		t.Fatalf("rows: got %d, want 2", len(m.benchRows))
	}
	if m.benchRows[0].Remark != "node-a" {
		t.Fatalf("first row: got %q, want the report order", m.benchRows[0].Remark)
	}
	if m.busy != "" {
		t.Fatalf("busy after a finished benchmark: %q", m.busy)
	}
	view := m.benchView(24)
	for _, want := range []string{"node-a", "node-b", "Best", "timeout"} {
		if !strings.Contains(view, want) {
			t.Errorf("bench view is missing %q:\n%s", want, view)
		}
	}
}

func TestBenchScopeIsForwardedAndSelectionActivates(t *testing.T) {
	best := bench.Row{Group: "work", Remark: "fast", Protocol: "vmess", Address: "9.9.9.9", Port: 8080, Latency: 42, HTTPS: true, Passed: true}
	svc := &stubService{benchReport: bench.Report{
		Groups: []string{"work"},
		Rows:   []bench.Row{best},
		Best:   &best,
	}}
	m := testMenu(t, svc)
	m.benchGroup = "work"

	press(t, m, "7", "r")
	if svc.lastBenchGroup != "work" {
		t.Fatalf("scope: got %q, want work", svc.lastBenchGroup)
	}
	press(t, m, "enter")
	if svc.lastActiveID != app.ConnectionID("work", "fast") {
		t.Fatalf("activated %q, want the selected bench row", svc.lastActiveID)
	}
}

func TestBenchSortOrdersByLatencyAndKeepsFailuresLast(t *testing.T) {
	svc := &stubService{benchReport: bench.Report{
		Groups: []string{"default"},
		Rows: []bench.Row{
			{Group: "default", Remark: "slow", Latency: 300, Passed: true, HTTPS: true},
			{Group: "default", Remark: "broken", Latency: -1, Passed: false},
			{Group: "default", Remark: "fast", Latency: 50, Passed: true, HTTPS: true},
		},
	}}
	m := testMenu(t, svc)
	press(t, m, "7", "r", "s")
	got := []string{m.benchRows[0].Remark, m.benchRows[1].Remark, m.benchRows[2].Remark}
	want := []string{"fast", "slow", "broken"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sorted rows: got %v, want %v", got, want)
		}
	}
	press(t, m, "s")
	if m.benchRows[0].Remark != "slow" {
		t.Fatalf("second s should restore report order, got %q first", m.benchRows[0].Remark)
	}
}

func TestBenchErrorIsShownWithoutDroppingPreviousRows(t *testing.T) {
	svc := &stubService{benchErr: &app.Error{Code: app.CodeInvalid, Message: "no testable links found in the selected scope"}}
	m := testMenu(t, svc)
	m.benchRows = []bench.Row{{Group: "default", Remark: "kept", Passed: true, HTTPS: true}}

	press(t, m, "7", "r")
	if len(m.benchRows) != 1 || m.benchRows[0].Remark != "kept" {
		t.Fatalf("a failed run must keep the previous rows, got %v", m.benchRows)
	}
	if !strings.Contains(m.benchErr, "no testable links") {
		t.Fatalf("bench error not surfaced: %q", m.benchErr)
	}
}
