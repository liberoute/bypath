package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/bench"
)

// benchMsg carries one finished benchmark run.
type benchMsg struct {
	gen    int
	report bench.Report
	err    error
}

// runBench executes the benchmark through the application service, so the
// daemon that owns the profile files does the work and the TUI only displays
// the result. It is cancellable like every other long action.
func (m *Menu) runBench() tea.Cmd {
	if m.svc == nil {
		m.setNotice(true, "Application service is not available: %s", friendlyError(m.svcErr))
		return nil
	}
	if m.busy != "" {
		return nil
	}
	m.busy = "Benchmarking connections"
	m.busySince = time.Now()
	m.opCanceled = false
	m.benchGen++
	gen := m.benchGen
	svc := m.svc
	group := m.benchGroup
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	m.cancelOp = cancel
	return tea.Batch(func() tea.Msg {
		defer cancel()
		report, err := svc.Bench(ctx, app.BenchRequest{Group: group})
		return benchMsg{gen: gen, report: report, err: err}
	}, spinnerTick())
}

func (m *Menu) handleBench(msg benchMsg) tea.Cmd {
	if msg.gen != m.benchGen {
		return nil
	}
	m.busy = ""
	m.cancelOp = nil
	if m.opCanceled {
		m.opCanceled = false
		m.setNotice(false, "Benchmark cancelled.")
		return nil
	}
	if msg.err != nil {
		m.benchErr = friendlyError(msg.err)
		return nil
	}
	m.benchErr = ""
	m.benchReport = msg.report
	m.benchRows = append([]bench.Row(nil), msg.report.Rows...)
	m.benchSorted = false
	m.benchCursor, m.benchOffset = 0, 0
	if best := msg.report.Best; best != nil {
		m.setNotice(false, "Benchmark complete: %d link(s); best %s/%s at %dms.",
			len(msg.report.Rows), best.Group, best.Remark, best.Latency)
	} else {
		m.setNotice(true, "Benchmark complete: no working link was found.")
	}
	return nil
}

func (m *Menu) selectedBench() (bench.Row, bool) {
	if m.benchCursor >= 0 && m.benchCursor < len(m.benchRows) {
		return m.benchRows[m.benchCursor], true
	}
	return bench.Row{}, false
}

func (m *Menu) moveBench(delta int) {
	if len(m.benchRows) == 0 {
		return
	}
	m.benchCursor = clampInt(m.benchCursor+delta, 0, len(m.benchRows)-1)
}

func (m *Menu) benchKey(key string) tea.Cmd {
	switch key {
	case "up", "k":
		m.moveBench(-1)
	case "down", "j":
		m.moveBench(1)
	case "pgup":
		m.moveBench(-10)
	case "pgdown":
		m.moveBench(10)
	case "home":
		m.benchCursor = 0
	case "end", "G":
		m.benchCursor = maxInt(0, len(m.benchRows)-1)
	case "r":
		return m.runBench()
	case "g":
		m.promptInput("Benchmark scope", "Group name (empty = all groups)", m.benchGroup, false, func(m *Menu, value string) tea.Cmd {
			m.benchGroup = strings.TrimSpace(value)
			return nil
		})
	case "s":
		m.sortBenchRows()
	case "enter", "a":
		row, ok := m.selectedBench()
		if !ok {
			return nil
		}
		id := app.ConnectionID(row.Group, row.Remark)
		return m.runAction("Select", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
			return svc.SetActive(ctx, id)
		})
	}
	return nil
}

// sortBenchRows orders by latency, keeping failed links last.
func (m *Menu) sortBenchRows() {
	m.benchSorted = !m.benchSorted
	if !m.benchSorted {
		m.benchRows = append([]bench.Row(nil), m.benchReport.Rows...)
		return
	}
	sort.SliceStable(m.benchRows, func(i, j int) bool {
		a, b := m.benchRows[i], m.benchRows[j]
		if a.Passed != b.Passed {
			return a.Passed
		}
		return a.Latency < b.Latency
	})
	m.benchCursor, m.benchOffset = 0, 0
}

func (m *Menu) benchView(h int) string {
	w := m.contentWidth()
	scope := m.benchGroup
	if scope == "" {
		scope = "all groups"
	}
	head := " " + styleMuted.Render("scope: ") + scope
	if m.benchSorted {
		head += styleMuted.Render("   sorted by latency")
	}
	if m.busy == "Benchmarking connections" {
		head += styleMuted.Render("   running…")
	}
	head += styleMuted.Render(fmt.Sprintf("   %d link(s)", len(m.benchRows)))
	rows := []string{"", head}
	if m.benchErr != "" {
		rows = append(rows, " "+styleErr.Render(truncatePlain(m.benchErr, w-2)))
	}
	if len(m.benchRows) == 0 {
		rows = append(rows, "")
		for _, line := range wrapPlain("Press r to benchmark the stored links. Each link starts on a temporary loopback port and is judged by a real HTTPS request through it.", maxInt(8, w-1)) {
			rows = append(rows, " "+styleMuted.Render(line))
		}
		rows = append(rows, "")
		for _, line := range wrapPlain("Press g first to limit the run to one group.", maxInt(8, w-1)) {
			rows = append(rows, " "+styleMuted.Render(line))
		}
		return m.layoutRows(rows, h)
	}

	bestGroup, bestRemark := "", ""
	if m.benchReport.Best != nil {
		bestGroup, bestRemark = m.benchReport.Best.Group, m.benchReport.Best.Remark
	}
	compact := w < 100
	header := "    " + padTo("CONNECTION", 28) + " " + padTo("PROTO", 8) + " " +
		padTo("ADDRESS", 24) + " " + padTo("PORT", 5) + " " +
		padTo("LATENCY", 8) + " " + padTo("HTTPS", 5) + "RESULT"
	if compact {
		header = "    " + padTo("CONNECTION", maxInt(14, w-30)) + " " + padTo("LATENCY", 8) + " " + padTo("HTTPS", 5) + "RESULT"
	}
	rows = append(rows, " "+styleMuted.Render(clipLine(header, w-1)))

	visible := h - len(rows) - 4
	if visible < 3 {
		visible = 3
	}
	if m.benchCursor < m.benchOffset {
		m.benchOffset = m.benchCursor
	}
	if m.benchCursor >= m.benchOffset+visible {
		m.benchOffset = m.benchCursor - visible + 1
	}
	if m.benchOffset < 0 {
		m.benchOffset = 0
	}
	end := minInt(len(m.benchRows), m.benchOffset+visible)
	for i := m.benchOffset; i < end; i++ {
		rows = append(rows, m.benchRowLine(i, m.benchRows[i], bestGroup, bestRemark, compact, w))
	}
	if end < len(m.benchRows) {
		rows = append(rows, " "+styleMuted.Render(fmt.Sprintf("… %d more", len(m.benchRows)-end)))
	}

	rows = append(rows, "")
	if best := m.benchReport.Best; best != nil {
		line := " " + styleOK.Render("Best: ") +
			fmt.Sprintf("%s/%s  %s:%d  %dms", best.Group, best.Remark, best.Address, best.Port, best.Latency)
		rows = append(rows, clipLine(line, w))
	}
	if m.benchReport.NoHTTPS {
		rows = append(rows, " "+styleWarn.Render("No HTTPS-capable link: the fastest HTTP link was chosen."))
	}
	if len(m.benchReport.Skipped) > 0 {
		rows = append(rows, " "+styleWarn.Render(fmt.Sprintf(
			"%d faster link(s) skipped because they cannot carry HTTPS.", len(m.benchReport.Skipped))))
	}
	rows = append(rows, " "+styleMuted.Render("enter/a select  r rerun  g scope  s sort"))
	return m.layoutRows(rows, h)
}

func (m *Menu) benchRowLine(idx int, r bench.Row, bestGroup, bestRemark string, compact bool, w int) string {
	marker := "  "
	if r.Group == bestGroup && r.Remark == bestRemark {
		marker = styleOK.Render("★ ")
	}
	conn := r.Remark
	if r.Group != "default" {
		conn = r.Group + "/" + r.Remark
	}
	https := "—"
	switch {
	case !r.Passed:
	case r.HTTPS:
		https = "✓"
	default:
		https = "✗"
	}
	latency, result := fmt.Sprintf("%dms", r.Latency), "OK"
	if !r.Passed {
		latency, result = "timeout", "FAIL"
	}

	var line string
	if compact {
		line = marker + padTo(truncatePlain(conn, maxInt(14, w-30)), maxInt(14, w-30)) + " " +
			padTo(latency, 8) + " " + padTo(https, 5) + result
	} else {
		line = marker + padTo(truncatePlain(conn, 28), 28) + " " +
			padTo(strings.ToUpper(shortBenchProto(r.Protocol)), 8) + " " +
			padTo(truncatePlain(r.Address, 24), 24) + " " +
			padTo(fmt.Sprintf("%d", r.Port), 5) + " " +
			padTo(latency, 8) + " " + padTo(https, 5) + result
	}
	if idx != m.benchCursor {
		return " " + line
	}
	return styleActive.Render(" " + padTo(line, w-2) + " ")
}

func shortBenchProto(p string) string {
	switch strings.ToLower(p) {
	case "vless":
		return "vless"
	case "vmess":
		return "vmess"
	case "trojan":
		return "trojan"
	case "shadowsocks":
		return "ss"
	case "wireguard":
		return "wg"
	default:
		return p
	}
}
