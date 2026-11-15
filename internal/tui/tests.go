package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/liberoute/bypath/internal/app"
)

// Tests mirror the panel: relay and latency first, bounded speed only on a
// connection that already has a proven path. Every row carries the evidence
// that produced it; nothing is ranked without L1+L2.

const (
	testTabRun = iota
	testTabResults
	testTabCompare
)

type testState struct {
	tab     int
	kind    string // latency | speed
	scope   string // all | group | link
	group   string // legacy bucket for the group scope
	link    string // legacy connection id for the link scope
	include bool   // include hidden connections in the run

	job         *app.TestJob
	jobErr      string
	jobGen      int
	jobTerminal bool

	budget    *app.TestBudget
	budgetReq app.TestRequest

	results        []app.TestResult
	resultsErr     string
	resultsLoaded  bool
	resultsLoading bool
	resultsGen     int

	cursor      int
	offset      int
	connFilter  string // connection id ("" = all)
	kindFilter  string // "" | latency | speed
	compareKind string // latency | speed
	compareCur  int
	compareOff  int
}

func (m *Menu) testKind() string {
	if m.tests.kind == "" {
		return "latency"
	}
	return m.tests.kind
}

func (m *Menu) testScope() string {
	if m.tests.scope == "" {
		return "all"
	}
	return m.tests.scope
}

func (m *Menu) compareKind() string {
	if m.tests.compareKind == "" {
		return m.testKind()
	}
	return m.tests.compareKind
}

func (m *Menu) testRunning() bool {
	job := m.tests.job
	if job == nil {
		return false
	}
	return job.State == "queued" || job.State == "running"
}

// testSummary is the Overview line. It only claims what has actually been
// measured: the latest result per connection, and how many of those carry the
// L1+L2 proof that alone allows ranking.
func (m *Menu) testSummary() string {
	if !m.tests.resultsLoaded {
		if m.testRunning() {
			return styleWarn.Render("a test job is running")
		}
		return styleMuted.Render("no results loaded — press 3 to run or review")
	}
	latest := map[string]app.TestResult{}
	results := append([]app.TestResult(nil), m.tests.results...)
	app.InvalidateSupersededResults(results)
	for _, res := range results {
		cur, ok := latest[res.ConnectionID]
		if !ok || app.TestResultAtLeastAsNew(res, cur) {
			latest[res.ConnectionID] = res
		}
	}
	if len(latest) == 0 {
		return styleMuted.Render("no results yet — run a relay test")
	}
	proven := 0
	for _, res := range latest {
		if app.VerifiedTestResult(res) {
			proven++
		}
	}
	out := fmt.Sprintf("%d connection(s) tested · %d proven", len(latest), proven)
	if proven < len(latest) {
		out += " (only proven paths are ranked)"
	}
	return out
}

// --- messages and loading ---

type testJobMsg struct {
	gen int
	job app.TestJob
	err error
}

type testResultsMsg struct {
	gen  int
	list []app.TestResult
	err  error
}

type budgetMsg struct {
	req    app.TestRequest
	budget app.TestBudget
	err    error
}

func (m *Menu) loadTestResults() tea.Cmd {
	if m.svc == nil {
		return nil
	}
	m.tests.resultsGen++
	gen := m.tests.resultsGen
	m.tests.resultsLoading = true
	svc := m.svc
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
		defer cancel()
		conns, err := svc.ListConnections(ctx, app.ConnectionFilter{IncludeHidden: true})
		if err != nil {
			return testResultsMsg{gen: gen, err: err}
		}
		seen := map[string]bool{}
		var out []app.TestResult
		var firstErr error
		for _, c := range conns {
			id := c.StableID
			if id == "" {
				id = c.ID
			}
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			list, err := svc.TestResults(ctx, id)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			out = append(out, list...)
		}
		if firstErr != nil && len(out) == 0 {
			return testResultsMsg{gen: gen, err: firstErr}
		}
		return testResultsMsg{gen: gen, list: out}
	}
}

func (m *Menu) handleTestResults(msg testResultsMsg) tea.Cmd {
	if msg.gen != m.tests.resultsGen {
		return nil
	}
	m.tests.resultsLoading = false
	m.tests.resultsLoaded = true
	if msg.err != nil {
		m.tests.resultsErr = friendlyError(msg.err)
		return nil
	}
	m.tests.resultsErr = ""
	m.tests.results = msg.list
	m.clampTestCursor()
	return nil
}

func (m *Menu) loadTestJob() tea.Cmd {
	if m.svc == nil || m.tests.job == nil {
		return nil
	}
	svc := m.svc
	id := m.tests.job.ID
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
		defer cancel()
		job, err := svc.GetTestJob(ctx, id)
		return testJobMsg{gen: 0, job: job, err: err}
	}
}

func (m *Menu) handleTestJob(msg testJobMsg) tea.Cmd {
	m.busy = ""
	if msg.err != nil {
		m.tests.jobErr = friendlyError(msg.err)
		m.setNotice(true, "Test job: %s", m.tests.jobErr)
		return nil
	}
	m.tests.jobErr = ""
	m.tests.job = &msg.job
	terminal := msg.job.State != "queued" && msg.job.State != "running"
	if terminal && !m.tests.jobTerminal {
		m.tests.jobTerminal = true
		switch msg.job.State {
		case "done":
			m.setNotice(false, "Test finished.")
		case "cancelled":
			m.setNotice(false, "Test cancelled.")
		default:
			m.setNotice(true, "Test failed: %s", orDash(msg.job.Error))
		}
		return m.loadTestResults()
	}
	return nil
}

func (m *Menu) testRequest() app.TestRequest {
	scope := app.TestScope{Kind: m.testScope()}
	switch scope.Kind {
	case "group":
		scope.Group = m.tests.group
	case "link":
		scope.ConnectionID = m.tests.link
	}
	return app.TestRequest{Kind: m.testKind(), Scope: scope, IncludeHidden: m.tests.include}
}

func (m *Menu) startTest(req app.TestRequest) tea.Cmd {
	if m.svc == nil || m.busy != "" {
		return nil
	}
	if m.testRunning() {
		m.setNotice(true, "A test job is already running. Cancel it or wait for it to finish.")
		return nil
	}
	label := "Relay test"
	if req.Kind == "speed" {
		label = "Speed test"
	}
	m.tests.jobTerminal = false
	m.busy = "Starting " + strings.ToLower(label)
	m.busySince = time.Now()
	svc := m.svc
	return tea.Batch(func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		job, err := svc.StartTestJob(ctx, req)
		return testJobMsg{job: job, err: err}
	}, spinnerTick())
}

// reviewBudget asks the gateway what a speed run would cost before it starts.
// The number is counted payload, not the provider's billing figure.
func (m *Menu) reviewBudget(req app.TestRequest) tea.Cmd {
	if m.svc == nil || m.busy != "" {
		return nil
	}
	m.busy = "Checking the speed budget"
	m.busySince = time.Now()
	svc := m.svc
	return tea.Batch(func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		budget, err := svc.TestBudget(ctx, req)
		return budgetMsg{req: req, budget: budget, err: err}
	}, spinnerTick())
}

func (m *Menu) handleBudget(msg budgetMsg) tea.Cmd {
	m.busy = ""
	if msg.err != nil {
		m.setNotice(true, "Budget check failed: %s", friendlyError(msg.err))
		return nil
	}
	m.tests.budget = &msg.budget
	m.tests.budgetReq = msg.req
	b := msg.budget
	detail := fmt.Sprintf("Target: %s\nLinks: %d · per link %d MB · per batch %d MB\nWorst case: %d MB · used this month: %d MB",
		orDash(b.TargetURL), b.Links, b.PerLinkMB, b.PerBatchMB, b.WorstCaseMB, b.MonthUsedMB)
	if b.MonthlyCapMB > 0 {
		detail += fmt.Sprintf(" of %d MB", b.MonthlyCapMB)
	}
	detail += "\n" + b.CheckNote
	detail += "\n\nSpeed runs are serial; upload is not enabled in this release."
	m.confirmChoice("Review the speed budget", detail,
		[]choice{{label: "Start bounded speed test"}, {label: "Cancel"}},
		func(m *Menu, idx int) tea.Cmd {
			if idx != 0 {
				return nil
			}
			return m.startTest(msg.req)
		})
	return nil
}

// --- view ---

func (m *Menu) testsView(h int) string {
	w := m.contentWidth()
	tabNames := []string{"Run", "Results", "Compare"}
	tabLine := " " + styleMuted.Render("Tests · ")
	for i, name := range tabNames {
		if i == m.tests.tab {
			tabLine += styleActive.Render(" " + name + " ")
		} else {
			tabLine += " " + name + " "
		}
	}
	tabLine += styleMuted.Render("   t cycles")
	rows := []string{"", tabLine}
	switch m.tests.tab {
	case testTabResults:
		rows = append(rows, m.testResultsRows(w)...)
	case testTabCompare:
		rows = append(rows, m.testCompareRows(w)...)
	default:
		rows = append(rows, m.testRunRows(w)...)
	}
	return m.layoutRows(rows, h)
}

func (m *Menu) testRunRows(w int) []string {
	var rows []string
	kind := m.testKind()
	kindName := "relay and latency"
	if kind == "speed" {
		kindName = "download speed (bounded)"
	}
	rows = append(rows, " "+styleLabel.Render("Kind   ")+kindName+styleMuted.Render("   K to switch"))
	scope := m.testScope()
	scopeLine := " " + styleLabel.Render("Scope  ") + scope
	switch scope {
	case "group":
		scopeLine += styleMuted.Render(" → ") + orDash(m.tests.group)
	case "link":
		scopeLine += styleMuted.Render(" → ") + m.linkLabel(m.tests.link)
	}
	scopeLine += styleMuted.Render("   s cycles · g group · l link")
	rows = append(rows, scopeLine)
	include := "no"
	if m.tests.include {
		include = "yes"
	}
	rows = append(rows, " "+styleLabel.Render("Hidden ")+include+styleMuted.Render("   i toggles"))
	rows = append(rows, "")

	job := m.tests.job
	if job == nil {
		if m.tests.jobErr != "" {
			rows = append(rows, m.indentedLines(m.tests.jobErr, 1, styleErr)...)
		}
		rows = append(rows, mutedLines("No job yet. Enter starts a measurement; relay results carry L1+L2 evidence, and a speed run needs one first.", w)...)
		return rows
	}
	stateStyle := styleMuted
	switch job.State {
	case "done":
		stateStyle = styleOK
	case "failed":
		stateStyle = styleErr
	case "running", "queued":
		stateStyle = styleWarn
	}
	head := " " + stateStyle.Render(strings.ToUpper(orDash(job.State)))
	head += styleMuted.Render(fmt.Sprintf("   %d/%d", job.Completed, job.Total))
	if job.Stage != "" {
		head += styleMuted.Render(" · " + job.Stage)
	}
	if job.Error != "" {
		head += styleErr.Render(" · " + job.Error)
	}
	rows = append(rows, head)
	rows = append(rows, " "+styleMuted.Render(truncatePlain("job "+job.ID, w-2)))
	rows = append(rows, "")
	if len(job.Results) == 0 {
		rows = append(rows, " "+styleMuted.Render("Results appear as each connection finishes."))
	}
	limit := 8
	for i, res := range job.Results {
		if i >= limit {
			rows = append(rows, " "+styleMuted.Render(fmt.Sprintf("… %d more", len(job.Results)-i)))
			break
		}
		rows = append(rows, m.testRow(res, w))
	}
	if m.testRunning() {
		rows = append(rows, "", " "+styleWarn.Render("A job is running.")+styleMuted.Render(" c cancels it."))
	}
	return rows
}

func (m *Menu) linkLabel(id string) string {
	for _, c := range m.conns {
		if c.ID == id {
			return connectionName(c)
		}
	}
	return orDash(id)
}

func (m *Menu) testRow(res app.TestResult, w int) string {
	name := truncatePlain(orDash(res.Remark), maxInt(10, w/3))
	verdict, vstyle := resultVerdict(res)
	evidence := truncatePlain(evidenceOf(res), maxInt(8, w-lipgloss.Width(name)-lipgloss.Width(verdict)-6))
	return " " + name + "  " + vstyle.Render(padTo(verdict, 12)) + evidence
}

func (m *Menu) filteredResults() []app.TestResult {
	results := append([]app.TestResult(nil), m.tests.results...)
	app.InvalidateSupersededResults(results)
	out := make([]app.TestResult, 0, len(results))
	for _, res := range results {
		if m.tests.connFilter != "" && res.ConnectionID != m.tests.connFilter {
			continue
		}
		if m.tests.kindFilter != "" && res.Kind != m.tests.kindFilter {
			continue
		}
		out = append(out, res)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TestedAt > out[j].TestedAt })
	return out
}

func (m *Menu) testResultsRows(w int) []string {
	kind := orDash(m.tests.kindFilter)
	conn := "all"
	if m.tests.connFilter != "" {
		conn = m.linkLabel(m.tests.connFilter)
	}
	rows := []string{" " + styleMuted.Render(fmt.Sprintf("filter: %s · kind: %s · %d result(s)", conn, kind, len(m.filteredResults())))}
	if m.tests.resultsErr != "" {
		rows = append(rows, m.indentedLines(m.tests.resultsErr, 1, styleErr)...)
	}
	if m.tests.resultsLoading {
		rows = append(rows, " "+styleMuted.Render("loading…"))
	}
	list := m.filteredResults()
	if len(list) == 0 {
		rows = append(rows, "")
		if m.tests.kindFilter == "speed" {
			rows = append(rows, mutedLines("No speed result matches this filter. A speed run is bounded and only produces a result on a connection that already has a proven path.", w)...)
		} else {
			rows = append(rows, mutedLines("No result matches. Run a relay test first; results are stored on the gateway and survive a reload.", w)...)
		}
		return rows
	}
	visible := m.testVisible()
	if m.tests.cursor < m.tests.offset {
		m.tests.offset = m.tests.cursor
	}
	if m.tests.cursor >= m.tests.offset+visible {
		m.tests.offset = m.tests.cursor - visible + 1
	}
	end := minInt(len(list), m.tests.offset+visible)
	for i := m.tests.offset; i < end; i++ {
		res := list[i]
		line := m.testResultLine(res, w)
		if i == m.tests.cursor {
			rows = append(rows, styleActive.Render(" "+padTo(line, w-2)+" "))
			continue
		}
		rows = append(rows, " "+line)
	}
	if end < len(list) {
		rows = append(rows, " "+styleMuted.Render(fmt.Sprintf("… %d more", len(list)-end)))
	}
	rows = append(rows, " "+styleMuted.Render("enter evidence · K kind · g connection · c clear · r reload"))
	return rows
}

// evidenceWithoutAge is the results column: the row already carries the age in
// its own trailing column, so repeating it inside the evidence would waste the
// width that the reason needs.
func evidenceWithoutAge(res app.TestResult) string {
	if !app.VerifiedTestResult(res) {
		return evidenceOf(res)
	}
	if res.Kind == "speed" && res.MBps > 0 {
		return fmt.Sprintf("%.1f Mbps", res.MBps)
	}
	if res.P50MS > 0 {
		return fmt.Sprintf("%d ms", res.P50MS)
	}
	return ""
}

func (m *Menu) testResultLine(res app.TestResult, w int) string {
	verdict, vstyle := resultVerdict(res)
	kind := padTo(strings.ToUpper(orDash(res.Kind)), 8)
	verdictCell := vstyle.Render(padTo(verdict, 12))
	age := timeAgo(res.TestedAt)
	tail := ""
	if age != "" {
		tail = " " + age
	}
	// One column is spent on the leading space and one more is reserved for the
	// highlighted row's right padding, so the age tail is never clipped.
	budget := w - 2
	maxName := maxInt(8, budget-23-lipgloss.Width(tail)-4)
	nameW := clampInt(budget/4, 8, maxName)
	name := truncatePlain(orDash(res.Remark), nameW)
	avail := budget - lipgloss.Width(name) - 23 - lipgloss.Width(tail)
	if avail < 4 {
		name = truncatePlain(orDash(res.Remark), maxInt(4, budget-22-lipgloss.Width(tail)))
		return name + " " + kind + " " + verdictCell + tail
	}
	evidence := padTo(truncatePlain(evidenceWithoutAge(res), avail), avail)
	return name + " " + kind + " " + verdictCell + " " + evidence + tail
}

func (m *Menu) testVisible() int {
	return maxInt(3, m.bodyHeight()-7)
}

// compareEntry is one row of the Compare list. heading marks the first row of
// the ranked or unranked section, so one scrolling window can render both.
type compareEntry struct {
	res     app.TestResult
	heading string
	rank    int
}

// compareEntries returns the latest result per connection for the kind, proven
// rows first (sorted by the kind's metric), then the unranked ones.
func (m *Menu) compareEntries() []compareEntry {
	kind := m.compareKind()
	latest := map[string]app.TestResult{}
	results := append([]app.TestResult(nil), m.tests.results...)
	app.InvalidateSupersededResults(results)
	for _, res := range results {
		if res.Kind != kind {
			continue
		}
		cur, ok := latest[res.ConnectionID]
		if !ok || app.TestResultAtLeastAsNew(res, cur) {
			latest[res.ConnectionID] = res
		}
	}
	var proven, rest []app.TestResult
	for _, res := range latest {
		if app.VerifiedTestResult(res) {
			proven = append(proven, res)
		} else {
			rest = append(rest, res)
		}
	}
	if kind == "speed" {
		sort.SliceStable(proven, func(i, j int) bool { return proven[i].MBps > proven[j].MBps })
	} else {
		sort.SliceStable(proven, func(i, j int) bool { return latencyMS(proven[i]) < latencyMS(proven[j]) })
	}
	sort.SliceStable(rest, func(i, j int) bool { return rest[i].TestedAt > rest[j].TestedAt })
	out := make([]compareEntry, 0, len(proven)+len(rest))
	for i, res := range proven {
		entry := compareEntry{res: res, rank: i + 1}
		if i == 0 {
			entry.heading = "Ranked (proven path)"
		}
		out = append(out, entry)
	}
	for i, res := range rest {
		entry := compareEntry{res: res, rank: i + 1}
		if i == 0 {
			entry.heading = "Not ranked"
		}
		out = append(out, entry)
	}
	return out
}

func (m *Menu) testCompareRows(w int) []string {
	kind := m.compareKind()
	entries := m.compareEntries()
	proven := len(entries)
	rest := 0
	for i, entry := range entries {
		if entry.heading == "Not ranked" {
			proven = i
			rest = len(entries) - i
			break
		}
	}
	rows := []string{" " + styleMuted.Render(fmt.Sprintf("%s · %d proven ranked · %d not ranked", kind, proven, rest))}
	if len(entries) == 0 {
		text := "Run a relay test across the connections you care about."
		if kind == "speed" {
			text = "A speed result requires a proven relay result for the same connection."
		}
		rows = append(rows, "")
		return append(rows, mutedLines(text, w)...)
	}
	// The cursor walks ranked rows first; the window scrolls over the whole list
	// so a long unranked tail stays reachable.
	m.tests.compareCur = clampInt(m.tests.compareCur, 0, len(entries)-1)
	visible := m.testVisible()
	if m.tests.compareCur < m.tests.compareOff {
		m.tests.compareOff = m.tests.compareCur
	}
	if m.tests.compareCur >= m.tests.compareOff+visible {
		m.tests.compareOff = m.tests.compareCur - visible + 1
	}
	if m.tests.compareOff < 0 {
		m.tests.compareOff = 0
	}
	rows = append(rows, "")
	if m.tests.compareOff > 0 {
		rows = append(rows, " "+styleMuted.Render(fmt.Sprintf("… %d above", m.tests.compareOff)))
	}
	end := minInt(len(entries), m.tests.compareOff+visible)
	for i := m.tests.compareOff; i < end; i++ {
		entry := entries[i]
		if entry.heading != "" {
			rows = append(rows, " "+styleTitle.Render(entry.heading))
			if entry.heading == "Not ranked" {
				rows = append(rows, mutedLines("An inconclusive result does not mean the link is bad; its path was not proven, so it is not used for ranking.", w)...)
			}
		}
		rows = append(rows, m.compareRow(i, entry, w))
	}
	if end < len(entries) {
		rows = append(rows, " "+styleMuted.Render(fmt.Sprintf("… %d more", len(entries)-end)))
	}
	rows = append(rows, " "+styleMuted.Render("↑/↓ move · enter evidence · K kind · r reload"))
	return rows
}

func (m *Menu) compareRow(cursor int, entry compareEntry, w int) string {
	res := entry.res
	verdict, vstyle := resultVerdict(res)
	value := ""
	if res.Status == "ok" {
		if res.Kind == "speed" {
			value = fmt.Sprintf("%.1f Mbps", res.MBps)
		} else {
			value = fmt.Sprintf("p50 %s · p90 %s", fmtMs(latencyMS(res)), fmtMs(res.P90MS))
		}
	}
	if value == "" {
		value = evidenceOf(res)
	}
	// One column is spent on the leading space and one more is reserved for the
	// highlighted row's right padding, so neither the name nor the value is
	// silently clipped at the terminal edge.
	budget := w - 2
	rank := fmt.Sprintf("%2d. ", entry.rank)
	verdictCell := vstyle.Render(padTo(verdict, 12))
	// The metric is the point of the comparison; drop the protocol label before
	// dropping the value on a narrow terminal.
	withProto := budget >= 46
	fixed := lipgloss.Width(rank) + 2 + lipgloss.Width(verdictCell) + 2
	if withProto {
		fixed += 8 + 2
	}
	nameW := maxInt(8, budget/4)
	if nameW > budget-fixed-8 {
		nameW = maxInt(8, budget-fixed-8)
	}
	name := padTo(truncatePlain(orDash(res.Remark), nameW), nameW)
	line := rank + name
	if withProto {
		line += "  " + padTo(strings.ToUpper(orDash(res.Protocol)), 8)
	}
	line += "  " + verdictCell
	valueW := budget - lipgloss.Width(line) - 2
	if valueW >= 4 {
		line += "  " + truncatePlain(value, valueW)
	}
	if cursor == m.tests.compareCur {
		return styleActive.Render(" " + padTo(line, w-2) + " ")
	}
	return " " + line
}

func (m *Menu) clampTestCursor() {
	m.tests.cursor = clampInt(m.tests.cursor, 0, maxInt(0, len(m.filteredResults())-1))
	m.tests.compareCur = clampInt(m.tests.compareCur, 0, maxInt(0, len(m.compareEntries())-1))
}

// --- keys ---

func (m *Menu) testsKey(k tea.KeyMsg, key string) tea.Cmd {
	switch key {
	case "t":
		m.tests.tab = (m.tests.tab + 1) % 3
		m.tests.cursor, m.tests.offset = 0, 0
		m.tests.compareCur, m.tests.compareOff = 0, 0
		return nil
	case "K":
		if m.tests.tab == testTabCompare {
			if m.compareKind() == "latency" {
				m.tests.compareKind = "speed"
			} else {
				m.tests.compareKind = "latency"
			}
			m.tests.compareCur, m.tests.compareOff = 0, 0
			return nil
		}
		if m.tests.tab == testTabResults {
			switch m.tests.kindFilter {
			case "":
				m.tests.kindFilter = "latency"
			case "latency":
				m.tests.kindFilter = "speed"
			default:
				m.tests.kindFilter = ""
			}
			m.tests.cursor, m.tests.offset = 0, 0
			return nil
		}
		if m.testKind() == "latency" {
			m.tests.kind = "speed"
		} else {
			m.tests.kind = "latency"
		}
		return nil
	}
	switch m.tests.tab {
	case testTabResults:
		return m.testResultsKey(key)
	case testTabCompare:
		last := maxInt(0, len(m.compareEntries())-1)
		switch key {
		case "up", "k":
			m.tests.compareCur = maxInt(0, m.tests.compareCur-1)
		case "down", "j":
			m.tests.compareCur = minInt(last, m.tests.compareCur+1)
		case "pgup":
			m.tests.compareCur = maxInt(0, m.tests.compareCur-10)
		case "pgdown":
			m.tests.compareCur = minInt(last, m.tests.compareCur+10)
		case "home":
			m.tests.compareCur = 0
		case "end":
			m.tests.compareCur = last
		case "enter":
			if res, ok := m.compareResultAt(m.tests.compareCur); ok {
				m.showInfo("Test evidence", testEvidenceText(res))
			}
		case "r":
			return tea.Batch(m.loadConnections(), m.loadTestResults())
		}
		return nil
	}
	return m.testRunKey(key)
}

func (m *Menu) compareResultAt(idx int) (app.TestResult, bool) {
	entries := m.compareEntries()
	if idx < 0 || idx >= len(entries) {
		return app.TestResult{}, false
	}
	return entries[idx].res, true
}

func (m *Menu) testResultsKey(key string) tea.Cmd {
	list := m.filteredResults()
	switch key {
	case "up":
		m.tests.cursor = maxInt(0, m.tests.cursor-1)
	case "down":
		m.tests.cursor = minInt(maxInt(0, len(list)-1), m.tests.cursor+1)
	case "pgup":
		m.tests.cursor = maxInt(0, m.tests.cursor-10)
	case "pgdown":
		m.tests.cursor = minInt(maxInt(0, len(list)-1), m.tests.cursor+10)
	case "home":
		m.tests.cursor = 0
	case "end":
		m.tests.cursor = maxInt(0, len(list)-1)
	case "enter":
		if m.tests.cursor < len(list) {
			m.showInfo("Test evidence", testEvidenceText(list[m.tests.cursor]))
		}
	case "g":
		m.pickResultConnection()
	case "c":
		m.tests.connFilter, m.tests.kindFilter = "", ""
		m.tests.cursor, m.tests.offset = 0, 0
	case "r":
		return tea.Batch(m.loadConnections(), m.loadTestResults())
	}
	return nil
}

func (m *Menu) pickResultConnection() {
	seen := map[string]bool{}
	choices := []choice{{label: "All connections"}}
	ids := []string{""}
	for _, res := range m.tests.results {
		if res.ConnectionID == "" || seen[res.ConnectionID] {
			continue
		}
		seen[res.ConnectionID] = true
		label := orDash(res.Remark)
		choices = append(choices, choice{label: label})
		ids = append(ids, res.ConnectionID)
	}
	choices = append(choices, choice{label: "Cancel"})
	m.confirmChoice("Filter results by connection", "Only results for the chosen connection are listed.", choices, func(m *Menu, idx int) tea.Cmd {
		if idx >= len(ids) {
			return nil
		}
		m.tests.connFilter = ids[idx]
		m.tests.cursor, m.tests.offset = 0, 0
		return nil
	})
}

func (m *Menu) testRunKey(key string) tea.Cmd {
	switch key {
	case "s":
		switch m.testScope() {
		case "all":
			m.tests.scope = "group"
			if m.tests.group == "" {
				m.tests.group = m.firstGroup()
			}
		case "group":
			m.tests.scope = "link"
			if m.tests.link == "" {
				m.pickTestLink()
			}
		default:
			m.tests.scope = "all"
		}
	case "g":
		m.tests.scope = "group"
		m.pickTestGroup()
	case "l":
		m.tests.scope = "link"
		m.pickTestLink()
	case "i":
		m.tests.include = !m.tests.include
	case "enter":
		req := m.testRequest()
		if req.Kind == "speed" {
			return m.reviewBudget(req)
		}
		return m.startTest(req)
	case "c":
		if m.tests.job == nil || !m.testRunning() {
			return nil
		}
		id := m.tests.job.ID
		return m.runAction("Cancel test", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
			if err := svc.CancelTestJob(ctx, id); err != nil {
				return app.ActionResult{}, err
			}
			return app.ActionResult{Message: "Test job cancelled."}, nil
		})
	case "r":
		cmds := []tea.Cmd{m.loadConnections(), m.loadTestResults()}
		if m.testRunning() {
			cmds = append(cmds, m.loadTestJob())
		}
		return tea.Batch(cmds...)
	}
	return nil
}

func (m *Menu) firstGroup() string {
	for _, c := range m.conns {
		if c.Group != "" {
			return c.Group
		}
	}
	return ""
}

func (m *Menu) pickTestGroup() {
	seen := map[string]bool{}
	var choices []choice
	var names []string
	for _, c := range m.conns {
		if c.Group == "" || seen[c.Group] {
			continue
		}
		seen[c.Group] = true
		choices = append(choices, choice{label: c.Group})
		names = append(names, c.Group)
	}
	if len(choices) == 0 {
		m.setNotice(true, "There are no groups to test.")
		return
	}
	choices = append(choices, choice{label: "Cancel"})
	m.confirmChoice("Test one group", "Every connection in the group is measured; hidden ones only when included.", choices, func(m *Menu, idx int) tea.Cmd {
		if idx < len(names) {
			m.tests.group = names[idx]
			m.tests.scope = "group"
		}
		return nil
	})
}

func (m *Menu) pickTestLink() {
	choices := make([]choice, 0, len(m.conns)+1)
	ids := make([]string, 0, len(m.conns))
	for _, c := range m.conns {
		choices = append(choices, choice{label: connectionName(c)})
		ids = append(ids, c.ID)
	}
	if len(choices) == 0 {
		m.setNotice(true, "There are no connections to test.")
		return
	}
	choices = append(choices, choice{label: "Cancel"})
	m.confirmChoice("Test one connection", "The connection is measured in an isolated test tunnel, not by switching the serving link.", choices, func(m *Menu, idx int) tea.Cmd {
		if idx < len(ids) {
			m.tests.link = ids[idx]
			m.tests.scope = "link"
		}
		return nil
	})
}

// --- result helpers ---

func latencyMS(res app.TestResult) int64 {
	if res.P50MS > 0 {
		return res.P50MS
	}
	return res.LatencyMS
}

func fmtMs(ms int64) string {
	if ms <= 0 {
		return "—"
	}
	return fmt.Sprintf("%d ms", ms)
}

func resultVerdict(res app.TestResult) (string, lipgloss.Style) {
	if res.Superseded {
		return "SUPERSEDED", styleMuted
	}
	if res.Status == "ok" && !app.VerifiedTestResult(res) && !res.Stale {
		return "INCONCLUSIVE", styleWarn
	}
	if res.Stale {
		return "STALE", styleWarn
	}
	switch res.Status {
	case "ok":
		return "HEALTHY", styleOK
	case "inconclusive":
		return "INCONCLUSIVE", styleWarn
	case "failed":
		return "FAILED", styleErr
	case "unavailable":
		return "UNAVAILABLE", styleWarn
	case "skipped":
		return "NOT RUN", styleMuted
	case "cancelled":
		return "CANCELLED", styleMuted
	}
	return "UNTESTED", styleMuted
}

var testReasonText = map[string]string{
	"CONFIG_NOT_ISOLATED":       "the test-tunnel configuration is not isolated",
	"PATH_DIRECT_TARGET":        "the destination would go DIRECT, not through the tunnel",
	"EXIT_EQUALS_UPLINK":        "traffic left directly instead of through the tunnel",
	"EXIT_EQUALS_SERVING":       "the exit matches the serving connection, so ownership is unproven",
	"EXIT_AMBIGUOUS":            "two identity services disagreed about the exit",
	"EXIT_CHANGED":              "the exit changed during the measurement",
	"EXIT_UNKNOWN":              "the exit identity could not be determined",
	"POLICY_CHANGED":            "the routing policy changed during the measurement",
	"CONTROL_FAILED":            "the DIRECT control failed, so route decisions are not trustworthy",
	"ROUTE_EXPLAIN_UNAVAILABLE": "the routing policy could not be evaluated for a target",
	"ISOLATION_UNVERIFIED":      "isolated-test isolation has not been verified on this host",
	"TARGET_REJECTED":           "the download target was rejected by the security checks",
	"BUDGET_REACHED":            "the traffic budget was reached",
	"NO_PROVEN_RESULT":          "a proven relay result is required before a speed test",
}

func reasonText(code string) string {
	if code == "" {
		return ""
	}
	if text, ok := testReasonText[code]; ok {
		return text
	}
	return strings.ToLower(strings.ReplaceAll(code, "_", " "))
}

func evidenceOf(res app.TestResult) string {
	if res.Superseded {
		return "a later attempt invalidated this proof"
	}
	if res.Status == "ok" && !app.VerifiedTestResult(res) {
		return "stale or incomplete path proof; not ranked"
	}
	if res.Status == "ok" {
		parts := []string{}
		if res.Kind == "speed" && res.MBps > 0 {
			parts = append(parts, fmt.Sprintf("%.1f Mbps", res.MBps))
		} else if res.P50MS > 0 {
			parts = append(parts, fmt.Sprintf("%d ms", res.P50MS))
		}
		if res.TestedAt != "" {
			parts = append(parts, timeAgo(res.TestedAt))
		}
		return strings.Join(parts, " · ")
	}
	if res.Status == "inconclusive" {
		return reasonText(res.Reason)
	}
	if res.Detail != "" {
		return res.Detail
	}
	if res.Reason != "" {
		return reasonText(res.Reason)
	}
	if res.TestedAt != "" {
		return timeAgo(res.TestedAt)
	}
	return ""
}

func pathKind(res app.TestResult) string {
	if res.Path == nil {
		return ""
	}
	switch res.Path.Kind {
	case "live":
		return "measured on the live tunnel"
	case "isolated":
		return "measured on an isolated test tunnel"
	default:
		return res.Path.Kind
	}
}

func timeAgo(iso string) string {
	if iso == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		return iso
	}
	d := time.Since(t)
	switch {
	case d < 5*time.Second:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%.0f s ago", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%.0f min ago", d.Minutes())
	case d < 48*time.Hour:
		return fmt.Sprintf("%.0f h ago", d.Hours())
	case d < 30*24*time.Hour:
		return fmt.Sprintf("%.0f d ago", d.Hours()/24)
	default:
		return fmt.Sprintf("%.0f mo ago", d.Hours()/24/30)
	}
}

func testEvidenceText(res app.TestResult) string {
	var b strings.Builder
	verdict, _ := resultVerdict(res)
	fmt.Fprintf(&b, "Connection: %s\n", orDash(res.Remark))
	fmt.Fprintf(&b, "Kind:       %s · %s\n", res.Kind, verdict)
	fmt.Fprintf(&b, "Tested:     %s\n", orDash(res.TestedAt))
	if res.Status != "ok" {
		fmt.Fprintf(&b, "Reason:     %s\n", orDash(evidenceOf(res)))
	}
	if res.Kind == "speed" {
		fmt.Fprintf(&b, "Throughput: %.1f Mbps\n", res.MBps)
		fmt.Fprintf(&b, "Target:     %s\n", orDash(res.Target))
		fmt.Fprintf(&b, "Bytes:      %d B counted by Bypath (payload, not link billing)\n", res.Bytes)
	} else {
		fmt.Fprintf(&b, "Median/p90: %s / %s\n", fmtMs(latencyMS(res)), fmtMs(res.P90MS))
	}
	if res.Path != nil {
		fmt.Fprintf(&b, "Path:       %s · %s\n", res.Path.Level, orDash(pathKind(res)))
		fmt.Fprintf(&b, "Exit before/after: %s / %s\n", orDash(res.Path.ExitBefore), orDash(res.Path.ExitAfter))
		fmt.Fprintf(&b, "Uplink:     %s\nServing:    %s\n", orDash(res.Path.UplinkIP), orDash(res.Path.ServingExitIP))
		fmt.Fprintf(&b, "Policy:     %s\n", orDash(res.Path.PolicyRevision))
		if res.Path.NegativeControl != "" {
			fmt.Fprintf(&b, "Control:    %s\n", res.Path.NegativeControl)
		}
		if len(res.Path.Echoes) > 0 {
			var echoes []string
			for _, e := range res.Path.Echoes {
				echoes = append(echoes, e.Service+" → "+e.IP)
			}
			fmt.Fprintf(&b, "Echoes:     %s\n", strings.Join(echoes, " · "))
		}
		if res.Path.Note != "" {
			fmt.Fprintf(&b, "Note:       %s\n", res.Path.Note)
		}
	}
	return b.String()
}
