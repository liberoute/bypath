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
	sortBy      string // "" (last tested) | latency | speed | failures
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
	proven, measured := 0, 0
	for _, res := range latest {
		if app.VerifiedTestResult(res) {
			proven++
			continue
		}
		if res.Status == app.TestStatusMeasured {
			measured++
		}
	}
	out := fmt.Sprintf("%d connection(s) tested · %d verified · %d measured", len(latest), proven, measured)
	if proven+measured < len(latest) {
		out += " (only verified paths are ranked as proven)"
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
	detail := fmt.Sprintf("Target: %s\nLinks: %d · planned %d · skipped by budget %d\nPer link %d MB · per batch %d MB\nWorst case: %d MB · used this month: %d MB",
		orDash(b.TargetURL), b.Links, b.LinksMeasured, b.LinksSkipped, b.PerLinkMB, b.PerBatchMB, b.WorstCaseMB, b.MonthUsedMB)
	if b.MonthlyCapMB > 0 {
		detail += fmt.Sprintf(" of %d MB (remaining %d MB)", b.MonthlyCapMB, b.RemainingMB)
	}
	detail += "\n" + b.CheckNote
	detail += "\n\nSpeed runs are serial; upload is not enabled in this release."
	detail += "\nA speed run needs a recent HTTPS measurement for the connection; exit ownership is not required."
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
		rows = append(rows, mutedLines("No job yet. Enter starts a measurement; relay results carry L1+L2 evidence, and a measured (not necessarily verified) HTTPS result is enough for a bounded speed run.", w)...)
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
	if job.Kind == "speed" && job.PlannedLinks > 0 {
		plan := fmt.Sprintf("plan: %d of %d connections, at most %d MB this batch", job.PlannedLinks, job.Total, job.PlannedBytes>>20)
		if job.BudgetSkipped > 0 {
			plan += fmt.Sprintf(" · %d skipped in the worst case", job.BudgetSkipped)
		}
		rows = append(rows, " "+styleMuted.Render(truncatePlain(plan, w-2)))
	}
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
	sortResults(out, m.tests.sortBy)
	return out
}

// sortResults orders the results list. An unmeasured row sorts after every
// measured row under a metric order, so sorting never promotes a connection
// whose test produced nothing.
func sortResults(list []app.TestResult, mode string) {
	switch mode {
	case "latency":
		sort.SliceStable(list, func(i, j int) bool {
			a, b := latencyMS(list[i]), latencyMS(list[j])
			if (a > 0) != (b > 0) {
				return a > 0
			}
			if a > 0 && a != b {
				return a < b
			}
			return list[i].TestedAt > list[j].TestedAt
		})
	case "speed":
		sort.SliceStable(list, func(i, j int) bool {
			a, b := list[i].MBps, list[j].MBps
			if (a > 0) != (b > 0) {
				return a > 0
			}
			if a > 0 && a != b {
				return a > b
			}
			return list[i].TestedAt > list[j].TestedAt
		})
	case "failures":
		sort.SliceStable(list, func(i, j int) bool {
			ra, rb := failureRank(list[i]), failureRank(list[j])
			if ra != rb {
				return ra < rb
			}
			return list[i].TestedAt > list[j].TestedAt
		})
	default:
		sort.SliceStable(list, func(i, j int) bool { return list[i].TestedAt > list[j].TestedAt })
	}
}

// failureRank puts the rows that need attention first; a skipped row is not a
// failure and stays behind measured rows.
func failureRank(res app.TestResult) int {
	switch res.Status {
	case app.TestStatusFailed:
		return 0
	case app.TestStatusUnavailable:
		return 1
	case app.TestStatusInconclusive:
		return 2
	case app.TestStatusCancelled:
		return 3
	case app.TestStatusSkipped:
		return 4
	case app.TestStatusMeasured:
		return 5
	case app.TestStatusOK:
		return 6
	}
	return 6
}

func sortLabel(mode string) string {
	switch mode {
	case "latency":
		return "latency"
	case "speed":
		return "download speed"
	case "failures":
		return "failures first"
	}
	return "last tested"
}

func (m *Menu) testResultsRows(w int) []string {
	kind := orDash(m.tests.kindFilter)
	conn := "all"
	if m.tests.connFilter != "" {
		conn = m.linkLabel(m.tests.connFilter)
	}
	rows := []string{" " + styleMuted.Render(fmt.Sprintf("filter: %s · kind: %s · sort: %s · %d result(s)",
		conn, kind, sortLabel(m.tests.sortBy), len(m.filteredResults())))}
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
			rows = append(rows, mutedLines("No speed result matches this filter. A speed run is bounded and needs a recent HTTPS measurement for the connection.", w)...)
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
	rows = append(rows, " "+styleMuted.Render("enter evidence · K kind · s sort · g connection · c clear · r reload"))
	return rows
}

// evidenceWithoutAge is the results column: the row already carries the age in
// its own trailing column, so repeating it inside the evidence would waste the
// width that the reason needs.
func evidenceWithoutAge(res app.TestResult) string {
	if res.Superseded {
		return evidenceOf(res)
	}
	if res.Status == "measured" {
		if res.Kind == "speed" && res.MBps > 0 {
			return throughputLine(res) + " · exit unproven"
		}
		if pair := msPair(res); pair != "" {
			return pair + " · exit unproven"
		}
		return "measured; exit unproven"
	}
	if res.Status != "ok" || !app.VerifiedTestResult(res) {
		return evidenceOf(res)
	}
	if res.Kind == "speed" && res.MBps > 0 {
		return throughputLine(res)
	}
	if pair := msPair(res); pair != "" {
		return pair
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

// compareEntries returns the latest result per connection for the kind,
// verified rows first, then operational measurements ranked by the kind's
// metric, then the rows that produced no measurement. Operational results are
// ranked separately so a shared-exit subscription still yields a useful
// latency/speed order without pretending the path was proven.
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
	var verified, operational, rest []app.TestResult
	for _, res := range latest {
		switch {
		case app.VerifiedTestResult(res):
			verified = append(verified, res)
		case res.Status == app.TestStatusMeasured && compareValue(res, kind) > 0:
			operational = append(operational, res)
		default:
			rest = append(rest, res)
		}
	}
	if kind == "speed" {
		sort.SliceStable(verified, func(i, j int) bool { return verified[i].MBps > verified[j].MBps })
		sort.SliceStable(operational, func(i, j int) bool { return operational[i].MBps > operational[j].MBps })
	} else {
		sort.SliceStable(verified, func(i, j int) bool { return latencyMS(verified[i]) < latencyMS(verified[j]) })
		sort.SliceStable(operational, func(i, j int) bool { return latencyMS(operational[i]) < latencyMS(operational[j]) })
	}
	sort.SliceStable(rest, func(i, j int) bool { return rest[i].TestedAt > rest[j].TestedAt })
	out := make([]compareEntry, 0, len(verified)+len(operational)+len(rest))
	add := func(list []app.TestResult, heading string) {
		for i, res := range list {
			entry := compareEntry{res: res, rank: i + 1}
			if i == 0 {
				entry.heading = heading
			}
			out = append(out, entry)
		}
	}
	add(verified, "Verified (ranked)")
	add(operational, "Measured · operational (exit unproven)")
	add(rest, "Not measured")
	return out
}

// compareValue is the ranking metric of a result; zero means the row carries
// no usable number for this kind.
func compareValue(res app.TestResult, kind string) float64 {
	if kind == "speed" {
		return res.MBps
	}
	return float64(latencyMS(res))
}

func (m *Menu) testCompareRows(w int) []string {
	kind := m.compareKind()
	entries := m.compareEntries()
	verified, operational, rest := 0, 0, 0
	section := ""
	for _, entry := range entries {
		if entry.heading != "" {
			section = entry.heading
		}
		switch section {
		case "Verified (ranked)":
			verified++
		case "Measured · operational (exit unproven)":
			operational++
		case "Not measured":
			rest++
		}
	}
	rows := []string{" " + styleMuted.Render(fmt.Sprintf("%s · %d verified · %d measured · %d not measured",
		kind, verified, operational, rest))}
	if len(entries) == 0 {
		text := "Run a relay test across the connections you care about."
		if kind == "speed" {
			text = "A speed result requires a recent HTTPS measurement for the same connection."
		}
		rows = append(rows, "")
		return append(rows, mutedLines(text, w)...)
	}
	// The cursor walks ranked rows first; the window scrolls over the whole list
	// so a long unmeasured tail stays reachable.
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
			switch entry.heading {
			case "Measured · operational (exit unproven)":
				rows = append(rows, mutedLines("These connections answered HTTPS and were measured. Their exit address is shared or not independently proven, which does not make them bad; they are not ranked as verified paths.", w)...)
			case "Not measured":
				rows = append(rows, mutedLines("No usable number was produced. This is not automatically a dead link; the reason column says what stopped it.", w)...)
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
	if res.Status == "ok" || res.Status == "measured" {
		if res.Kind == "speed" {
			value = throughputLine(res)
		} else {
			value = fmt.Sprintf("delay %s · https p90 %s", fmtMs(latencyMS(res)), fmtMs(res.P90MS))
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
	case "s":
		switch m.tests.sortBy {
		case "":
			m.tests.sortBy = "latency"
		case "latency":
			m.tests.sortBy = "speed"
		case "speed":
			m.tests.sortBy = "failures"
		default:
			m.tests.sortBy = ""
		}
		m.tests.cursor, m.tests.offset = 0, 0
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

// latencyMS is the metric used to rank a latency row: the fast per-connection
// delay when recorded, the full HTTPS median otherwise (older rows).
func latencyMS(res app.TestResult) int64 {
	if res.DelayMS > 0 {
		return res.DelayMS
	}
	if res.P50MS > 0 {
		return res.P50MS
	}
	return res.LatencyMS
}

// httpsMS is the full exchange figure, kept separate from the fast delay so a
// slow body or probe page cannot be read as connection latency.
func httpsMS(res app.TestResult) int64 {
	if res.P50MS > 0 {
		return res.P50MS
	}
	return res.LatencyMS
}

// msPair renders "delay N ms · https M ms" when both figures exist.
func msPair(res app.TestResult) string {
	delay, https := latencyMS(res), httpsMS(res)
	switch {
	case delay > 0 && https > 0 && delay != https:
		return fmt.Sprintf("delay %d ms · https %d ms", delay, https)
	case delay > 0:
		return fmt.Sprintf("%d ms", delay)
	}
	return ""
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
		return "VERIFIED", styleOK
	case "measured":
		return "MEASURED", styleInfo
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
	"CONFIG_NOT_ISOLATED":       "measured on the live tunnel; the test-tunnel configuration is not isolated",
	"PATH_DIRECT_TARGET":        "the destination would go DIRECT, not through the tunnel",
	"EXIT_EQUALS_UPLINK":        "traffic left directly instead of through the tunnel",
	"EXIT_EQUALS_SERVING":       "the exit address is shared with the serving connection; ownership is unproven",
	"EXIT_AMBIGUOUS":            "two identity services disagreed about the exit",
	"EXIT_CHANGED":              "the exit changed during the measurement",
	"EXIT_UNKNOWN":              "the exit identity could not be determined",
	"POLICY_CHANGED":            "the routing policy changed during the measurement",
	"CONTROL_FAILED":            "the DIRECT control failed, so route decisions are not trustworthy",
	"ROUTE_EXPLAIN_UNAVAILABLE": "the routing policy could not be evaluated for a target",
	"ISOLATION_UNVERIFIED":      "isolated-test isolation has not been verified on this host",
	"TARGET_REJECTED":           "the download target was rejected by the security checks",
	"BUDGET_REACHED":            "the traffic budget was reached",
	"NO_PROVEN_RESULT":          "a recent HTTPS measurement is required before a speed test",
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

// connectivityNote separates "the connection carried traffic" from "the exit
// was proven". A measured or inconclusive row with a latency did work; only its
// path ownership is unproven, and the row must say so instead of reading like a
// dead link.
func connectivityNote(res app.TestResult) string {
	switch res.Status {
	case "measured":
		if ms := latencyMS(res); ms > 0 {
			return fmt.Sprintf("answered in %d ms; exit ownership unproven", ms)
		}
		if answered(res) {
			return "answered through the tested instance; exit identity unproven"
		}
		return ""
	case "inconclusive":
		if res.Reason == app.ReasonExitEqualsUplink && answered(res) {
			return "answered directly instead of through the tunnel; not measured"
		}
		if !answered(res) {
			return ""
		}
		if ms := latencyMS(res); ms > 0 {
			return fmt.Sprintf("answered in %d ms; path ownership unproven", ms)
		}
		return "answered through the tested instance; exit identity unproven"
	}
	return ""
}

// answered reports whether the run itself observed a completed request. The
// latency probe is not attempted once the exit check fails, but an isolated
// instance that completed the HTTPS probe still carried traffic.
func answered(res app.TestResult) bool {
	return latencyMS(res) > 0 || res.HTTPSProven || (res.Path != nil && res.Path.TunneledHTTPS)
}

// connectivityLine states what the evidence shows about carrying traffic,
// independently of whether the exit could be certified.
func connectivityLine(res app.TestResult) string {
	switch res.Status {
	case "ok":
		if app.VerifiedTestResult(res) {
			return "answered through the proven path"
		}
		return "answered; path proof incomplete, not ranked"
	case "measured":
		if ms := latencyMS(res); ms > 0 {
			return fmt.Sprintf("answered in %d ms; exit ownership unproven", ms)
		}
		if answered(res) {
			return "answered through the tested instance; exit identity unproven"
		}
		return "no answer recorded"
	case "inconclusive":
		if res.Reason == app.ReasonExitEqualsUplink && answered(res) {
			return "answered directly instead of through the tunnel; not measured"
		}
		if ms := latencyMS(res); ms > 0 {
			return fmt.Sprintf("answered in %d ms; exit ownership unproven", ms)
		}
		if answered(res) {
			return "answered through the tested instance; exit identity unproven"
		}
		return "no answer recorded"
	case "failed":
		return "no answer"
	case "cancelled":
		return "not measured (cancelled)"
	case "skipped":
		return "not run"
	}
	return "unknown"
}

// throughputLine states the measured transfer in both units: the API stores
// megabits per second, and the counted payload over the elapsed seconds gives
// the MB/s figure v2rayN-style comparisons use.
func throughputLine(res app.TestResult) string {
	if res.Kind != "speed" || res.MBps <= 0 {
		return ""
	}
	line := fmt.Sprintf("%.1f Mbps", res.MBps)
	if res.Seconds > 0 && res.Bytes > 0 {
		line += fmt.Sprintf(" · %.2f MB/s", float64(res.Bytes)/res.Seconds/1e6)
	}
	return line
}

func evidenceOf(res app.TestResult) string {
	if res.Superseded {
		return "a later attempt invalidated this proof"
	}
	if res.Status == "ok" && !app.VerifiedTestResult(res) {
		return "stale or incomplete path proof; not ranked"
	}
	if res.Status == "ok" || res.Status == "measured" {
		parts := []string{}
		if res.Kind == "speed" && res.MBps > 0 {
			parts = append(parts, throughputLine(res))
		} else if pair := msPair(res); pair != "" {
			parts = append(parts, pair)
		}
		if res.Status == "measured" {
			parts = append(parts, "exit unproven")
		}
		if res.TestedAt != "" {
			parts = append(parts, timeAgo(res.TestedAt))
		}
		return strings.Join(parts, " · ")
	}
	if res.Status == "inconclusive" {
		reason := reasonText(res.Reason)
		if note := connectivityNote(res); note != "" {
			if reason == "" {
				return note
			}
			return note + " · " + reason
		}
		return reason
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
	switch res.Evidence {
	case app.EvidenceVerified:
		fmt.Fprintf(&b, "Evidence:   verified path (isolated engine-owned config, independent exit)\n")
	case app.EvidenceOperational:
		fmt.Fprintf(&b, "Evidence:   operational measurement (exit ownership unproven)\n")
	}
	if res.Status != "ok" && res.Status != "measured" {
		fmt.Fprintf(&b, "Reason:     %s\n", orDash(evidenceOf(res)))
	} else if res.Status == "measured" && res.Reason != "" {
		fmt.Fprintf(&b, "Reason:     %s\n", orDash(reasonText(res.Reason)))
	}
	fmt.Fprintf(&b, "Connectivity: %s\n", connectivityLine(res))
	if res.Kind == "speed" {
		fmt.Fprintf(&b, "Throughput: %s\n", orDash(throughputLine(res)))
		fmt.Fprintf(&b, "Downloaded: %d B in %.2f s (counted payload, not link billing)\n", res.Bytes, res.Seconds)
		fmt.Fprintf(&b, "Target:     %s\n", orDash(res.Target))
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
