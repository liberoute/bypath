package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/bench"
	"github.com/liberoute/bypath/internal/layer"
)

const (
	opTimeout = 90 * time.Second
	// actionTimeout must stay above the gateway's total startup budget
	// (5 minutes by default). A shorter client deadline cancels the HTTP
	// request, and the daemon aborts the start it is still working on.
	actionTimeout = 10 * time.Minute
	pollEvery     = 4 * time.Second
	noticeLife    = 8 * time.Second
)

type section int

const (
	secDashboard section = iota
	secConnections
	secTests
	secSubscriptions
	secRouting
	secSettings
	secBench
	secImport
	secGateway
	secDNS
	secLogs
	secAbout
	secCount
)

var sectionTitles = []string{
	"Overview", "Connections", "Tests", "Sources", "Routing", "Settings",
	"Benchmark", "Import", "Gateway", "DNS", "Logs", "About",
}

var (
	styleTitle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("212"))
	styleAccent = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
	styleMuted  = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	styleOK     = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	styleWarn   = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	styleErr    = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	styleLabel  = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
	styleActive = lipgloss.NewStyle().Foreground(lipgloss.Color("0")).Background(lipgloss.Color("39"))
	styleDanger = lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Bold(true)
)

// Menu is the whole terminal application. It holds view state only; every
// operation goes through app.Contract, which is also what the CLI and the web
// panel use.
type Menu struct {
	svc    app.Contract
	svcErr error

	width, height int
	section       section
	prevSection   section

	status    app.Status
	statusErr string

	conns       []app.Connection
	connCursor  int
	connOffset  int
	connFilter  string
	connGroup   string
	connErr     string
	connGen     int
	connLoading bool

	// Organisation layer: the migration state, user groups and filters. These
	// never gate the legacy import lists; a layer error is shown, not fatal.
	layerStatus layer.Status
	layerPlan   *layer.MigrationPlan
	groups      []layer.GroupView
	layerErr    string
	layerGen    int
	// migrationPending opens the plan dialog as soon as a plan arrives.
	migrationPending bool
	// connShowHidden includes hidden connections in the list.
	connShowHidden bool
	// connLayerGroup filters the visible list by organisation group:
	// "" means every group, layerUngrouped means entries without a group.
	connLayerGroup string

	tests      testState
	routing    routingState
	subs       []app.Subscription
	subCursor  int
	subOffset  int
	subErr     string
	subGen     int
	subLoading bool

	benchReport bench.Report
	benchRows   []bench.Row
	benchCursor int
	benchOffset int
	benchErr    string
	benchGroup  string
	benchGen    int
	benchSorted bool

	engines   []app.Engine
	engineErr string

	settings       app.Settings
	settingsCursor int
	settingsOffset int
	settingsErr    string

	logs       []app.LogEntry
	logCursor  int
	logOffset  int
	logFilter  string
	followLogs bool
	logGen     int
	logErr     string

	exitIP  string
	exitErr string
	exitAt  time.Time

	detail       *app.ConnectionDetail
	detailScroll int

	importCursor int
	lastImport   string

	wiz *wizard

	overlay overlay

	busy       string
	busySince  time.Time
	spinner    int
	cancelOp   context.CancelFunc
	opCanceled bool

	notice    string
	noticeErr bool
	noticeAt  time.Time

	opSeq int
}

// New builds the terminal UI. The application service is opened once; when a
// gateway owns the state this is an HTTP client speaking to it.
func New() *Menu {
	svc, err := app.OpenDefault()
	return newWithService(svc, err)
}

func newWithService(svc app.Contract, err error) *Menu {
	return &Menu{svc: svc, svcErr: err, section: secDashboard}
}

// Run starts the program on the alternate screen.
func (m *Menu) Run() error {
	if m.width == 0 {
		m.width, m.height = 100, 30
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

// --- messages ---

type pollMsg struct{ at time.Time }
type spinnerMsg struct{}
type openedMsg struct {
	svc app.Contract
	err error
}
type statusMsg struct {
	gen    int
	status app.Status
	err    error
}
type connsMsg struct {
	gen  int
	list []app.Connection
	err  error
}
type subsMsg struct {
	gen  int
	list []app.Subscription
	err  error
}
type enginesMsg struct {
	list []app.Engine
	err  error
}
type settingsMsg struct {
	settings app.Settings
	err      error
}
type logsMsg struct {
	gen  int
	list []app.LogEntry
	err  error
}
type detailMsg struct {
	detail *app.ConnectionDetail
	err    error
}
type exitMsg struct {
	ip  string
	err error
}

// tunnelCanceledMsg reports the disconnect that follows a cancelled connect or
// restart.
type tunnelCanceledMsg struct{ err error }

type doneMsg struct {
	label  string
	result app.ActionResult
	err    error
}

// subPreviewMsg carries a secret-free preview fetched before anything is
// stored. url is set for URL previews, text for pasted/uploaded dumps.
type subPreviewMsg struct {
	preview app.SubscriptionPreview
	url     string
	text    string
	err     error
}

// subAddedMsg reports a subscription that was stored but whose first fetch
// failed, so the UI can be precise instead of claiming the add failed.
type subAddedMsg struct {
	group string
	links int
	err   error
}

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// Init implements tea.Model.
func (m *Menu) Init() tea.Cmd {
	if m.svc == nil {
		return nil
	}
	return tea.Batch(m.loadStatus(), m.reloadCurrent(), tickCmd())
}

func tickCmd() tea.Cmd {
	return tea.Tick(pollEvery, func(t time.Time) tea.Msg { return pollMsg{at: t} })
}

func spinnerTick() tea.Cmd {
	return tea.Tick(120*time.Millisecond, func(time.Time) tea.Msg { return spinnerMsg{} })
}

func openCmd() tea.Cmd {
	return func() tea.Msg {
		svc, err := app.OpenDefault()
		return openedMsg{svc: svc, err: err}
	}
}

// --- update ---

// Update implements tea.Model.
func (m *Menu) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case tea.KeyMsg:
		return m, m.handleKey(msg)

	case pollMsg:
		cmds := []tea.Cmd{tickCmd(), m.loadStatus()}
		if m.section == secLogs && m.followLogs {
			cmds = append(cmds, m.loadLogs())
		}
		if m.section == secTests && m.testRunning() {
			cmds = append(cmds, m.loadTestJob())
		}
		if m.notice != "" && time.Since(m.noticeAt) > noticeLife {
			m.notice = ""
			m.noticeErr = false
		}
		if m.busy != "" {
			cmds = append(cmds, spinnerTick())
		}
		return m, tea.Batch(cmds...)

	case spinnerMsg:
		if m.busy == "" {
			return m, nil
		}
		m.spinner++
		return m, spinnerTick()

	case openedMsg:
		m.svc = msg.svc
		m.svcErr = msg.err
		if m.svcErr != nil {
			return m, nil
		}
		return m, tea.Batch(m.loadStatus(), m.reloadCurrent())

	case statusMsg:
		if msg.err != nil {
			m.statusErr = friendlyError(msg.err)
			return m, nil
		}
		m.statusErr = ""
		prevActive := m.status.ActiveID
		prevSelected := m.status.SelectedID
		m.status = msg.status
		if (prevActive != m.status.ActiveID || prevSelected != m.status.SelectedID) &&
			(m.section == secConnections || m.section == secDashboard) {
			return m, m.loadConnections()
		}
		return m, nil

	case connsMsg:
		if msg.gen != m.connGen {
			return m, nil
		}
		m.connLoading = false
		if msg.err != nil {
			m.connErr = friendlyError(msg.err)
			return m, nil
		}
		m.connErr = ""
		m.conns = msg.list
		m.clampConnCursor()
		return m, nil

	case subsMsg:
		if msg.gen != m.subGen {
			return m, nil
		}
		m.subLoading = false
		if msg.err != nil {
			m.subErr = friendlyError(msg.err)
			return m, nil
		}
		m.subErr = ""
		m.subs = msg.list
		if m.subCursor >= len(m.subs) {
			m.subCursor = maxInt(0, len(m.subs)-1)
		}
		return m, nil

	case enginesMsg:
		if msg.err != nil {
			m.engineErr = friendlyError(msg.err)
			return m, nil
		}
		m.engineErr = ""
		m.engines = msg.list
		return m, nil

	case settingsMsg:
		if msg.err != nil {
			m.settingsErr = friendlyError(msg.err)
			return m, nil
		}
		m.settingsErr = ""
		m.settings = msg.settings
		m.clampSettingsCursor()
		return m, nil

	case logsMsg:
		if msg.gen != m.logGen {
			return m, nil
		}
		if msg.err != nil {
			m.logErr = friendlyError(msg.err)
			return m, nil
		}
		m.logErr = ""
		m.logs = msg.list
		if m.followLogs {
			m.logCursor = maxInt(0, len(m.logs)-1)
		}
		if m.logCursor >= len(m.logs) {
			m.logCursor = maxInt(0, len(m.logs)-1)
		}
		return m, nil

	case detailMsg:
		if msg.err != nil {
			m.overlay = overlay{}
			m.setNotice(true, "Could not load connection: %s", friendlyError(msg.err))
			return m, nil
		}
		m.detail = msg.detail
		m.detailScroll = 0
		return m, nil

	case exitMsg:
		m.busy = ""
		if msg.err != nil {
			m.exitErr = friendlyError(msg.err)
			m.exitIP = ""
			return m, nil
		}
		m.exitErr = ""
		m.exitIP = msg.ip
		m.exitAt = time.Now()
		return m, nil

	case doneMsg:
		m.busy = ""
		m.cancelOp = nil
		if m.opCanceled {
			m.opCanceled = false
			m.setNotice(false, "%s cancelled.", msg.label)
			return m, m.loadStatus()
		}
		if msg.err != nil {
			m.setNotice(true, "%s failed: %s", msg.label, friendlyError(msg.err))
			return m, m.loadStatus()
		}
		m.setNotice(false, "%s", msg.result.Message)
		cmds := []tea.Cmd{m.loadStatus(), m.reloadCurrent()}
		if m.section == secGateway {
			cmds = append(cmds, m.loadEngines())
		}
		return m, tea.Batch(cmds...)

	case tunnelCanceledMsg:
		if msg.err != nil {
			m.setNotice(true, "Cancelled, but the tunnel did not stop cleanly: %s", friendlyError(msg.err))
		} else {
			m.setNotice(false, "Cancelled. The tunnel is disconnected; the management service stays available.")
		}
		return m, m.loadStatus()

	case openVPNPreparedMsg:
		return m.handlePrepared(msg)

	case openVPNPreviewedMsg:
		return m.handlePreviewed(msg)

	case openVPNImportedMsg:
		return m.handleImported(msg)

	case subPreviewMsg:
		m.busy = ""
		if msg.err != nil {
			m.setNotice(true, "Subscription preview failed: %s", friendlyError(msg.err))
			return m, nil
		}
		m.showSubscriptionPreview(msg)
		return m, nil

	case subAddedMsg:
		m.busy = ""
		if msg.err != nil {
			m.setNotice(true, "Subscription added to %q, but fetching its links failed: %s. Press r to retry.",
				msg.group, friendlyError(msg.err))
		} else {
			m.setNotice(false, "Subscription added to %q with %d link(s).", msg.group, msg.links)
		}
		return m, tea.Batch(m.loadStatus(), m.reloadCurrent())

	case benchMsg:
		return m, m.handleBench(msg)

	case layerMsg:
		return m, m.handleLayer(msg)

	case connDeletePlanMsg:
		return m, m.handleConnDeletePlan(msg)

	case sourceDeletePlanMsg:
		return m, m.handleSourceDeletePlan(msg)

	case testJobMsg:
		return m, m.handleTestJob(msg)

	case testResultsMsg:
		return m, m.handleTestResults(msg)

	case budgetMsg:
		return m, m.handleBudget(msg)

	case routingMsg:
		return m, m.handleRouting(msg)
	}
	return m, nil
}

func (m *Menu) setNotice(isErr bool, format string, args ...interface{}) {
	m.notice = fmt.Sprintf(format, args...)
	m.noticeErr = isErr
	m.noticeAt = time.Now()
}

func (m *Menu) handleKey(k tea.KeyMsg) tea.Cmd {
	key := k.String()
	if key == "ctrl+c" {
		return tea.Quit
	}
	if m.overlay.kind != ovNone {
		return m.overlayKey(k)
	}
	if m.detail != nil {
		switch key {
		case "esc", "q", "enter":
			m.detail = nil
		case "up", "k":
			m.detailScroll = maxInt(0, m.detailScroll-1)
		case "down", "j":
			m.detailScroll++
		}
		return nil
	}
	// While an action is in flight, Escape cancels that action instead of
	// navigating. Running this before the section keys is what makes a single
	// Escape predictable: it used to jump to the dashboard first and only the
	// second press reached the cancellation branch.
	if m.busy != "" && key == "esc" {
		return m.cancelBusy()
	}
	if key == "q" {
		return tea.Quit
	}
	if m.svc == nil {
		if key == "r" {
			m.setNotice(false, "Reopening the application service…")
			return openCmd()
		}
		return nil
	}
	if len(key) == 1 && key[0] >= '1' && key[0] <= '9' {
		m.goSection(section(key[0] - '1'))
		return m.reloadCurrent()
	}
	switch key {
	case "tab":
		m.goSection((m.section + 1) % secCount)
		return m.reloadCurrent()
	case "shift+tab":
		m.goSection((m.section + secCount - 1) % secCount)
		return m.reloadCurrent()
	case "r":
		// Subscriptions and benchmark bind r to a bounded network operation;
		// every other section only reloads local state.
		if m.section == secSubscriptions || m.section == secBench {
			return m.sectionKey(k)
		}
		return tea.Batch(m.loadStatus(), m.reloadCurrent())
	case "esc":
		if m.section != secDashboard {
			m.goSection(secDashboard)
			return m.reloadCurrent()
		}
	}
	return m.sectionKey(k)
}

func (m *Menu) goSection(s section) {
	if s < 0 || s >= secCount || s == m.section {
		return
	}
	m.prevSection = m.section
	m.section = s
	m.detail = nil
}

func (m *Menu) sectionKey(k tea.KeyMsg) tea.Cmd {
	key := k.String()
	if m.busy != "" {
		if key == "esc" {
			return m.cancelBusy()
		}
		return nil
	}
	switch m.section {
	case secDashboard:
		return m.dashboardKey(key)
	case secConnections:
		return m.connectionsKey(k, key)
	case secTests:
		return m.testsKey(k, key)
	case secSubscriptions:
		return m.subscriptionsKey(k, key)
	case secRouting:
		return m.routingKey(k, key)
	case secSettings:
		return m.settingsKey(k, key)
	case secBench:
		return m.benchKey(key)
	case secImport:
		return m.importKey(key)
	case secGateway:
		return m.gatewayKey(key)
	case secDNS:
		return m.dnsKey(key)
	case secLogs:
		return m.logsKey(k, key)
	case secAbout:
		return nil
	}
	return nil
}

// --- loading commands ---

func (m *Menu) loadStatus() tea.Cmd {
	if m.svc == nil {
		return nil
	}
	svc := m.svc
	m.opSeq++
	gen := m.opSeq
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		st, err := svc.Status(ctx)
		return statusMsg{gen: gen, status: st, err: err}
	}
}

func (m *Menu) loadConnections() tea.Cmd {
	if m.svc == nil {
		return nil
	}
	m.connGen++
	gen := m.connGen
	m.connLoading = true
	svc := m.svc
	filter := app.ConnectionFilter{Search: m.connFilter, Group: m.connGroup, IncludeHidden: m.connShowHidden}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
		defer cancel()
		list, err := svc.ListConnections(ctx, filter)
		return connsMsg{gen: gen, list: list, err: err}
	}
}

func (m *Menu) loadSubscriptions() tea.Cmd {
	if m.svc == nil {
		return nil
	}
	m.subGen++
	gen := m.subGen
	m.subLoading = true
	svc := m.svc
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
		defer cancel()
		list, err := svc.ListSubscriptions(ctx)
		return subsMsg{gen: gen, list: list, err: err}
	}
}

func (m *Menu) loadEngines() tea.Cmd {
	if m.svc == nil {
		return nil
	}
	svc := m.svc
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		list, err := svc.Engines(ctx)
		return enginesMsg{list: list, err: err}
	}
}

func (m *Menu) loadSettings() tea.Cmd {
	if m.svc == nil {
		return nil
	}
	svc := m.svc
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		s, err := svc.Settings(ctx)
		return settingsMsg{settings: s, err: err}
	}
}

func (m *Menu) loadLogs() tea.Cmd {
	if m.svc == nil {
		return nil
	}
	m.logGen++
	gen := m.logGen
	svc := m.svc
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		list, err := svc.Logs(ctx, app.LogQuery{Limit: 2000})
		return logsMsg{gen: gen, list: list, err: err}
	}
}

func (m *Menu) loadDetail(id string) tea.Cmd {
	if m.svc == nil {
		return nil
	}
	svc := m.svc
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		d, err := svc.GetConnection(ctx, id)
		if err != nil {
			return detailMsg{err: err}
		}
		return detailMsg{detail: &d}
	}
}

func (m *Menu) probeExit() tea.Cmd {
	if m.svc == nil {
		return nil
	}
	svc := m.svc
	m.busy = "Probing public exit address"
	return tea.Batch(func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		ip, err := svc.ProbeExitIP(ctx)
		return exitMsg{ip: ip, err: err}
	}, spinnerTick())
}

// reloadCurrent refreshes the dataset backing the visible section.
func (m *Menu) reloadCurrent() tea.Cmd {
	switch m.section {
	case secConnections:
		return tea.Batch(m.loadConnections(), m.loadLayer())
	case secTests:
		return tea.Batch(m.loadConnections(), m.loadTestResults())
	case secSubscriptions:
		return tea.Batch(m.loadSubscriptions(), m.loadConnections())
	case secRouting:
		return m.loadRouting()
	case secBench:
		return nil
	case secImport:
		return tea.Batch(m.loadConnections(), m.loadSubscriptions())
	case secGateway:
		return tea.Batch(m.loadEngines(), m.loadConnections())
	case secDNS:
		return tea.Batch(m.loadSettings(), m.loadLogs())
	case secSettings:
		return m.loadSettings()
	case secLogs:
		return m.loadLogs()
	}
	return nil
}

// runAction wraps a mutating contract call. Exactly one action runs at a time
// and the busy flag is cleared when the result arrives.
func (m *Menu) runAction(label string, fn func(ctx context.Context, svc app.Contract) (app.ActionResult, error)) tea.Cmd {
	if m.svc == nil {
		m.setNotice(true, "Application service is not available: %s", friendlyError(m.svcErr))
		return nil
	}
	if m.busy != "" {
		return nil
	}
	m.busy = label
	m.busySince = time.Now()
	m.opCanceled = false
	svc := m.svc
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	m.cancelOp = cancel
	return tea.Batch(func() tea.Msg {
		defer cancel()
		res, err := fn(ctx, svc)
		return doneMsg{label: label, result: res, err: err}
	}, spinnerTick())
}

// cancelBusy aborts the in-flight action at the request level. Closing the
// client connection makes the daemon abort the work it is still doing, so this
// is a real cancellation rather than a local dismissal. The action's result
// message still arrives and clears the busy state if the call returns.
//
// A cancelled connect or restart leaves the daemon somewhere between
// "starting" and "failed"; an explicit Disconnect follows so the gateway ends
// in DISCONNECTED instead of reporting a failed start the operator never
// wanted, and so the cancellation is enforced even if the request had already
// completed on the daemon.
func (m *Menu) cancelBusy() tea.Cmd {
	if m.busy == "" {
		return nil
	}
	label := m.busy
	if m.cancelOp != nil {
		m.cancelOp()
		m.cancelOp = nil
	}
	m.busy = ""
	m.opCanceled = true
	m.setNotice(false, "Cancelling %s: the gateway is stopping the work it had started.", strings.ToLower(label))
	if (label != "Connect" && label != "Restart") || m.svc == nil {
		return nil
	}
	svc := m.svc
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := svc.Disconnect(ctx)
		return tunnelCanceledMsg{err: err}
	}
}

// --- cursor helpers ---

func (m *Menu) clampConnCursor() {
	list := m.filteredConnections()
	if m.connCursor >= len(list) {
		m.connCursor = maxInt(0, len(list)-1)
	}
	if m.connCursor < 0 {
		m.connCursor = 0
	}
}

func (m *Menu) moveConn(delta int) {
	list := m.filteredConnections()
	if len(list) == 0 {
		return
	}
	m.connCursor = clampInt(m.connCursor+delta, 0, len(list)-1)
}

func (m *Menu) moveSub(delta int) {
	if len(m.subs) == 0 {
		return
	}
	m.subCursor = clampInt(m.subCursor+delta, 0, len(m.subs)-1)
}

// --- small helpers ---

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// friendlyError trims an application error to one readable line and strips any
// accidental URI material.
func friendlyError(err error) string {
	if err == nil {
		return ""
	}
	msg := app.Redact(strings.TrimSpace(err.Error()))
	msg = strings.ReplaceAll(msg, "\n", " ")
	if msg == "" {
		return "unknown error"
	}
	var ae *app.Error
	if errors.As(err, &ae) && ae.Hint != "" {
		return msg + " — " + ae.Hint
	}
	return msg
}

func stateColor(state string) lipgloss.Style {
	switch strings.ToUpper(state) {
	case "CONNECTED":
		return styleOK
	case "CONNECTING", "DEGRADED", "RECONNECTING", "RECOVERING":
		return styleWarn
	case "ERROR", "FAILED":
		return styleErr
	default:
		return styleMuted
	}
}

func (m *Menu) bodyHeight() int {
	used := lipgloss.Height(m.viewHeader()) + lipgloss.Height(m.viewTabs()) + lipgloss.Height(m.viewFooter())
	if m.notice != "" {
		used++
	}
	h := m.height - used
	if h < 1 {
		h = 1
	}
	return h
}

func (m *Menu) contentWidth() int {
	w := m.width
	if w < 20 {
		w = 20
	}
	return w
}

func clipLine(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= width {
		return s
	}
	return lipgloss.NewStyle().MaxWidth(width).Render(s)
}

func fillLine(s string, width int) string {
	w := lipgloss.Width(s)
	if w >= width {
		return clipLine(s, width)
	}
	return s + strings.Repeat(" ", width-w)
}

// wrapPlain breaks plain text at word boundaries so section copy stays readable
// in narrow SSH windows instead of being clipped mid-sentence.
func wrapPlain(s string, width int) []string {
	if width < 1 {
		width = 1
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	var lines []string
	cur := ""
	for _, word := range words {
		if cur == "" {
			// A path or URL has no spaces to break at, so an overlong word is
			// split on display columns instead of being clipped off the edge.
			for lipgloss.Width(word) > width {
				head, rest := splitAtWidth(word, width)
				lines = append(lines, head)
				word = rest
			}
			cur = word
			continue
		}
		if lipgloss.Width(cur)+1+lipgloss.Width(word) <= width {
			cur += " " + word
			continue
		}
		lines = append(lines, cur)
		for lipgloss.Width(word) > width {
			head, rest := splitAtWidth(word, width)
			lines = append(lines, head)
			word = rest
		}
		cur = word
	}
	return append(lines, cur)
}

// splitAtWidth cuts plain text after at most width display columns and returns
// the remainder. Runes, not bytes, so wide characters stay intact.
func splitAtWidth(s string, width int) (string, string) {
	used := 0
	for i, r := range s {
		rw := lipgloss.Width(string(r))
		if used+rw > width {
			if used == 0 {
				// A single wide rune wider than the whole line still has to
				// advance, or the caller's loop would never terminate.
				return string(r), s[i+len(string(r)):]
			}
			return s[:i], s[i:]
		}
		used += rw
	}
	return s, ""
}

// mutedLines renders wrapped explanatory copy with one leading space per line.
func mutedLines(text string, width int) []string {
	lines := wrapPlain(text, width-1)
	for i := range lines {
		lines[i] = " " + styleMuted.Render(lines[i])
	}
	return lines
}

// truncatePlain clips plain text to a display width. Width is counted in
// terminal columns, not bytes or runes: a CJK or emoji character occupies two
// columns and a combining mark none, and treating each as one column shifted
// every column after it. Styled text is returned untouched because cutting it
// can split an escape sequence; callers that hold styled text clip it with the
// ANSI-aware clipLine instead.
func truncatePlain(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= width {
		return s
	}
	if strings.ContainsRune(s, 0x1b) {
		return s
	}
	if width == 1 {
		return "…"
	}
	var b strings.Builder
	used := 0
	for _, r := range s {
		rw := lipgloss.Width(string(r))
		if rw < 0 {
			rw = 0
		}
		if used+rw > width-1 {
			break
		}
		b.WriteRune(r)
		used += rw
	}
	return b.String() + "…"
}

// kvLines renders a label and a possibly long value. The value wraps under
// itself instead of being clipped, so an error cause such as "local
// configuration error" stays fully readable in a narrow window.
func (m *Menu) kvLines(label, value string, labelWidth int, valueStyle lipgloss.Style) []string {
	prefix := " " + styleLabel.Render(fmt.Sprintf("%-*s", labelWidth, label)) + " "
	indent := labelWidth + 2
	avail := m.contentWidth() - indent
	if avail < 8 {
		avail = 8
	}
	lines := wrapPlain(value, avail)
	out := make([]string, 0, len(lines))
	for i, line := range lines {
		if i > 0 {
			out = append(out, strings.Repeat(" ", indent)+valueStyle.Render(line))
			continue
		}
		out = append(out, prefix+valueStyle.Render(line))
	}
	return out
}

// indentedLines wraps text under a section heading with a hanging indent.
func (m *Menu) indentedLines(text string, indent int, style lipgloss.Style) []string {
	if indent < 0 {
		indent = 0
	}
	avail := m.contentWidth() - indent
	if avail < 8 {
		avail = 8
	}
	lines := wrapPlain(text, avail)
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		out = append(out, strings.Repeat(" ", indent)+style.Render(line))
	}
	return out
}

// layoutRows renders lines clipped and padded to the terminal width.
func (m *Menu) layoutRows(lines []string, height int) string {
	w := m.contentWidth()
	if len(lines) > height {
		lines = lines[:height]
	}
	for i := range lines {
		lines[i] = fillLine(clipLine(lines[i], w), w)
	}
	return strings.Join(lines, "\n")
}
