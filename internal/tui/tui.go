// Package tui provides an interactive terminal UI using bubbletea.
package tui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/updater"
)

// socksPort returns the configured SOCKS5 port (reads from config, defaults to 2801).
func socksPort() int {
	cfg, err := config.Load(paths.Get().ConfigFile)
	if err == nil && cfg.Server.SOCKSPort > 0 {
		return cfg.Server.SOCKSPort
	}
	return 2801
}

// socksAddr returns the full SOCKS5 proxy address string.
func socksAddr() string {
	return fmt.Sprintf("socks5h://127.0.0.1:%d", socksPort())
}

// --- Styles ---
var (
	// Header
	logoStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("14"))
	// Tabs
	activeTabStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("14")).Padding(0, 2)
	inactiveTabStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("7")).Padding(0, 2)
	// Status bar
	statusBarStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).PaddingLeft(2)
	statusOffStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).PaddingLeft(2)
	// List
	itemStyle     = lipgloss.NewStyle().PaddingLeft(2)
	selectedStyle = lipgloss.NewStyle().PaddingLeft(0).Foreground(lipgloss.Color("10")).Bold(true)
	headerStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("6")).Bold(true).PaddingLeft(2)
	dimStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	// Messages
	errorMsgStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).PaddingLeft(2)
	successStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).PaddingLeft(2)
	outputStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("7")).PaddingLeft(2)
	updateStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).PaddingLeft(2).Bold(true)
)

// --- Types ---

type tab int

const (
	tabHome tab = iota
	tabServers
	tabSubs
)

type model struct {
	tab         tab
	cursor      int
	groups      []string
	activeGroup int // index into groups for server tab
	output      string
	showOutput  bool
	outputScroll int // scroll offset for output view
	termHeight   int // terminal height for scroll calculation
	running     bool
	inputMode   bool
	inputBuf    string
	inputLabel  string
	inputAction string
	updateInfo  string
	activeInfo  string
	statusInfo  string
	// Confirm dialog state
	confirmMode   bool
	confirmLabel  string
	confirmYes    bool // true = Yes selected, false = No selected
	confirmAction string
	confirmYesLabel string // custom label for Yes button (empty = "Yes")
	confirmNoLabel  string // custom label for No button (empty = "No")
	// Bench state (inline in servers tab)
	benchRunning bool
	benchDone    bool
	benchResults []benchEntry
	benchMode    string // "ping", "full", "single"
	benchSortAsc bool   // true = ascending (fastest first), false = descending
	// Cancellable action support
	cancelFn context.CancelFunc
}

// Messages
type actionDoneMsg struct{ output string; err error; targetGroup string }
type updateCheckMsg struct{ info string }
type activeInfoMsg struct{ info string }
type statusMsg struct{ info string }
type inlineBenchDoneMsg struct{ results []benchEntry }

type Menu struct{}
func New() *Menu { return &Menu{} }

func (m *Menu) Run() {
	mdl := initialModel()
	p := tea.NewProgram(mdl, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}

func initialModel() model {
	groups := findGroups()
	ag := 0
	// Start on first group that has links
	for i, g := range groups {
		if g != "default" {
			ag = i
			break
		}
	}
	return model{tab: tabHome, groups: groups, activeGroup: ag}
}

// --- Init ---

func (m model) Init() tea.Cmd {
	return tea.Batch(checkUpdateCmd, loadActiveInfoCmd, loadStatusCmd)
}

func checkUpdateCmd() tea.Msg {
	result, err := updater.Check()
	if err == nil && result.Available {
		info := fmt.Sprintf("🆕 %s → %s  |  https://github.com/liberoute/bypath/compare/v%s...v%s",
			result.CurrentVersion, result.LatestVersion, result.CurrentVersion, result.LatestVersion)
		return updateCheckMsg{info: info}
	}
	return updateCheckMsg{}
}

func loadActiveInfoCmd() tea.Msg {
	data, err := os.ReadFile(filepath.Join(paths.Get().ProfileDir, ".active"))
	if err != nil {
		return activeInfoMsg{info: "No server selected"}
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		return activeInfoMsg{info: "No server selected"}
	}
	return activeInfoMsg{info: fmt.Sprintf("%s / %s", strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1]))}
}

func loadStatusCmd() tea.Msg {
	// Check PID file first
	pidPaths := []string{
		filepath.Join(paths.Get().DataDir, "bypath.pid"),
		"./bypath.pid",
		"/run/bypath.pid",
	}
	for _, pidPath := range pidPaths {
		pidData, _ := os.ReadFile(pidPath)
		pidStr := strings.TrimSpace(string(pidData))
		if pidStr != "" {
			if _, err := os.Stat(fmt.Sprintf("/proc/%s", pidStr)); err == nil {
				return statusMsg{info: "running"}
			}
		}
	}
	// Fallback: check if any bypath run process exists
	out, err := exec.Command("pgrep", "-f", "bypath run").Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		return statusMsg{info: "running"}
	}
	return statusMsg{info: "stopped"}
}

// --- Update ---

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case updateCheckMsg:
		m.updateInfo = msg.info
		return m, nil
	case activeInfoMsg:
		m.activeInfo = msg.info
		return m, nil
	case statusMsg:
		m.statusInfo = msg.info
		return m, nil
	case tea.WindowSizeMsg:
		m.termHeight = msg.Height
		return m, nil
	case inlineBenchDoneMsg:
		m.benchRunning = false
		m.benchDone = true
		m.benchResults = msg.results
		return m, nil
	case actionDoneMsg:
		m.running = false
		m.cancelFn = nil
		m.showOutput = true
		m.outputScroll = 0
		m.output = msg.output
		if msg.err != nil {
			m.output += "\n" + errorMsgStyle.Render(fmt.Sprintf("Error: %v", msg.err))
		}
		// Reload groups, preserving the active group by name (not index) so that
		// newly-added groups inserted earlier alphabetically don't shift the pointer.
		prevGroup := ""
		if m.activeGroup < len(m.groups) {
			prevGroup = m.groups[m.activeGroup]
		}
		m.groups = findGroups()
		restored := false
		for i, g := range m.groups {
			if g == prevGroup {
				m.activeGroup = i
				restored = true
				break
			}
		}
		if !restored {
			// If the active group was renamed, track it to its new name.
			if msg.targetGroup != "" {
				for i, g := range m.groups {
					if g == msg.targetGroup {
						m.activeGroup = i
						restored = true
						break
					}
				}
			}
		}
		if !restored {
			// Previous group gone; land on first non-default group, or 0.
			m.activeGroup = 0
			for i, g := range m.groups {
				if g != "default" {
					m.activeGroup = i
					break
				}
			}
		}
		return m, tea.Batch(loadActiveInfoCmd, loadStatusCmd)
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Global keys
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	}

	// Confirm dialog mode
	if m.confirmMode {
		return m.handleConfirm(msg)
	}

	// Input mode
	if m.inputMode {
		return m.handleInput(msg)
	}

	// Output mode — scroll or dismiss
	if m.showOutput {
		switch msg.String() {
		case "q", "esc", "enter":
			m.showOutput = false
			m.output = ""
			m.outputScroll = 0
			return m, nil
		case "up", "k":
			if m.outputScroll > 0 {
				m.outputScroll--
			}
			return m, nil
		case "down", "j":
			m.outputScroll++
			return m, nil
		default:
			// Any other key dismisses
			m.showOutput = false
			m.output = ""
			m.outputScroll = 0
			return m, nil
		}
	}

	// Running — allow esc/q to cancel if a cancellable action is active
	if m.running {
		switch msg.String() {
		case "esc", "q":
			if m.cancelFn != nil {
				m.cancelFn()
				m.cancelFn = nil
			}
			m.running = false
		}
		return m, nil
	}

	switch msg.String() {
	case "q":
		return m, tea.Quit
	case "tab", "l", "right":
		m.tab = (m.tab + 1) % 3
		m.cursor = 0
		return m, nil
	case "shift+tab", "h", "left":
		m.tab = (m.tab + 2) % 3 // -1 mod 3
		m.cursor = 0
		return m, nil
	}

	// Tab-specific keys
	switch m.tab {
	case tabHome:
		return m.handleHomeKey(msg)
	case tabServers:
		return m.handleServersKey(msg)
	case tabSubs:
		return m.handleSubsKey(msg)
	}
	return m, nil
}

// --- Home tab keys ---

func (m model) handleHomeKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	homeItems := m.homeItems()
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 { m.cursor-- }
	case "down", "j":
		if m.cursor < len(homeItems)-1 { m.cursor++ }
	case "enter", " ":
		return m.executeHomeAction(homeItems[m.cursor])
	}
	return m, nil
}

type homeItem struct {
	icon, label, action string
}

func (m model) homeItems() []homeItem {
	// Check autostart status
	autoLabel := "Auto Start (disabled)"
	cmd := exec.Command("systemctl", "is-enabled", "bypath")
	out, _ := cmd.Output()
	if strings.TrimSpace(string(out)) == "enabled" {
		autoLabel = "Auto Start (enabled)"
	}

	// Check current engine preference
	engineLabel := "Engine: auto (sing-box)"
	cfg, err := config.Load(paths.Get().ConfigFile)
	if err == nil && cfg.Engines.PreferredEngine != "" {
		engineLabel = fmt.Sprintf("Engine: %s", cfg.Engines.PreferredEngine)
	}

	// Update label — show version if available
	updateLabel := "Update Bypath"
	if m.updateInfo != "" {
		updateLabel = "Update Bypath ⚡ UPDATE AVAILABLE"
	}

	if m.statusInfo == "running" {
		return []homeItem{
			{"🔄", "Restart Gateway", "restart"},
			{"🛑", "Stop Gateway", "stop"},
			{"📊", "Status (test connection)", "live-status"},
			{"🔁", autoLabel, "autostart-toggle"},
			{"⚙️", engineLabel, "change-engine"},
			{"🆕", updateLabel, "self-update"},
			{"📥", "Update All Subs", "sub-update"},
			{"📡", "Add Subscription", "sub-add"},
			{"➕", "Add Server (URI)", "add-link"},
			{"🔧", fmt.Sprintf("Change Port (current: %d)", socksPort()), "change-port"},
			{"ℹ️", "Version Info", "status"},
			{"🚪", "Exit", "exit"},
		}
	}
	return []homeItem{
		{"🚀", "Start Gateway", "start"},
		{"🔁", autoLabel, "autostart-toggle"},
		{"⚙️", engineLabel, "change-engine"},
		{"🆕", updateLabel, "self-update"},
		{"📥", "Update All Subs", "sub-update"},
		{"📡", "Add Subscription", "sub-add"},
		{"➕", "Add Server (URI)", "add-link"},
		{"🔧", fmt.Sprintf("Change Port (current: %d)", socksPort()), "change-port"},
		{"ℹ️", "Version Info", "status"},
		{"🚪", "Exit", "exit"},
	}
}

func (m model) executeHomeAction(item homeItem) (tea.Model, tea.Cmd) {
	switch item.action {
	case "exit":
		return m, tea.Quit
	case "sub-add":
		m.inputMode = true
		m.inputLabel = "Subscription URL"
		m.inputBuf = ""
		m.inputAction = "sub-add"
		return m, nil
	case "add-link":
		m.inputMode = true
		m.inputLabel = "Server URI (vmess://, vless://, ss://...)"
		m.inputBuf = ""
		m.inputAction = "add-link"
		return m, nil
	case "change-port":
		m.inputMode = true
		m.inputLabel = "New SOCKS/Mixed port"
		m.inputBuf = fmt.Sprintf("%d", socksPort())
		m.inputAction = "change-port"
		return m, nil
	case "self-update":
		m.confirmMode = true
		m.confirmLabel = "Update bypath to latest version?"
		m.confirmYes = true // default on Yes
		m.confirmAction = "do-update-ask-method"
		return m, nil
	case "restart":
		m.confirmMode = true
		m.confirmLabel = "Restart gateway?"
		m.confirmYes = true
		m.confirmAction = "restart-gateway"
		return m, nil
	case "stop":
		m.confirmMode = true
		m.confirmLabel = "Stop gateway?"
		m.confirmYes = false
		m.confirmAction = "stop-gateway"
		return m, nil
	case "live-status":
		ctx, cancel := context.WithCancel(context.Background())
		m.cancelFn = cancel
		m.running = true
		return m, func() tea.Msg {
			defer cancel()
			return executeLiveStatus(ctx)
		}
	default:
		m.running = true
		act := item.action
		return m, func() tea.Msg { return executeAction(act, "") }
	}
}

// --- Servers tab keys ---

func (m model) handleServersKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	links := m.currentLinks()
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 { m.cursor-- }
	case "down", "j":
		if m.cursor < len(links)-1 { m.cursor++ }
	case "0":
		// Switch to default group
		for i, g := range m.groups {
			if g == "default" { m.activeGroup = i; m.cursor = 0; m.benchDone = false; m.benchResults = nil; break }
		}
	case "1", "2", "3", "4", "5", "6", "7", "8", "9":
		// Switch group by number (skip default, count non-default)
		num := int(msg.String()[0] - '0')
		count := 0
		for i, g := range m.groups {
			if g == "default" { continue }
			count++
			if count == num { m.activeGroup = i; m.cursor = 0; m.benchDone = false; m.benchResults = nil; break }
		}
	case "enter", " ":
		if m.benchDone && len(m.benchResults) > 0 && m.cursor < len(m.benchResults) {
			// When bench results are shown (sorted), use the sorted entry's idx
			sorted := m.getSortedBenchResults()
			if m.cursor < len(sorted) {
				entry := sorted[m.cursor]
				group := m.groups[m.activeGroup]
				m.running = true
				idx := entry.idx
				return m, func() tea.Msg {
					exe, _ := os.Executable()
					result := runCmdCapture(exe, "select", fmt.Sprintf("%d", idx), "-g", group)
					// Restart gateway if running
					if isGatewayRunning() {
						restartGateway(exe)
						result.output += "\n🔄 Gateway restarted with new server"
					}
					return result
				}
			}
		} else if len(links) > 0 && m.cursor < len(links) {
			link := links[m.cursor]
			group := m.groups[m.activeGroup]
			m.running = true
			return m, func() tea.Msg {
				exe, _ := os.Executable()
				result := runCmdCapture(exe, "select", fmt.Sprintf("%d", link.idx), "-g", group)
				if isGatewayRunning() {
					restartGateway(exe)
					result.output += "\n🔄 Gateway restarted with new server"
				}
				return result
			}
		}
	case "p":
		// Ping ALL in current group
		if len(links) > 0 {
			m.benchRunning = true
			m.benchDone = false
			m.benchResults = nil
			entries := loadBenchEntries(m.groups[m.activeGroup])
			return m, func() tea.Msg {
				results := make([]benchEntry, len(entries))
				copy(results, entries)
				var wg sync.WaitGroup
				var mu sync.Mutex
				for i, e := range entries {
					wg.Add(1)
					go func(idx int, entry benchEntry) {
						defer wg.Done()
						ms := tcpPing(entry.address, entry.port)
						mu.Lock()
						results[idx].ping = ms
						if ms > 0 { results[idx].status = benchDone } else { results[idx].status = benchFailed }
						mu.Unlock()
					}(i, e)
				}
				wg.Wait()
				return inlineBenchDoneMsg{results: results}
			}
		}
	case "s", "b":
		// Full test ALL (ping + relay + download)
		if len(links) > 0 {
			m.benchRunning = true
			m.benchDone = false
			m.benchResults = nil
			m.benchSortAsc = true // default: fastest first
			g := m.groups[m.activeGroup]
			entries := loadBenchEntries(g)
			return m, func() tea.Msg {
				results := runParallelBench(entries, g)
				return inlineBenchDoneMsg{results: results}
			}
		}
	case "f":
		// Flip/toggle sort order in bench results
		if m.benchDone && len(m.benchResults) > 0 {
			m.benchSortAsc = !m.benchSortAsc
			m.cursor = 0
		}
	case "t":
		// Test SINGLE (ping + relay)
		if len(links) > 0 && m.cursor < len(links) {
			link := links[m.cursor]
			group := m.groups[m.activeGroup]
			m.running = true
			idx := link.idx
			return m, func() tea.Msg {
				exe, _ := os.Executable()
				result := runCmdCapture(exe, "bench", "-g", group, "--single", fmt.Sprintf("%d", idx))
				return result
			}
		}
	case "n":
		// Create new group
		m.inputMode = true
		m.inputLabel = "New group name"
		m.inputBuf = ""
		m.inputAction = "create-group"
	case "x":
		// Delete current group (if empty or confirm)
		if len(m.groups) > 0 && m.activeGroup < len(m.groups) {
			group := m.groups[m.activeGroup]
			if group == "default" {
				m.showOutput = true
				m.output = "❌ Cannot delete 'default' group"
				return m, nil
			}
			m.confirmMode = true
			m.confirmLabel = fmt.Sprintf("Delete group '%s' and all its links?", group)
			m.confirmYes = false // default No
			m.confirmAction = "delete-group-" + group
		}
	case "d", "delete":
		// Delete selected server
		if len(links) > 0 && m.cursor < len(links) {
			link := links[m.cursor]
			group := m.groups[m.activeGroup]
			name := link.remark
			if name == "" { name = link.server }
			m.confirmMode = true
			m.confirmLabel = fmt.Sprintf("Delete server '%s'?", name)
			m.confirmYes = false
			m.confirmAction = fmt.Sprintf("delete-server|%s|%d", group, link.idx)
		}
	}
	return m, nil
}

func tcpPingFromTUI(host string, port int) int {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil { return -1 }
	conn.Close()
	return int(time.Since(start).Milliseconds())
}

func (m model) currentLinks() []linkEntry {
	if len(m.groups) == 0 { return nil }
	return loadGroupLinks(m.groups[m.activeGroup])
}

// getSortedBenchResults returns bench results sorted by the current sort preference
func (m model) getSortedBenchResults() []benchEntry {
	sorted := make([]benchEntry, len(m.benchResults))
	copy(sorted, m.benchResults)
	sortAsc := m.benchSortAsc
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].relay > 0 && sorted[j].relay > 0 {
			if sortAsc {
				return sorted[i].relay < sorted[j].relay
			}
			return sorted[i].relay > sorted[j].relay
		}
		if sorted[i].relay > 0 {
			return true
		}
		if sorted[j].relay > 0 {
			return false
		}
		if sorted[i].ping > 0 && sorted[j].ping <= 0 {
			return true
		}
		if sorted[j].ping > 0 && sorted[i].ping <= 0 {
			return false
		}
		if sortAsc {
			return sorted[i].ping < sorted[j].ping
		}
		return sorted[i].ping > sorted[j].ping
	})
	return sorted
}

// --- Subs tab keys ---

func (m model) handleSubsKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	subs := loadSubscriptions()
	switch msg.String() {
	case "up", "k":
		if m.cursor > 0 { m.cursor-- }
	case "down", "j":
		if m.cursor < len(subs)-1 { m.cursor++ }
	case "d", "delete":
		if len(subs) > 0 && m.cursor < len(subs) {
			sub := subs[m.cursor]
			m.confirmMode = true
			m.confirmLabel = fmt.Sprintf("Delete subscription from '%s'?", sub.group)
			m.confirmYes = false
			m.confirmAction = fmt.Sprintf("delete-sub|%s|%d", sub.group, sub.idx)
		}
	case "u":
		// Update all subs (direct)
		m.running = true
		return m, func() tea.Msg { return executeAction("sub-update", "") }
	case "p":
		// Update all subs via proxy (through current connection)
		m.running = true
		return m, func() tea.Msg {
			exe, _ := os.Executable()
			cmd := exec.Command(exe, "sub", "update")
			proxy := socksAddr()
			cmd.Env = append(os.Environ(),
				"http_proxy="+proxy,
				"https_proxy="+proxy,
				"ALL_PROXY="+proxy,
			)
			var buf bytes.Buffer
			cmd.Stdout = &buf
			cmd.Stderr = &buf
			err := cmd.Run()
			return actionDoneMsg{output: strings.TrimSpace(buf.String()), err: err}
		}
	case "enter":
		// Update single sub's group (direct)
		if len(subs) > 0 && m.cursor < len(subs) {
			sub := subs[m.cursor]
			m.running = true
			g := sub.group
			return m, func() tea.Msg {
				exe, _ := os.Executable()
				return runCmdCapture(exe, "sub", "update", "-g", g)
			}
		}
	case "o":
		// Update single sub's group via proxy
		if len(subs) > 0 && m.cursor < len(subs) {
			sub := subs[m.cursor]
			m.running = true
			g := sub.group
			return m, func() tea.Msg {
				exe, _ := os.Executable()
				cmd := exec.Command(exe, "sub", "update", "-g", g)
				proxy := socksAddr()
				cmd.Env = append(os.Environ(),
					"http_proxy="+proxy,
					"https_proxy="+proxy,
					"ALL_PROXY="+proxy,
				)
				var buf bytes.Buffer
				cmd.Stdout = &buf
				cmd.Stderr = &buf
				err := cmd.Run()
				return actionDoneMsg{output: strings.TrimSpace(buf.String()), err: err}
			}
		}
	case "r", "e":
		// Rename group
		if len(subs) > 0 && m.cursor < len(subs) {
			m.inputMode = true
			m.inputLabel = fmt.Sprintf("Rename group '%s' to", subs[m.cursor].group)
			m.inputBuf = subs[m.cursor].group
			m.inputAction = fmt.Sprintf("rename-group-%s", subs[m.cursor].group)
		}
	case "a":
		// Add new subscription
		m.inputMode = true
		m.inputLabel = "Subscription URL"
		m.inputBuf = ""
		m.inputAction = "sub-add"
	}
	return m, nil
}

// --- Confirm dialog handling ---

func (m model) handleConfirm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "left", "right", "h", "l", "tab":
		m.confirmYes = !m.confirmYes
	case "enter", " ":
		m.confirmMode = false
		m.confirmYesLabel = ""
		m.confirmNoLabel = ""
		if m.confirmYes {
			// Execute confirmed action
			switch {
			case m.confirmAction == "do-update-ask-method":
				// Ask download method: Direct or Over Bypath
				m.confirmMode = true
				m.confirmLabel = "Download method?"
				m.confirmYes = false // default on "Over Bypath"
				m.confirmAction = "do-update-method"
				m.confirmYesLabel = "Direct"
				m.confirmNoLabel = "Over Bypath"
				return m, nil
			case m.confirmAction == "do-update-method":
				// "Direct" selected (Yes)
				exe, _ := os.Executable()
				shellCmd := fmt.Sprintf(`clear; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo "  Bypath Self-Update (Direct)"; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo; %s update --direct; echo; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo "  ✅ Done. Press Enter to launch new version..."; read; exec %s`, exe, exe)
				cmd := exec.Command("bash", "-c", shellCmd)
				return m, tea.ExecProcess(cmd, func(err error) tea.Msg {
					return tea.Quit()
				})
			case m.confirmAction == "do-update":
				exe, _ := os.Executable()
				shellCmd := fmt.Sprintf(`clear; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo "  Bypath Self-Update"; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo; %s update; echo; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo "  ✅ Done. Press Enter to launch new version..."; read; exec %s`, exe, exe)
				cmd := exec.Command("bash", "-c", shellCmd)
				return m, tea.ExecProcess(cmd, func(err error) tea.Msg {
					return tea.Quit()
				})
			case strings.HasPrefix(m.confirmAction, "delete-group-"):
				groupName := strings.TrimPrefix(m.confirmAction, "delete-group-")
				groupPath := filepath.Join(paths.Get().ProfileDir, groupName+".json")
				os.Remove(groupPath)
				m.groups = findGroups()
				if m.activeGroup >= len(m.groups) {
					m.activeGroup = 0
				}
				m.cursor = 0
				m.showOutput = true
				m.output = fmt.Sprintf("✅ Group '%s' deleted", groupName)
				return m, nil
			case strings.HasPrefix(m.confirmAction, "delete-server|"):
				parts := strings.SplitN(strings.TrimPrefix(m.confirmAction, "delete-server|"), "|", 2)
				if len(parts) == 2 {
					group := parts[0]
					idx, _ := strconv.Atoi(parts[1])
					m.running = true
					return m, func() tea.Msg {
						exe, _ := os.Executable()
						return runCmdCapture(exe, "remove", fmt.Sprintf("%d", idx), "-g", group)
					}
				}
			case strings.HasPrefix(m.confirmAction, "delete-sub|"):
				parts := strings.SplitN(strings.TrimPrefix(m.confirmAction, "delete-sub|"), "|", 2)
				if len(parts) == 2 {
					group := parts[0]
					idx, _ := strconv.Atoi(parts[1])
					err := removeSubscription(group, idx)
					if err != nil {
						m.showOutput = true
						m.output = fmt.Sprintf("❌ %v", err)
					} else {
						m.showOutput = true
						m.output = fmt.Sprintf("✅ Removed from '%s'", group)
						if m.cursor > 0 { m.cursor-- }
					}
					return m, nil
				}
			case m.confirmAction == "restart-gateway":
				m.running = true
				return m, func() tea.Msg { return executeAction("restart", "") }
			case m.confirmAction == "stop-gateway":
				m.running = true
				return m, func() tea.Msg { return executeAction("stop", "") }
			}
		} else {
			// "No" selected
			if m.confirmAction == "do-update-method" {
				// "Over Bypath" selected (No)
				exe, _ := os.Executable()
				proxy := socksAddr()
				shellCmd := fmt.Sprintf(`clear; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo "  Bypath Self-Update (Over Bypath)"; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo; ALL_PROXY=%s %s update --proxy; echo; echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; echo "  ✅ Done. Press Enter to launch new version..."; read; exec %s`, proxy, exe, exe)
				cmd := exec.Command("bash", "-c", shellCmd)
				return m, tea.ExecProcess(cmd, func(err error) tea.Msg {
					return tea.Quit()
				})
			}
		}
		return m, nil
	case "esc", "q":
		m.confirmMode = false
		m.confirmYesLabel = ""
		m.confirmNoLabel = ""
		return m, nil
	case "n":
		// For download method dialog, "n" should not cancel — use esc for that
		if m.confirmAction == "do-update-method" {
			// Toggle to No (Over Bypath) and treat as selection
			m.confirmYes = false
			return m, nil
		}
		m.confirmMode = false
		m.confirmYesLabel = ""
		m.confirmNoLabel = ""
		return m, nil
	case "y":
		m.confirmYes = true
	}
	return m, nil
}

// --- Input handling ---

func (m model) handleInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		m.inputMode = false
		input := strings.TrimSpace(m.inputBuf)
		if input == "" { return m, nil }

		m.running = true
		action := m.inputAction
		return m, func() tea.Msg { return executeActionWithInput(action, input) }
	case tea.KeyEsc:
		m.inputMode = false
		m.inputBuf = ""
		return m, nil
	case tea.KeyBackspace, tea.KeyDelete:
		if len(m.inputBuf) > 0 {
			// Remove last rune (handles multi-byte chars)
			runes := []rune(m.inputBuf)
			m.inputBuf = string(runes[:len(runes)-1])
		}
	case tea.KeyCtrlU:
		m.inputBuf = ""
	case tea.KeyRunes:
		// Handles both single chars and pasted text (bracket paste)
		m.inputBuf += string(msg.Runes)
	default:
		// Fallback: accept any printable string representation
		s := msg.String()
		if len(s) > 0 && s[0] >= 32 {
			m.inputBuf += s
		}
	}
	return m, nil
}

// --- View ---

func (m model) View() string {
	var b strings.Builder

	// Header: logo + status
	status := statusOffStyle.Render("● STOPPED")
	if m.statusInfo == "running" {
		status = statusBarStyle.Render("● RUNNING")
	}
	b.WriteString(fmt.Sprintf(" %s  %s\n", logoStyle.Render("BYPATH"), status))

	// Active link
	if m.activeInfo != "" {
		b.WriteString(dimStyle.Render(fmt.Sprintf("  ⚡ %s", m.activeInfo)))
		b.WriteString("\n")
	}

	// Tabs
	b.WriteString("\n ")
	tabs := []string{"Home", "Servers", "Subscriptions"}
	for i, t := range tabs {
		if tab(i) == m.tab {
			b.WriteString(activeTabStyle.Render(t))
		} else {
			b.WriteString(inactiveTabStyle.Render(t))
		}
		b.WriteString(" ")
	}
	b.WriteString("\n")
	b.WriteString(dimStyle.Render(" ─────────────────────────────────────────────────"))
	b.WriteString("\n")

	// Confirm dialog overlay
	if m.confirmMode {
		b.WriteString(fmt.Sprintf("\n  %s\n\n", m.confirmLabel))
		yesLabel := "  Yes  "
		noLabel := "  No  "
		if m.confirmYesLabel != "" {
			yesLabel = "  " + m.confirmYesLabel + "  "
		}
		if m.confirmNoLabel != "" {
			noLabel = "  " + m.confirmNoLabel + "  "
		}
		var yes, no string
		if m.confirmYes {
			yes = activeTabStyle.Render(yesLabel)
			no = dimStyle.Render(noLabel)
		} else {
			yes = dimStyle.Render(yesLabel)
			no = activeTabStyle.Render(noLabel)
		}
		b.WriteString(fmt.Sprintf("       %s     %s\n\n", yes, no))
		b.WriteString(dimStyle.Render("  ←→ select • enter confirm • esc cancel"))
		b.WriteString("\n")
		return b.String()
	}

	// Input mode overlay
	if m.inputMode {
		b.WriteString(fmt.Sprintf("\n  %s:\n", m.inputLabel))
		b.WriteString(fmt.Sprintf("  > %s▌\n\n", m.inputBuf))
		b.WriteString(dimStyle.Render("  enter confirm • esc cancel"))
		b.WriteString("\n")
		return b.String()
	}

	// Running overlay
	if m.running {
		if m.cancelFn != nil {
			b.WriteString("\n  ⏳ Working...  " + dimStyle.Render("(esc to cancel)") + "\n")
		} else {
			b.WriteString("\n  ⏳ Working...\n")
		}
		return b.String()
	}

	// Output overlay (scrollable)
	if m.showOutput {
		b.WriteString("\n")
		lines := strings.Split(m.output, "\n")
		// Calculate visible area (leave room for header + footer)
		visibleLines := m.termHeight - 6
		if visibleLines < 5 {
			visibleLines = 20 // fallback if termHeight not set
		}
		// Clamp scroll
		maxScroll := len(lines) - visibleLines
		if maxScroll < 0 {
			maxScroll = 0
		}
		if m.outputScroll > maxScroll {
			m.outputScroll = maxScroll
		}
		// Render visible portion
		end := m.outputScroll + visibleLines
		if end > len(lines) {
			end = len(lines)
		}
		for _, line := range lines[m.outputScroll:end] {
			b.WriteString(outputStyle.Render(line))
			b.WriteString("\n")
		}
		b.WriteString("\n")
		scrollInfo := ""
		if len(lines) > visibleLines {
			scrollInfo = fmt.Sprintf(" (%d/%d)", m.outputScroll+1, len(lines))
		}
		b.WriteString(dimStyle.Render(fmt.Sprintf("  ↑↓ scroll • q/esc/enter close%s", scrollInfo)))
		b.WriteString("\n")
		return b.String()
	}

	// Tab content
	switch m.tab {
	case tabHome:
		b.WriteString(m.viewHome())
	case tabServers:
		b.WriteString(m.viewServers())
	case tabSubs:
		b.WriteString(m.viewSubs())
	}

	// Footer
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("  tab switch • ↑↓ navigate • enter select • q quit"))
	if m.updateInfo != "" {
		b.WriteString("\n")
		b.WriteString(updateStyle.Render("  " + m.updateInfo))
	}
	b.WriteString("\n")

	return b.String()
}

func (m model) viewHome() string {
	var b strings.Builder
	b.WriteString("\n")
	items := m.homeItems()
	for i, it := range items {
		line := fmt.Sprintf("  %s %s", it.icon, it.label)
		if i == m.cursor {
			b.WriteString(selectedStyle.Render(fmt.Sprintf("  ▸ %s %s", it.icon, it.label)))
		} else if it.action == "self-update" && m.updateInfo != "" {
			// Highlight update item in yellow when update is available
			b.WriteString(updateStyle.Render(line))
		} else {
			b.WriteString(itemStyle.Render(line))
		}
		b.WriteString("\n")
	}
	return b.String()
}

func (m model) viewServers() string {
	var b strings.Builder

	// Load active link info to highlight it
	activeGroup, activeRemark := getActiveLinkInfo()

	// Group tabs (mini) — show all including default
	b.WriteString("\n ")
	num := 0
	for i, g := range m.groups {
		label := g
		key := ""
		if g == "default" {
			key = "0"
		} else {
			num++
			key = fmt.Sprintf("%d", num)
		}
		if i == m.activeGroup {
			b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("11")).Render(fmt.Sprintf(" [%s:%s] ", key, label)))
		} else {
			b.WriteString(dimStyle.Render(fmt.Sprintf("  %s:%s  ", key, label)))
		}
	}
	b.WriteString("\n")

	// Links
	links := m.currentLinks()
	if len(links) == 0 {
		b.WriteString("\n  (no servers in this group)\n")
		b.WriteString("\n")
		b.WriteString(dimStyle.Render("  n new group • x del group • 0-9 switch"))
		b.WriteString("\n")
		return b.String()
	}

	currentGroup := ""
	if m.activeGroup < len(m.groups) {
		currentGroup = m.groups[m.activeGroup]
	}

	// Show bench results if available
	if m.benchRunning {
		b.WriteString("\n  ⏳ Testing...\n")
		return b.String()
	}

	if m.benchDone && len(m.benchResults) > 0 {
		// Sort results
		sorted := m.getSortedBenchResults()

		sortLabel := "▲ fastest"
		if !m.benchSortAsc {
			sortLabel = "▼ slowest"
		}

		// Show results table
		b.WriteString(headerStyle.Render(fmt.Sprintf("  %-4s %-6s %-3s %-14s %-5s %-7s %-7s %-8s %s", "#", "Proto", "🌐", "Server", "Port", "Ping", "Relay", "Down", "Name")))
		b.WriteString("\n")

		maxShow := 14
		start := 0
		if m.cursor >= maxShow { start = m.cursor - maxShow + 1 }
		end := start + maxShow
		if end > len(sorted) { end = len(sorted) }

		for i := start; i < end; i++ {
			e := sorted[i]
			proto := e.protocol
			if proto == "shadowsocks" { proto = "ss" }
			server := e.address
			if len(server) > 12 { server = server[:9] + "..." }

			pingStr, relayStr, downStr := "—", "—", "—"
			if e.ping > 0 { pingStr = fmt.Sprintf("%dms", e.ping) }
			if e.relay > 0 { relayStr = fmt.Sprintf("%dms", e.relay) }
			if e.down > 0 { downStr = fmt.Sprintf("%dKB", e.down) }
			if e.status == benchFailed { pingStr = "✗"; relayStr = "✗"; downStr = "✗" }

			name := e.remark
			if len([]rune(name)) > 14 { name = string([]rune(name)[:14]) }

			isActive := currentGroup == activeGroup && e.remark == activeRemark
			line := fmt.Sprintf("%-4d %-6s %-3s %-14s %-5d %-7s %-7s %-8s %s", e.idx, proto, e.flag, server, e.port, pingStr, relayStr, downStr, name)

			if i == m.cursor {
				b.WriteString(selectedStyle.Render("  ▸ " + line))
			} else if isActive {
				b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Render("  ⚡" + line))
			} else if e.status == benchDone && e.relay > 0 {
				b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render("  " + line))
			} else if e.status == benchFailed {
				b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render("  " + line))
			} else {
				b.WriteString(itemStyle.Render("  " + line))
			}
			b.WriteString("\n")
		}

		b.WriteString("\n")
		b.WriteString(dimStyle.Render(fmt.Sprintf("  enter select • p ping • s full test • t single • f sort (%s) • d del • esc clear", sortLabel)))
		b.WriteString("\n")
		return b.String()
	}

	// Normal server list (no bench results)
	b.WriteString(headerStyle.Render(fmt.Sprintf("  %-4s %-7s %-3s %-20s %-6s %s", "#", "Proto", "🌐", "Server", "Port", "Name")))
	b.WriteString("\n")

	maxShow := 15
	start := 0
	if m.cursor >= maxShow { start = m.cursor - maxShow + 1 }
	end := start + maxShow
	if end > len(links) { end = len(links) }

	for i := start; i < end; i++ {
		l := links[i]
		// Check if this is the active link
		isActive := currentGroup == activeGroup && l.remark == activeRemark
		activeMarker := "  "
		if isActive {
			activeMarker = "⚡"
		}

		name := l.remark
		if len([]rune(name)) > 18 { name = string([]rune(name)[:18]) }

		line := fmt.Sprintf("%s%-4d %-7s %-3s %-20s %-6d %s", activeMarker, l.idx, l.proto, l.flag, l.server, l.port, name)
		if i == m.cursor {
			b.WriteString(selectedStyle.Render("  ▸ " + line))
		} else if isActive {
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Render("  " + line))
		} else {
			b.WriteString(itemStyle.Render("  " + line))
		}
		b.WriteString("\n")
	}

	if len(links) > maxShow {
		b.WriteString(dimStyle.Render(fmt.Sprintf("  ... %d/%d (scroll ↑↓)", maxShow, len(links))))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("  0-9 group • enter select • p ping • s full test • t single • d del • x del group • n new"))
	b.WriteString("\n")
	return b.String()
}

func getActiveLinkInfo() (group, remark string) {
	data, err := os.ReadFile(filepath.Join(paths.Get().ProfileDir, ".active"))
	if err != nil { return "", "" }
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 { return "", "" }
	return strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1])
}

func (m model) viewSubs() string {
	var b strings.Builder
	subs := loadSubscriptions()

	if len(subs) == 0 {
		b.WriteString("\n  No subscriptions. Go to Home → Add Subscription.\n")
		return b.String()
	}

	b.WriteString("\n")
	for i, s := range subs {
		url := s.url
		if len(url) > 45 { url = url[:42] + "..." }
		line := fmt.Sprintf("[%s] %s", s.group, url)
		if i == m.cursor {
			b.WriteString(selectedStyle.Render("  ▸ " + line))
		} else {
			b.WriteString(itemStyle.Render("  " + line))
		}
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("  enter update • o update(proxy) • u all • p all(proxy) • a add • r rename • d del"))
	b.WriteString("\n")
	return b.String()
}

// --- Data loading ---

type linkEntry struct {
	idx    int
	proto  string
	flag   string
	server string
	port   int
	remark string
}

func loadGroupLinks(group string) []linkEntry {
	data, err := os.ReadFile(filepath.Join(paths.Get().ProfileDir, group+".json"))
	if err != nil { return nil }

	var g struct {
		Links []struct {
			Remark   string `json:"remark"`
			Protocol string `json:"protocol"`
			Address  string `json:"address"`
			Port     int    `json:"port"`
		} `json:"links"`
	}
	if json.Unmarshal(data, &g) != nil { return nil }

	var entries []linkEntry
	for i, l := range g.Links {
		if l.Port < 10 || l.Address == "" || l.Address == "0.0.0.0" { continue }
		proto := l.Protocol
		if proto == "shadowsocks" { proto = "ss" }
		if proto == "wireguard" { proto = "wg" }
		flag := extractFlagFromRemark(l.Remark)
		server := l.Address
		if len(server) > 18 { server = server[:15] + "..." }
		entries = append(entries, linkEntry{
			idx: i + 1, proto: proto, flag: flag,
			server: server, port: l.Port, remark: l.Remark,
		})
	}
	return entries
}

func extractFlagFromRemark(remark string) string {
	runes := []rune(remark)
	for i := 0; i < len(runes)-1; i++ {
		if runes[i] >= 0x1F1E6 && runes[i] <= 0x1F1FF && runes[i+1] >= 0x1F1E6 && runes[i+1] <= 0x1F1FF {
			return string(runes[i : i+2])
		}
	}
	return "🌐"
}

type subEntry struct {
	group string
	url   string
	idx   int
}

func loadSubscriptions() []subEntry {
	groups := findGroups()
	var subs []subEntry
	for _, group := range groups {
		data, err := os.ReadFile(filepath.Join(paths.Get().ProfileDir, group+".json"))
		if err != nil { continue }
		var g struct { Subscriptions []string `json:"subscriptions"` }
		if json.Unmarshal(data, &g) != nil { continue }
		for i, url := range g.Subscriptions {
			subs = append(subs, subEntry{group: group, url: url, idx: i})
		}
	}
	return subs
}

func findGroups() []string {
	entries, err := os.ReadDir(paths.Get().ProfileDir)
	if err != nil { return nil }
	var groups []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			groups = append(groups, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	return groups
}

// --- Actions ---

func executeLiveStatus(ctx context.Context) actionDoneMsg {
	start := time.Now()
	cmd := exec.CommandContext(ctx, "curl", "-s", "-x", socksAddr(),
		"--connect-timeout", "8", "--max-time", "12", "https://1.1.1.1/cdn-cgi/trace")
	out, err := cmd.Output()
	elapsed := time.Since(start).Milliseconds()

	if ctx.Err() != nil {
		return actionDoneMsg{output: "⚠️  Cancelled"}
	}
	if err != nil || len(strings.TrimSpace(string(out))) == 0 {
		return actionDoneMsg{output: "❌ Connection failed (no relay)"}
	}

	// Parse ip= and loc= from Cloudflare trace — country comes free, no extra request needed.
	exitIP, countryCode := "", ""
	for _, line := range strings.Split(string(out), "\n") {
		switch {
		case strings.HasPrefix(line, "ip="):
			exitIP = strings.TrimSpace(strings.TrimPrefix(line, "ip="))
		case strings.HasPrefix(line, "loc="):
			countryCode = strings.TrimSpace(strings.TrimPrefix(line, "loc="))
		}
	}
	if exitIP == "" {
		return actionDoneMsg{output: "❌ Could not parse exit IP from response"}
	}

	// ISP lookup: direct (no proxy) — we already confirmed the tunnel works,
	// and ip-api.com might be in bypass_domains so going through proxy is unreliable.
	isp := ""
	geoCmd := exec.CommandContext(ctx, "curl", "-s",
		"--connect-timeout", "5", "--max-time", "8",
		fmt.Sprintf("http://ip-api.com/json/%s?fields=isp", exitIP))
	if geoOut, geoErr := geoCmd.Output(); geoErr == nil && ctx.Err() == nil {
		var geo struct{ ISP string `json:"isp"` }
		if json.Unmarshal(geoOut, &geo) == nil {
			isp = geo.ISP
		}
	}

	activeData, _ := os.ReadFile(filepath.Join(paths.Get().ProfileDir, ".active"))
	lines := strings.Split(strings.TrimSpace(string(activeData)), "\n")
	activeStr := ""
	if len(lines) >= 2 {
		activeStr = fmt.Sprintf("%s / %s", strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1]))
	}

	return actionDoneMsg{output: fmt.Sprintf("✅ Gateway is RUNNING\n\n"+
		"  Server:   %s\n"+
		"  Relay:    %dms\n"+
		"  Exit IP:  %s\n"+
		"  Country:  %s\n"+
		"  ISP:      %s",
		activeStr, elapsed, exitIP, countryCode, isp)}
}

func executeAction(action, group string) actionDoneMsg {
	exe, _ := os.Executable()
	switch action {
	case "sub-update":
		return runCmdCapture(exe, "sub", "update")
	case "start":
		logFile, err := os.OpenFile("./bypath.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil { return actionDoneMsg{err: fmt.Errorf("log: %w", err)} }
		cmd := exec.Command(exe, "run")
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		setSysProcAttr(cmd)
		if err := cmd.Start(); err != nil {
			logFile.Close()
			return actionDoneMsg{err: fmt.Errorf("start: %w", err)}
		}
		pid := cmd.Process.Pid
		cmd.Process.Release()
		logFile.Close()
		time.Sleep(3 * time.Second)
		if isProcessRunning(pid) {
			return actionDoneMsg{output: fmt.Sprintf("✅ Gateway started (PID: %d)", pid)}
		}
		logData, _ := os.ReadFile("./bypath.log")
		lines := strings.Split(string(logData), "\n")
		if len(lines) > 5 { lines = lines[len(lines)-5:] }
		return actionDoneMsg{output: "❌ Gateway failed:\n" + strings.Join(lines, "\n")}
	case "restart":
		// Stop first, then start
		runCmdCapture(exe, "stop")
		time.Sleep(2 * time.Second)
		logFile, err := os.OpenFile("./bypath.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil { return actionDoneMsg{err: fmt.Errorf("log: %w", err)} }
		cmd := exec.Command(exe, "run")
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		setSysProcAttr(cmd)
		if err := cmd.Start(); err != nil {
			logFile.Close()
			return actionDoneMsg{err: fmt.Errorf("start: %w", err)}
		}
		pid := cmd.Process.Pid
		cmd.Process.Release()
		logFile.Close()
		time.Sleep(3 * time.Second)
		if isProcessRunning(pid) {
			return actionDoneMsg{output: fmt.Sprintf("✅ Gateway restarted (PID: %d)", pid)}
		}
		logData, _ := os.ReadFile("./bypath.log")
		lines := strings.Split(string(logData), "\n")
		if len(lines) > 5 { lines = lines[len(lines)-5:] }
		return actionDoneMsg{output: "❌ Restart failed:\n" + strings.Join(lines, "\n")}
	case "stop":
		return runCmdCapture(exe, "stop")
	case "live-status":
		return actionDoneMsg{output: "internal: use executeLiveStatus"}
	case "status":
		return runCmdCapture(exe, "version")
	case "autostart-toggle":
		// Check if systemd service is enabled
		cmd := exec.Command("systemctl", "is-enabled", "bypath")
		out, _ := cmd.Output()
		enabled := strings.TrimSpace(string(out)) == "enabled"
		if enabled {
			cmd = exec.Command("systemctl", "disable", "bypath")
			var buf bytes.Buffer
			cmd.Stdout = &buf
			cmd.Stderr = &buf
			err := cmd.Run()
			if err != nil {
				return actionDoneMsg{output: fmt.Sprintf("❌ Failed to disable: %v\n%s", err, buf.String())}
			}
			return actionDoneMsg{output: "✅ Auto start DISABLED (systemctl disable bypath)"}
		}
		cmd = exec.Command("systemctl", "enable", "bypath")
		var buf bytes.Buffer
		cmd.Stdout = &buf
		cmd.Stderr = &buf
		err := cmd.Run()
		if err != nil {
			return actionDoneMsg{output: fmt.Sprintf("❌ Failed to enable: %v\n%s", err, buf.String())}
		}
		return actionDoneMsg{output: "✅ Auto start ENABLED (systemctl enable bypath)"}
	case "self-update":
		return actionDoneMsg{output: "Use TUI home action for update"}
	case "change-engine":
		return changeEngine()
	default:
		return actionDoneMsg{output: "Unknown: " + action}
	}
}

func executeActionWithInput(action, input string) actionDoneMsg {
	exe, _ := os.Executable()
	switch action {
	case "sub-add":
		result := runCmdCapture(exe, "sub", "add", input)
		if result.err == nil {
			update := runCmdCapture(exe, "sub", "update")
			result.output += "\n" + update.output
		}
		return result
	case "add-link":
		return runCmdCapture(exe, "add", input)
	case "change-port":
		return changeSOCKSPort(input)
	case "create-group":
		name := strings.TrimSpace(input)
		if name == "" { return actionDoneMsg{output: "No name"} }
		// Create empty group JSON
		path := filepath.Join(paths.Get().ProfileDir, name+".json")
		if _, err := os.Stat(path); err == nil {
			return actionDoneMsg{output: fmt.Sprintf("❌ Group '%s' already exists", name)}
		}
		data := fmt.Sprintf(`{"name":"%s","type":"basic","links":[],"subscriptions":[]}`, name)
		if err := os.WriteFile(path, []byte(data), 0644); err != nil {
			return actionDoneMsg{output: fmt.Sprintf("❌ %v", err)}
		}
		return actionDoneMsg{output: fmt.Sprintf("✅ Group '%s' created", name)}
	default:
		// Handle rename-group-<oldname>
		if strings.HasPrefix(action, "rename-group-") {
			oldName := strings.TrimPrefix(action, "rename-group-")
			newName := strings.TrimSpace(input)
			if newName == "" || newName == oldName {
				return actionDoneMsg{output: "No change"}
			}
			err := renameGroup(oldName, newName)
			if err != nil {
				return actionDoneMsg{output: fmt.Sprintf("❌ %v", err)}
			}
			return actionDoneMsg{output: fmt.Sprintf("✅ Renamed '%s' → '%s'", oldName, newName), targetGroup: newName}
		}
		return actionDoneMsg{output: "Unknown action"}
	}
}

func runCmdCapture(name string, args ...string) actionDoneMsg {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return actionDoneMsg{output: strings.TrimSpace(buf.String()), err: err}
}

func isProcessRunning(pid int) bool {
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil { return true }
	return false
}

// isGatewayRunning checks if bypath gateway is currently running
func isGatewayRunning() bool {
	// Check systemd first
	out, err := exec.Command("systemctl", "is-active", "bypath").Output()
	if err == nil && strings.TrimSpace(string(out)) == "active" {
		return true
	}
	// Check pgrep
	out, err = exec.Command("pgrep", "-f", "bypath run").Output()
	if err == nil && len(strings.TrimSpace(string(out))) > 0 {
		return true
	}
	return false
}

// restartGateway restarts the gateway (prefers systemctl, falls back to manual)
func restartGateway(exe string) {
	// Try systemctl restart first
	cmd := exec.Command("systemctl", "is-active", "bypath")
	out, _ := cmd.Output()
	if strings.TrimSpace(string(out)) == "active" {
		exec.Command("systemctl", "restart", "bypath").Run()
		time.Sleep(3 * time.Second)
		return
	}
	// Manual restart
	runCmdCapture(exe, "stop")
	// Wait until the SOCKS port is released (engines killed with -9 die fast).
	// Falls back to a hard 3s ceiling so we never block indefinitely.
	port := socksPort()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err != nil {
			break // port is free
		}
		conn.Close()
		time.Sleep(200 * time.Millisecond)
	}
	logFile, _ := os.OpenFile("./bypath.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	cmd2 := exec.Command(exe, "run")
	cmd2.Stdout = logFile
	cmd2.Stderr = logFile
	setSysProcAttr(cmd2)
	cmd2.Start()
	cmd2.Process.Release()
	logFile.Close()
	time.Sleep(3 * time.Second)
}

func removeSubscription(group string, idx int) error {
	path := filepath.Join(paths.Get().ProfileDir, group+".json")
	data, err := os.ReadFile(path)
	if err != nil { return err }
	var g map[string]interface{}
	if err := json.Unmarshal(data, &g); err != nil { return err }
	subsRaw, ok := g["subscriptions"]
	if !ok { return fmt.Errorf("no subscriptions") }
	subs, ok := subsRaw.([]interface{})
	if !ok || idx >= len(subs) { return fmt.Errorf("invalid index") }
	subs = append(subs[:idx], subs[idx+1:]...)
	g["subscriptions"] = subs
	newData, _ := json.MarshalIndent(g, "", "  ")
	return os.WriteFile(path, newData, 0644)
}

// renameGroup renames a group by renaming its JSON file and updating the name field.
func renameGroup(oldName, newName string) error {
	oldPath := filepath.Join(paths.Get().ProfileDir, oldName+".json")
	newPath := filepath.Join(paths.Get().ProfileDir, newName+".json")

	// Check old exists
	if _, err := os.Stat(oldPath); err != nil {
		return fmt.Errorf("group '%s' not found", oldName)
	}
	// Check new doesn't exist
	if _, err := os.Stat(newPath); err == nil {
		return fmt.Errorf("group '%s' already exists", newName)
	}

	// Read, update name, write to new path
	data, err := os.ReadFile(oldPath)
	if err != nil { return err }

	var g map[string]interface{}
	if err := json.Unmarshal(data, &g); err != nil { return err }
	g["name"] = newName

	newData, _ := json.MarshalIndent(g, "", "  ")
	if err := os.WriteFile(newPath, newData, 0644); err != nil { return err }

	// Remove old file
	os.Remove(oldPath)

	// Update .active if it references old group
	activeData, err := os.ReadFile(filepath.Join(paths.Get().ProfileDir, ".active"))
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(activeData)), "\n")
		if len(lines) >= 2 && strings.TrimSpace(lines[0]) == oldName {
			newActive := newName + "\n" + lines[1]
			os.WriteFile(filepath.Join(paths.Get().ProfileDir, ".active"), []byte(newActive), 0644)
		}
	}

	return nil
}

// changeEngine cycles through engine options: auto → sing-box → xray → auto
func changeEngine() actionDoneMsg {
	configPath := paths.Get().ConfigFile
	data, err := os.ReadFile(configPath)
	if err != nil {
		return actionDoneMsg{output: fmt.Sprintf("❌ Cannot read config: %v", err)}
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	// Find current preferred engine
	current := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "preferred:") {
			current = strings.TrimSpace(strings.TrimPrefix(trimmed, "preferred:"))
			current = strings.Trim(current, "\"'")
			break
		}
	}

	// Cycle: "" (auto/sing-box) → "xray" → "sing-box" → "" (auto)
	var next string
	switch current {
	case "", "sing-box":
		next = "xray"
	case "xray":
		next = "sing-box"
	default:
		next = "xray"
	}

	// Update or add preferred line
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "preferred:") {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			lines[i] = fmt.Sprintf("%spreferred: \"%s\"", indent, next)
			found = true
			break
		}
	}

	if !found {
		// Add after "prefer_system:" or "directory:" in engines section
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "prefer_system:") || strings.HasPrefix(trimmed, "directory:") {
				indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
				newLine := fmt.Sprintf("%spreferred: \"%s\"", indent, next)
				lines = append(lines[:i+1], append([]string{newLine}, lines[i+1:]...)...)
				break
			}
		}
	}

	newContent := strings.Join(lines, "\n")
	if err := os.WriteFile(configPath, []byte(newContent), 0644); err != nil {
		return actionDoneMsg{output: fmt.Sprintf("❌ Cannot write config: %v", err)}
	}

	label := next
	if label == "" {
		label = "auto (sing-box)"
	}
	return actionDoneMsg{output: fmt.Sprintf("✅ Engine changed to: %s\nRestart gateway to apply.", label)}
}

// changeSOCKSPort updates the socks_port in the config file.
func changeSOCKSPort(input string) actionDoneMsg {
	// Parse port number
	port := 0
	for _, ch := range input {
		if ch >= '0' && ch <= '9' {
			port = port*10 + int(ch-'0')
		}
	}
	if port < 1 || port > 65535 {
		return actionDoneMsg{output: "❌ Invalid port (must be 1-65535)"}
	}

	configPath := paths.Get().ConfigFile
	data, err := os.ReadFile(configPath)
	if err != nil {
		return actionDoneMsg{output: fmt.Sprintf("❌ Cannot read config: %v", err)}
	}

	content := string(data)

	// Replace or add socks_port line
	lines := strings.Split(content, "\n")
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "socks_port:") {
			// Preserve indentation
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			lines[i] = fmt.Sprintf("%ssocks_port: %d", indent, port)
			found = true
			break
		}
	}

	if !found {
		// Add after dns_port line
		for i, line := range lines {
			if strings.Contains(line, "dns_port:") {
				indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
				newLine := fmt.Sprintf("%ssocks_port: %d", indent, port)
				lines = append(lines[:i+1], append([]string{newLine}, lines[i+1:]...)...)
				break
			}
		}
	}

	newContent := strings.Join(lines, "\n")
	if err := os.WriteFile(configPath, []byte(newContent), 0644); err != nil {
		return actionDoneMsg{output: fmt.Sprintf("❌ Cannot write config: %v", err)}
	}

	return actionDoneMsg{output: fmt.Sprintf("✅ Port changed to %d. Restart gateway to apply.", port)}
}
