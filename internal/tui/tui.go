// Package tui provides an interactive terminal UI using bubbletea.
package tui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/liberoute/bypath/internal/updater"
)

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("14")).Padding(1, 2)
	subtitleStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("6")).PaddingLeft(4)
	itemStyle     = lipgloss.NewStyle().PaddingLeft(4)
	selectedStyle = lipgloss.NewStyle().PaddingLeft(2).Foreground(lipgloss.Color("10")).Bold(true)
	dimStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	errorMsgStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).PaddingLeft(4)
	successStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).PaddingLeft(4)
	outputStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("7")).PaddingLeft(4)
	updateStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).PaddingLeft(4).Bold(true)
)

type item struct {
	icon  string
	label string
	id    string
}

type page int

const (
	pageMain page = iota
	pageLinks
	pageOutput
)

// actionDoneMsg is sent when a background action completes.
type actionDoneMsg struct {
	output string
	err    error
}

type model struct {
	page        page
	items       []item
	cursor      int
	title       string
	subtitle    string
	group       string
	output      string // output text shown on pageOutput
	running     bool   // true while an action is executing
	inputMode   bool   // true when waiting for user text input
	inputBuf    string // text input buffer
	inputLabel  string // prompt label for input
	inputAction string // action to run after input
	updateInfo  string // update notification (empty = no update)
}

type Menu struct{}

func New() *Menu { return &Menu{} }

func (m *Menu) Run() {
	mdl := newMainPage()
	p := tea.NewProgram(mdl, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}

func newMainPage() model {
	m := model{
		page:  pageMain,
		title: "BYPATH",
		items: []item{
			{"📡", "Add subscription", "sub-add"},
			{"🔄", "Update subscriptions", "sub-update"},
			{"✅", "Select server", "select"},
			{"🏁", "Speed test (bench)", "bench"},
			{"🚀", "Start gateway", "start"},
			{"🛑", "Stop gateway", "stop"},
			{"📊", "Status", "status"},
			{"👋", "Quit", "quit"},
		},
	}

	// Background update check (non-blocking)
	go func() {
		result, err := updater.Check()
		if err == nil && result.Available {
			m.updateInfo = fmt.Sprintf("🆕 Update available: %s → %s", result.CurrentVersion, result.LatestVersion)
		}
	}()

	return m
}

func newLinksPage(group string) model {
	links := loadGroupLinks(group)
	items := make([]item, 0, len(links)+1)
	for _, l := range links {
		items = append(items, item{l.flag, l.label, fmt.Sprintf("pick-%d", l.idx)})
	}
	items = append(items, item{"⬅️", "Back", "back"})

	return model{
		page:     pageLinks,
		title:    "Select Server",
		subtitle: fmt.Sprintf("Group: %s • %d servers", group, len(links)),
		items:    items,
		group:    group,
	}
}

type linkEntry struct {
	idx   int
	flag  string
	label string
}

func loadGroupLinks(group string) []linkEntry {
	data, err := os.ReadFile(fmt.Sprintf("./data/profiles/%s.json", group))
	if err != nil {
		return nil
	}

	var g struct {
		Links []struct {
			Remark   string `json:"remark"`
			Protocol string `json:"protocol"`
			Address  string `json:"address"`
			Port     int    `json:"port"`
		} `json:"links"`
	}
	if json.Unmarshal(data, &g) != nil {
		return nil
	}

	var entries []linkEntry
	for i, l := range g.Links {
		proto := l.Protocol
		if proto == "shadowsocks" {
			proto = "ss"
		}
		flag := extractFlagFromRemark(l.Remark)
		server := l.Address
		if len(server) > 18 {
			server = server[:15] + "..."
		}
		label := fmt.Sprintf("%-6s %s %-18s :%d", proto, flag, server, l.Port)
		entries = append(entries, linkEntry{idx: i + 1, flag: "", label: label})
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

// --- Tea interface ---

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case actionDoneMsg:
		m.running = false
		m.page = pageOutput
		m.output = msg.output
		if msg.err != nil {
			m.output += "\n" + errorMsgStyle.Render(fmt.Sprintf("Error: %v", msg.err))
		}
		return m, nil

	case tea.KeyMsg:
		// If in input mode, handle text input
		if m.inputMode {
			return m.handleInput(msg)
		}

		// If on output page, any key goes back to main
		if m.page == pageOutput {
			switch msg.String() {
			case "q", "ctrl+c":
				return m, tea.Quit
			default:
				return newMainPage(), nil
			}
		}

		// Don't accept input while running
		if m.running {
			if msg.String() == "q" || msg.String() == "ctrl+c" {
				return m, tea.Quit
			}
			return m, nil
		}

		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "esc":
			if m.page == pageMain {
				return m, tea.Quit
			}
			return newMainPage(), nil
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			}
		case "enter", " ":
			return m.handleSelect()
		}
	}
	return m, nil
}

func (m model) handleSelect() (tea.Model, tea.Cmd) {
	selected := m.items[m.cursor]

	switch selected.id {
	case "quit":
		return m, tea.Quit
	case "back":
		return newMainPage(), nil
	case "select":
		groups := findGroups()
		if len(groups) == 0 {
			m.page = pageOutput
			m.output = errorMsgStyle.Render("No groups found. Add a subscription first.")
			return m, nil
		}
		return newLinksPage(groups[0]), nil
	case "sub-add":
		m.inputMode = true
		m.inputLabel = "Subscription URL"
		m.inputBuf = ""
		m.inputAction = "sub-add"
		return m, nil
	case "bench":
		// Open bench TUI page
		groups := findGroups()
		if len(groups) == 0 {
			m.page = pageOutput
			m.output = errorMsgStyle.Render("No groups found.")
			return m, nil
		}
		return newBenchModel(groups[0]), newBenchModel(groups[0]).Init()
	default:
		// All other actions run in background and show output
		m.running = true
		action := selected.id
		group := m.group
		return m, func() tea.Msg {
			return executeAction(action, group)
		}
	}
}

func (m model) handleInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		m.inputMode = false
		url := strings.TrimSpace(m.inputBuf)
		if url == "" {
			return newMainPage(), nil
		}
		m.running = true
		action := m.inputAction
		input := url
		return m, func() tea.Msg {
			return executeActionWithInput(action, input)
		}
	case "esc":
		m.inputMode = false
		m.inputBuf = ""
		return m, nil
	case "backspace", "ctrl+h":
		if len(m.inputBuf) > 0 {
			m.inputBuf = m.inputBuf[:len(m.inputBuf)-1]
		}
	case "ctrl+u":
		m.inputBuf = ""
	default:
		// Only add printable characters
		if len(msg.String()) == 1 || strings.HasPrefix(msg.String(), "http") {
			m.inputBuf += msg.String()
		}
	}
	return m, nil
}

func (m model) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render(m.title))
	b.WriteString("\n")

	// Input mode
	if m.inputMode {
		b.WriteString(subtitleStyle.Render(fmt.Sprintf("%s:", m.inputLabel)))
		b.WriteString("\n\n")
		b.WriteString(itemStyle.Render(fmt.Sprintf("  > %s▌", m.inputBuf)))
		b.WriteString("\n\n")
		b.WriteString(dimStyle.Render("   enter confirm • esc cancel"))
		b.WriteString("\n")
		return b.String()
	}

	// Running indicator
	if m.running {
		b.WriteString("\n")
		b.WriteString(subtitleStyle.Render("⏳ Running..."))
		b.WriteString("\n")
		return b.String()
	}

	// Output page
	if m.page == pageOutput {
		b.WriteString("\n")
		b.WriteString(outputStyle.Render(m.output))
		b.WriteString("\n\n")
		b.WriteString(dimStyle.Render("   press any key to continue"))
		b.WriteString("\n")
		return b.String()
	}

	// Normal menu
	if m.subtitle != "" {
		b.WriteString(subtitleStyle.Render(m.subtitle))
		b.WriteString("\n")
	}
	b.WriteString("\n")

	for i, it := range m.items {
		icon := it.icon
		if icon != "" {
			icon += " "
		}
		if i == m.cursor {
			b.WriteString(selectedStyle.Render(fmt.Sprintf(" ▸ %s%s", icon, it.label)))
		} else {
			b.WriteString(itemStyle.Render(fmt.Sprintf("   %s%s", icon, it.label)))
		}
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("   ↑↓ navigate • enter select • esc back • q quit"))
	b.WriteString("\n")

	// Show update notification at bottom
	if m.updateInfo != "" {
		b.WriteString("\n")
		b.WriteString(updateStyle.Render(m.updateInfo))
		b.WriteString("\n")
	}

	return b.String()
}

// --- Action execution (runs in background, returns result) ---

func executeAction(action, group string) actionDoneMsg {
	exe, _ := os.Executable()

	switch action {
	case "sub-update":
		return runCmdCapture(exe, "sub", "update")

	case "start":
		logFile, err := os.OpenFile("./bypath.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			return actionDoneMsg{err: fmt.Errorf("opening log: %w", err)}
		}
		cmd := exec.Command(exe, "run")
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		setSysProcAttr(cmd)
		if err := cmd.Start(); err != nil {
			logFile.Close()
			return actionDoneMsg{err: fmt.Errorf("starting gateway: %w", err)}
		}
		pid := cmd.Process.Pid
		cmd.Process.Release()
		logFile.Close()

		// Wait a moment and check if it's still running
		time.Sleep(2 * time.Second)
		if isProcessRunning(pid) {
			return actionDoneMsg{output: fmt.Sprintf("✅ Gateway started (PID: %d)\n📄 Log: ./bypath.log", pid)}
		}
		// Read last few lines of log for error info
		logData, _ := os.ReadFile("./bypath.log")
		lines := strings.Split(string(logData), "\n")
		tail := lines
		if len(tail) > 5 {
			tail = tail[len(tail)-5:]
		}
		return actionDoneMsg{output: fmt.Sprintf("❌ Gateway exited quickly.\nLog:\n%s", strings.Join(tail, "\n"))}

	case "stop":
		exec.Command("pkill", "-f", "bypath run").Run()
		exec.Command("pkill", "sing-box").Run()
		exec.Command("pkill", "dns2socks").Run()
		exec.Command("pkill", "tun2socks").Run()
		exec.Command("ip", "link", "del", "tun0").Run()
		exec.Command("iptables", "-t", "mangle", "-F", "PREROUTING").Run()
		exec.Command("iptables", "-t", "nat", "-F", "POSTROUTING").Run()
		exec.Command("iptables", "-F", "FORWARD").Run()
		exec.Command("ip", "rule", "del", "fwmark", "0x1", "lookup", "100").Run()
		return actionDoneMsg{output: "✅ Gateway stopped"}

	case "status":
		out := runCmdCapture(exe, "version")
		pgrep, _ := exec.Command("pgrep", "-f", "bypath run").Output()
		if len(strings.TrimSpace(string(pgrep))) > 0 {
			out.output += fmt.Sprintf("\n\n🟢 Gateway is RUNNING (PID: %s)", strings.TrimSpace(string(pgrep)))
		} else {
			out.output += "\n\n🔴 Gateway is STOPPED"
		}
		return out

	default:
		if strings.HasPrefix(action, "pick-") {
			num := strings.TrimPrefix(action, "pick-")
			return runCmdCapture(exe, "select", num)
		}
		return actionDoneMsg{output: "Unknown action: " + action}
	}
}

func executeActionWithInput(action, input string) actionDoneMsg {
	exe, _ := os.Executable()

	switch action {
	case "sub-add":
		result := runCmdCapture(exe, "sub", "add", input)
		if result.err == nil {
			// Auto-update after adding
			update := runCmdCapture(exe, "sub", "update")
			result.output += "\n" + update.output
		}
		return result
	default:
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
	// Check /proc/<pid> on Linux, or just try FindProcess
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil {
		return true
	}
	// Fallback: try to find process
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = proc
	return false
}

// --- Helpers ---

func findGroups() []string {
	entries, err := os.ReadDir("./data/profiles")
	if err != nil {
		return nil
	}
	var groups []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			groups = append(groups, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	return groups
}
