package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mattn/go-runewidth"
)

// --- Bench TUI page ---

type benchStatus int

const (
	benchWaiting benchStatus = iota
	benchTesting
	benchDone
	benchFailed
)

type benchEntry struct {
	idx      int
	remark   string
	protocol string
	address  string
	port     int
	flag     string
	status   benchStatus
	ping     int // ms, -1 = fail
	relay    int // ms, -1 = fail
	download float64 // KB/s, 0 = not tested
}

type sortMode int

const (
	sortByIndex sortMode = iota
	sortByPing
	sortByRelay
	sortByDownload
)

type benchModel struct {
	entries  []benchEntry
	cursor   int
	sortBy   sortMode
	done     bool
	selected int // index of selected entry, -1 = none
	group    string
}

// Messages
type benchTickMsg struct{}
type benchDoneMsg struct {
	results []benchEntry
}

var (
	benchHeaderStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("14"))
	benchRowStyle     = lipgloss.NewStyle()
	benchActiveStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	benchOkStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	benchFailStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	benchCursorStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))
	benchDimStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	benchSortStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
)

func newBenchModel(group string) benchModel {
	entries := loadBenchEntries(group)
	return benchModel{
		entries:  entries,
		cursor:   0,
		sortBy:   sortByIndex,
		done:     false,
		selected: -1,
		group:    group,
	}
}

func loadBenchEntries(group string) []benchEntry {
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

	var entries []benchEntry
	for i, l := range g.Links {
		if l.Port < 10 || l.Address == "" {
			continue
		}
		flag := extractFlagFromRemark(l.Remark)
		entries = append(entries, benchEntry{
			idx:      i + 1,
			remark:   cleanRemarkForBench(l.Remark),
			protocol: l.Protocol,
			address:  l.Address,
			port:     l.Port,
			flag:     flag,
			status:   benchWaiting,
			ping:     -1,
			relay:    -1,
		})
	}
	return entries
}

func cleanRemarkForBench(remark string) string {
	// Remove flags and trim
	runes := []rune(remark)
	var clean []rune
	for i := 0; i < len(runes); i++ {
		if runes[i] >= 0x1F1E6 && runes[i] <= 0x1F1FF {
			i++
			continue
		}
		clean = append(clean, runes[i])
	}
	name := strings.TrimSpace(string(clean))
	if idx := strings.Index(name, "|"); idx != -1 {
		name = strings.TrimSpace(name[:idx])
	}
	if idx := strings.LastIndex(name, " - "); idx != -1 {
		name = strings.TrimSpace(name[idx+3:])
	}
	name = strings.ReplaceAll(name, "📊", "")
	name = strings.TrimSpace(name)
	if name == "" {
		return "unnamed"
	}
	if len([]rune(name)) > 22 {
		name = string([]rune(name)[:22])
	}
	return name
}

// startBench kicks off parallel testing and returns a Cmd that sends benchDoneMsg
func startBench(entries []benchEntry, group string) tea.Cmd {
	return func() tea.Msg {
		results := runParallelBench(entries, group)
		return benchDoneMsg{results: results}
	}
}

func runParallelBench(entries []benchEntry, group string) []benchEntry {
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Load full profile for config generation
	data, _ := os.ReadFile(fmt.Sprintf("./data/profiles/%s.json", group))
	var g struct {
		Links []struct {
			Remark   string `json:"remark"`
			Protocol string `json:"protocol"`
			Address  string `json:"address"`
			Port     int    `json:"port"`
			UUID     string `json:"uuid"`
			AlterId  int    `json:"alter_id"`
			Security string `json:"security"`
			Network  string `json:"network"`
			TLS      bool   `json:"tls"`
			SNI      string `json:"sni"`
			Path     string `json:"path"`
			Host     string `json:"host"`
			Flow     string `json:"flow"`
		} `json:"links"`
	}
	json.Unmarshal(data, &g)

	results := make([]benchEntry, len(entries))
	copy(results, entries)

	for i := range results {
		results[i].status = benchTesting
	}

	sbPath, _ := exec.LookPath("sing-box")
	if sbPath == "" {
		sbPath = "./engines/sing-box"
	}

	for i, entry := range entries {
		wg.Add(1)
		go func(idx int, e benchEntry) {
			defer wg.Done()

			// 1. TCP ping (direct connection to server)
			pingMs := tcpPing(e.address, e.port)

			// 2. Relay test (through sing-box proxy)
			relayMs := -1
			localPort := 19870 + idx

			// Find matching link in full profile
			var outboundJSON string
			for _, l := range g.Links {
				if l.Address == e.address && l.Port == e.port && l.Protocol == e.protocol {
					outboundJSON = buildOutboundJSON(l.Protocol, l.Address, l.Port, l.UUID, l.AlterId, l.Security, l.Network, l.TLS, l.SNI, l.Path, l.Host, l.Flow)
					break
				}
			}

			if outboundJSON != "" {
				relayMs = testRelay(sbPath, outboundJSON, localPort)
			}

			mu.Lock()
			results[idx].ping = pingMs
			results[idx].relay = relayMs
			if relayMs > 0 {
				results[idx].status = benchDone
			} else if pingMs > 0 {
				results[idx].status = benchDone
			} else {
				results[idx].status = benchFailed
			}
			mu.Unlock()
		}(i, entry)
	}

	wg.Wait()
	return results
}

func tcpPing(host string, port int) int {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return -1
	}
	conn.Close()
	return int(time.Since(start).Milliseconds())
}

func testRelay(sbPath, outboundJSON string, port int) int {
	cfg := fmt.Sprintf(`{"log":{"level":"error"},"inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":%d}],"outbounds":[%s,{"type":"direct","tag":"direct"}]}`, port, outboundJSON)

	tmpFile := fmt.Sprintf("./data/tmp/bench-%d-%d.json", os.Getpid(), port)
	os.WriteFile(tmpFile, []byte(cfg), 0644)
	defer os.Remove(tmpFile)

	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cmdCancel()

	cmd := exec.CommandContext(cmdCtx, sbPath, "run", "-c", tmpFile)
	if err := cmd.Start(); err != nil {
		return -1
	}
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()

	// Wait for port
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(300 * time.Millisecond)
	}

	// Test through proxy
	start := time.Now()
	testCmd := exec.CommandContext(cmdCtx, "curl", "-s", "-x", fmt.Sprintf("socks5h://127.0.0.1:%d", port),
		"--connect-timeout", "5", "-o", "/dev/null", "-w", "%{http_code}", "http://cp.cloudflare.com")
	out, err := testCmd.Output()
	elapsed := time.Since(start)

	if err != nil || strings.TrimSpace(string(out)) != "204" {
		return -1
	}

	return int(elapsed.Milliseconds())
}

func buildOutboundJSON(protocol, address string, port int, uuid string, alterId int, security, network string, tls bool, sni, path, host, flow string) string {
	// Fix SNI: if it's a comma-separated list, take the first one
	if strings.Contains(sni, ",") {
		sni = strings.TrimSpace(strings.Split(sni, ",")[0])
	}
	// Fix host: same treatment
	if strings.Contains(host, ",") {
		host = strings.TrimSpace(strings.Split(host, ",")[0])
	}

	switch protocol {
	case "shadowsocks":
		return fmt.Sprintf(`{"type":"shadowsocks","tag":"proxy","server":"%s","server_port":%d,"method":"%s","password":"%s"}`,
			address, port, security, uuid)
	case "vmess":
		ob := fmt.Sprintf(`{"type":"vmess","tag":"proxy","server":"%s","server_port":%d,"uuid":"%s","alter_id":%d,"security":"%s"`,
			address, port, uuid, alterId, security)
		if network != "" && network != "tcp" {
			ob += fmt.Sprintf(`,"transport":{"type":"%s"`, network)
			if path != "" {
				ob += fmt.Sprintf(`,"path":"%s"`, path)
			}
			if host != "" {
				ob += fmt.Sprintf(`,"headers":{"Host":"%s"}`, host)
			}
			ob += "}"
		}
		if tls {
			ob += `,"tls":{"enabled":true`
			if sni != "" {
				ob += fmt.Sprintf(`,"server_name":"%s"`, sni)
			}
			ob += "}"
		}
		ob += "}"
		return ob
	case "vless":
		ob := fmt.Sprintf(`{"type":"vless","tag":"proxy","server":"%s","server_port":%d,"uuid":"%s"`,
			address, port, uuid)
		if flow != "" {
			ob += fmt.Sprintf(`,"flow":"%s"`, flow)
		}
		if network != "" && network != "tcp" {
			ob += fmt.Sprintf(`,"transport":{"type":"%s"`, network)
			if path != "" {
				ob += fmt.Sprintf(`,"path":"%s"`, path)
			}
			if host != "" {
				ob += fmt.Sprintf(`,"headers":{"Host":"%s"}`, host)
			}
			ob += "}"
		}
		if security == "reality" {
			ob += `,"tls":{"enabled":true,"reality":{"enabled":true}` 
			if sni != "" {
				ob += fmt.Sprintf(`,"server_name":"%s"`, sni)
			}
			ob += "}"
		} else if tls {
			ob += `,"tls":{"enabled":true,"insecure":true`
			if sni != "" {
				ob += fmt.Sprintf(`,"server_name":"%s"`, sni)
			}
			ob += "}"
		}
		ob += "}"
		return ob
	case "trojan":
		ob := fmt.Sprintf(`{"type":"trojan","tag":"proxy","server":"%s","server_port":%d,"password":"%s","tls":{"enabled":true`, address, port, uuid)
		if sni != "" {
			ob += fmt.Sprintf(`,"server_name":"%s"`, sni)
		}
		ob += "}}"
		return ob
	default:
		return `{"type":"direct","tag":"proxy"}`
	}
}

// --- Bench page Tea interface ---

func (m benchModel) Init() tea.Cmd {
	return startBench(m.entries, m.group)
}

func (m benchModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case benchDoneMsg:
		m.entries = msg.results
		m.done = true
		m.applySorting()
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			// Return to main menu
			return newMainPage(), nil
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.entries)-1 {
				m.cursor++
			}
		case "enter":
			if m.done && m.cursor < len(m.entries) && m.entries[m.cursor].status == benchDone {
				m.selected = m.cursor
				// Select this link
				selectLink(m.entries[m.cursor].idx, m.group)
			}
		case "1":
			m.sortBy = sortByIndex
			m.applySorting()
		case "2":
			m.sortBy = sortByPing
			m.applySorting()
		case "3":
			m.sortBy = sortByRelay
			m.applySorting()
		}
	}
	return m, nil
}

func (m *benchModel) applySorting() {
	switch m.sortBy {
	case sortByPing:
		sort.SliceStable(m.entries, func(i, j int) bool {
			pi, pj := m.entries[i].ping, m.entries[j].ping
			if pi <= 0 {
				pi = 99999
			}
			if pj <= 0 {
				pj = 99999
			}
			return pi < pj
		})
	case sortByRelay:
		sort.SliceStable(m.entries, func(i, j int) bool {
			ri, rj := m.entries[i].relay, m.entries[j].relay
			if ri <= 0 {
				ri = 99999
			}
			if rj <= 0 {
				rj = 99999
			}
			return ri < rj
		})
	case sortByIndex:
		sort.SliceStable(m.entries, func(i, j int) bool {
			return m.entries[i].idx < m.entries[j].idx
		})
	}
}

func (m benchModel) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("BENCH"))
	b.WriteString("\n")

	if !m.done {
		testing := 0
		done := 0
		for _, e := range m.entries {
			if e.status == benchTesting {
				testing++
			}
			if e.status == benchDone || e.status == benchFailed {
				done++
			}
		}
		b.WriteString(subtitleStyle.Render(fmt.Sprintf("⏳ Testing %d/%d links...", done, len(m.entries))))
		b.WriteString("\n")
	} else {
		// Sort indicator
		sortLabels := []string{"#", "ping", "relay"}
		sortLabel := sortLabels[m.sortBy]
		b.WriteString(benchSortStyle.Render(fmt.Sprintf("  Sort: %s  [1]# [2]ping [3]relay", sortLabel)))
		b.WriteString("\n")
	}
	b.WriteString("\n")

	// Header
	header := padRight("#", 4) + padRight("Proto", 7) + padRight("Flag", 4) + padRight("Server", 18) + padRight("Port", 6) + padRight("Ping", 8) + padRight("Relay", 8) + "Name"
	b.WriteString(benchHeaderStyle.Render("  " + header))
	b.WriteString("\n")

	// Entries
	maxVisible := 18
	start := 0
	if m.cursor >= maxVisible {
		start = m.cursor - maxVisible + 1
	}
	end := start + maxVisible
	if end > len(m.entries) {
		end = len(m.entries)
	}

	for i := start; i < end; i++ {
		e := m.entries[i]
		proto := e.protocol
		if proto == "shadowsocks" {
			proto = "ss"
		}
		server := e.address
		if runewidth.StringWidth(server) > 16 {
			server = runewidth.Truncate(server, 15, "..")
		}

		pingStr := "..."
		relayStr := "..."

		switch e.status {
		case benchDone:
			if e.ping > 0 {
				pingStr = fmt.Sprintf("%dms", e.ping)
			} else {
				pingStr = "—"
			}
			if e.relay > 0 {
				relayStr = fmt.Sprintf("%dms", e.relay)
			} else {
				relayStr = "✗"
			}
		case benchFailed:
			pingStr = "✗"
			relayStr = "✗"
		case benchTesting:
			pingStr = "..."
			relayStr = "..."
		}

		name := e.remark
		if runewidth.StringWidth(name) > 20 {
			name = runewidth.Truncate(name, 19, "..")
		}

		line := padRight(fmt.Sprintf("%d", e.idx), 4) +
			padRight(proto, 7) +
			padRight(e.flag, 4) +
			padRight(server, 18) +
			padRight(fmt.Sprintf("%d", e.port), 6) +
			padRight(pingStr, 8) +
			padRight(relayStr, 8) +
			name

		prefix := "  "
		if i == m.cursor {
			prefix = "▸ "
		}

		if i == m.cursor {
			if e.status == benchDone && e.relay > 0 {
				b.WriteString(benchCursorStyle.Render(prefix + line))
			} else {
				b.WriteString(lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9")).Render(prefix + line))
			}
		} else {
			if e.status == benchDone && e.relay > 0 {
				b.WriteString(benchOkStyle.Render(prefix + line))
			} else if e.status == benchFailed || (e.status == benchDone && e.relay <= 0) {
				b.WriteString(benchFailStyle.Render(prefix + line))
			} else if e.status == benchTesting {
				b.WriteString(benchActiveStyle.Render(prefix + "⏳" + line[2:]))
			} else {
				b.WriteString(benchRowStyle.Render(prefix + line))
			}
		}
		b.WriteString("\n")
	}

	if len(m.entries) > maxVisible {
		b.WriteString(benchDimStyle.Render(fmt.Sprintf("  ... %d/%d shown (scroll with ↑↓)", maxVisible, len(m.entries))))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	if m.done {
		b.WriteString(benchDimStyle.Render("  ↑↓ navigate • enter select • 1/2/3 sort • esc back"))
	} else {
		b.WriteString(benchDimStyle.Render("  testing in progress... esc to cancel"))
	}
	b.WriteString("\n")

	if m.selected >= 0 && m.selected < len(m.entries) {
		b.WriteString("\n")
		b.WriteString(successStyle.Render(fmt.Sprintf("✅ Selected: #%d %s", m.entries[m.selected].idx, m.entries[m.selected].remark)))
		b.WriteString("\n")
	}

	return b.String()
}

func selectLink(idx int, group string) {
	exe, _ := os.Executable()
	exec.Command(exe, "select", fmt.Sprintf("%d", idx)).Run()
}

// padRight pads a string to the given visual width using runewidth.
func padRight(s string, width int) string {
	w := runewidth.StringWidth(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}
