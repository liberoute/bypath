package tui

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
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
	down     int // KB/s, -1 = not tested
	up       int // KB/s, -1 = not tested
	https    int // 1=ok, 0=untested, -1=failed
}

// Messages
type benchDoneMsg struct {
	results []benchEntry
}

var (
	benchHeaderStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("14"))
	benchRowStyle    = lipgloss.NewStyle()
	benchActiveStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	benchOkStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	benchFailStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	benchCursorStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))
	benchDimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	benchSortStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
)

func loadBenchEntries(group string) []benchEntry {
	data, err := os.ReadFile(filepath.Join(paths.Get().ProfileDir, group+".json"))
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
			down:     -1,
			up:       -1,
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

// startBench kicks off parallel testing (ping + relay + download)
func startBench(entries []benchEntry, group string) tea.Cmd {
	return func() tea.Msg {
		results := runParallelBench(entries, group)
		return benchDoneMsg{results: results}
	}
}

// startPingOnly runs only TCP ping (no relay/download)
func startPingOnly(entries []benchEntry) tea.Cmd {
	return func() tea.Msg {
		results := make([]benchEntry, len(entries))
		copy(results, entries)
		for i := range results {
			results[i].status = benchTesting
		}

		var wg sync.WaitGroup
		var mu sync.Mutex

		for i, e := range entries {
			wg.Add(1)
			go func(idx int, entry benchEntry) {
				defer wg.Done()
				pingMs := tcpPing(entry.address, entry.port)
				mu.Lock()
				results[idx].ping = pingMs
				if pingMs > 0 {
					results[idx].status = benchDone
				} else {
					results[idx].status = benchFailed
				}
				mu.Unlock()
			}(i, e)
		}

		wg.Wait()
		return benchDoneMsg{results: results}
	}
}

// testDownload measures download speed through a SOCKS proxy (KB/s)
func testDownload(proxyPort int) int {
	// Download ~100KB file and measure speed
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "curl", "-s",
		"-x", fmt.Sprintf("socks5h://127.0.0.1:%d", proxyPort),
		"--connect-timeout", "5",
		"-o", "/dev/null",
		"-w", "%{speed_download}",
		"http://speed.cloudflare.com/__down?bytes=102400")
	out, err := cmd.Output()
	if err != nil {
		return -1
	}
	// speed_download is in bytes/sec
	speed := 0.0
	for _, ch := range strings.TrimSpace(string(out)) {
		if ch == '.' {
			break
		}
		if ch >= '0' && ch <= '9' {
			speed = speed*10 + float64(ch-'0')
		}
	}
	return int(speed / 1024) // KB/s
}

func runParallelBench(entries []benchEntry, group string) []benchEntry {
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Load full profile for config generation
	data, _ := os.ReadFile(filepath.Join(paths.Get().ProfileDir, group+".json"))
	var g struct {
		Links []struct {
			Remark           string `json:"remark"`
			Protocol         string `json:"protocol"`
			Address          string `json:"address"`
			Port             int    `json:"port"`
			UUID             string `json:"uuid"`
			AlterId          int    `json:"alter_id"`
			Security         string `json:"security"`
			Network          string `json:"network"`
			TLS              bool   `json:"tls"`
			SNI              string `json:"sni"`
			Path             string `json:"path"`
			Host             string `json:"host"`
			Flow             string `json:"flow"`
			RealityPublicKey string `json:"reality_pbk"`
			RealityShortID   string `json:"reality_sid"`
			Fingerprint      string `json:"fingerprint"`
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
		sbPath = filepath.Join(paths.Get().EngineDir, "sing-box")
	}

	// Bench always uses sing-box for relay testing (more compatible with all protocols)
	// Engine preference only affects the main gateway connection

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
			var matchedLink struct {
				UUID             string
				AlterId          int
				Security         string
				Network          string
				TLS              bool
				SNI              string
				Path             string
				Host             string
				Flow             string
				RealityPublicKey string
				RealityShortID   string
				Fingerprint      string
			}
			for _, l := range g.Links {
				if l.Address == e.address && l.Port == e.port && l.Protocol == e.protocol {
					outboundJSON = buildOutboundJSON(l.Protocol, l.Address, l.Port, l.UUID, l.AlterId, l.Security, l.Network, l.TLS, l.SNI, l.Path, l.Host, l.Flow, l.RealityPublicKey, l.RealityShortID, l.Fingerprint)
					matchedLink.UUID = l.UUID
					matchedLink.AlterId = l.AlterId
					matchedLink.Security = l.Security
					matchedLink.Network = l.Network
					matchedLink.TLS = l.TLS
					matchedLink.SNI = l.SNI
					matchedLink.Path = l.Path
					matchedLink.Host = l.Host
					matchedLink.Flow = l.Flow
					matchedLink.RealityPublicKey = l.RealityPublicKey
					matchedLink.RealityShortID = l.RealityShortID
					matchedLink.Fingerprint = l.Fingerprint
					break
				}
			}

			if outboundJSON != "" {
				relayMs = testRelay(sbPath, outboundJSON, localPort)
			}

			// Download test (only if relay succeeded)
			downKBs := -1
			httpsResult := 0 // 0=untested
			if relayMs > 0 {
				downKBs = testDownload(localPort)
				// HTTPS connectivity test
				if profile.TestHTTPS(context.Background(), localPort) {
					httpsResult = 1
				} else {
					httpsResult = -1
				}
			}

			mu.Lock()
			results[idx].ping = pingMs
			results[idx].relay = relayMs
			results[idx].down = downKBs
			results[idx].https = httpsResult
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
	cfg := fmt.Sprintf(`{"log":{"level":"error"},"dns":{"servers":[{"tag":"dns-direct","type":"udp","server":"1.1.1.1","server_port":53}],"final":"dns-direct"},"route":{"default_domain_resolver":"dns-direct"},"inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":%d}],"outbounds":[%s,{"type":"direct","tag":"direct"}]}`, port, outboundJSON)

	tmpFile := fmt.Sprintf(filepath.Join(paths.Get().TmpDir, "bench-%d-%d.json"), os.Getpid(), port)
	os.WriteFile(tmpFile, []byte(cfg), 0644)
	defer os.Remove(tmpFile)

	cmdCtx, cmdCancel := context.WithTimeout(context.Background(), 20*time.Second)
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
	deadline := time.Now().Add(6 * time.Second)
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
		"--connect-timeout", "8", "-o", "/dev/null", "-w", "%{http_code}", "http://cp.cloudflare.com")
	out, err := testCmd.Output()
	elapsed := time.Since(start)

	if err != nil || strings.TrimSpace(string(out)) != "204" {
		return -1
	}

	return int(elapsed.Milliseconds())
}

func buildOutboundJSON(protocol, address string, port int, uuid string, alterId int, security, network string, tls bool, sni, path, host, flow, realityPbk, realitySid, fingerprint string) string {
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
			ob += `,"tls":{"enabled":true,"reality":{"enabled":true`
			if realityPbk != "" {
				ob += fmt.Sprintf(`,"public_key":"%s"`, realityPbk)
			}
			if realitySid != "" {
				ob += fmt.Sprintf(`,"short_id":"%s"`, realitySid)
			}
			ob += "}"
			if sni != "" {
				ob += fmt.Sprintf(`,"server_name":"%s"`, sni)
			}
			if fingerprint != "" {
				ob += fmt.Sprintf(`,"utls":{"enabled":true,"fingerprint":"%s"}`, fingerprint)
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

// persistHTTPSResults updates the HTTPSCapable field on links in the profile JSON
// after bench completes, then saves the group.
func persistHTTPSResults(group string, entries []benchEntry) {
	mgr, err := profile.NewManager(paths.Get().ProfileDir, "default")
	if err != nil {
		return
	}
	g, err := mgr.GetGroup(group)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.status != benchDone {
			continue
		}
		// Match by index (entry.idx is 1-based)
		linkIdx := entry.idx - 1
		if linkIdx < 0 || linkIdx >= len(g.Links) {
			continue
		}
		if entry.https == 1 {
			g.Links[linkIdx].HTTPSCapable = 1
		} else if entry.https == -1 {
			g.Links[linkIdx].HTTPSCapable = -1
		}
	}
	mgr.SaveGroup(group)
}
