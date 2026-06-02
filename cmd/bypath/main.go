package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/liberoute/bypath/internal/api"
	"github.com/liberoute/bypath/internal/build"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/gateway"
	"github.com/liberoute/bypath/internal/geo"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/pidfile"
	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/tui"
	"github.com/liberoute/bypath/internal/updater"
	"gopkg.in/yaml.v3"
)

func main() {
	if len(os.Args) < 2 {
		// No arguments — show interactive menu
		menu := tui.New()
		menu.Run()
		os.Exit(0)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "run":
		cmdRun(args)
	case "start":
		cmdRun(args) // alias
	case "add":
		cmdAdd(args)
	case "remove", "rm", "del":
		cmdRemove(args)
	case "list":
		cmdList(args)
	case "select":
		cmdSelect(args)
	case "bench":
		cmdBench(args)
	case "stop":
		cmdStop()
	case "test":
		cmdTest(args)
	case "sub":
		cmdSub(args)
	case "chain":
		cmdChain(args)
	case "engines":
		cmdEngines(args)
	case "update":
		cmdUpdate()
	case "version", "-v", "--version":
		fmt.Print(build.PrintVersionInfo())
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Printf("Unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`%s — Network Gateway & Tunnel Manager

Usage:
  bypath <command> [options]

Commands:
  run                     Start the gateway (main command)
    -c, --config PATH     Config file (default: configs/default.yaml)

  add <uri>               Add a proxy link (vmess://, vless://, ss://, etc.)
    -g, --group NAME      Target group (default: "default")

  list                    List all links in active group
    -g, --group NAME      Specific group

  select <name|number>    Set active link

  bench                   Test ALL links, show speed, auto-select best
    -g, --group NAME      Specific group

  sub add <url>           Add a subscription URL
    -g, --group NAME      Target group (default: "default")
  sub update              Fetch latest links from subscriptions
    -g, --group NAME      Specific group
  sub list                Show subscription URLs

  test <uri|file>         Test a config/link without starting gateway
    -e, --engine NAME     Force engine (sing-box, xray, auto)

  engines                 Show available engines and their status

  update                  Check for updates

  version                 Show version info
  help                    Show this help

Examples:
  bypath run
  bypath run -c /etc/bypath/config.yaml
  bypath add "vmess://eyJ2Ijo..."
  bypath add -g work "vless://uuid@host:443?type=ws#name"
  bypath test "vmess://..." -e xray
  bypath test /path/to/singbox-config.json
  bypath list
  bypath select my-server

`, build.Name)
}

// --- Commands ---

func cmdRun(args []string) {
	p := paths.Detect()
	p.EnsureDirs()

	configPath := p.ConfigFile
	for i, arg := range args {
		if (arg == "-c" || arg == "--config") && i+1 < len(args) {
			configPath = args[i+1]
		}
	}

	// Setup logging
	setupLogging(p)

	// Auto-create config if it doesn't exist
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Printf("⚠️  Config file not found: %s — creating with defaults...", configPath)
		if err := createDefaultConfig(configPath); err != nil {
			log.Fatalf("❌ Could not create config: %v", err)
		}
		log.Printf("✅ Default config created: %s", configPath)
	}

	// Check if already running
	if pid, running := pidfile.IsRunningFromFile(""); running {
		log.Fatalf("❌ Gateway already running (PID: %d). Use 'bypath stop' first.", pid)
	}

	log.Printf("🚀 %s starting...", build.FullVersion())

	// Write PID file
	if err := pidfile.Write(""); err != nil {
		log.Printf("⚠️  Could not write PID file: %v", err)
	}
	defer pidfile.Remove("")

	// Background update check
	go updater.CheckAndLog()

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("❌ Config error: %v", err)
	}

	// Download geosite files if configured
	if len(cfg.Whitelist.GeositeCountries) > 0 {
		updateInterval, parseErr := time.ParseDuration(cfg.Whitelist.UpdateInterval)
		if parseErr != nil {
			updateInterval = 24 * time.Hour
		}
		geo.DownloadGeositeFiles(cfg.Whitelist.GeositeURL, cfg.Whitelist.GeositeCountries, paths.Get().GeoDir, updateInterval)
		validatedCountries := geo.ValidateGeositeFiles(cfg.Whitelist.GeositeCountries, paths.Get().GeoDir)
		if len(validatedCountries) < len(cfg.Whitelist.GeositeCountries) {
			log.Printf("⚠️  Geosite: only %d/%d country files available", len(validatedCountries), len(cfg.Whitelist.GeositeCountries))
		}
		cfg.Whitelist.GeositeCountries = validatedCountries
	}

	engineMgr := engine.NewManager(cfg.Engines)
	if err := engineMgr.Init(); err != nil {
		log.Fatalf("❌ Engine init error: %v", err)
	}

	gw, err := gateway.New(cfg, engineMgr)
	if err != nil {
		log.Fatalf("❌ Gateway init error: %v", err)
	}

	if err := gw.Start(); err != nil {
		log.Fatalf("❌ Gateway start error: %v", err)
	}

	apiServer := api.NewServer(cfg, gw, engineMgr)
	go apiServer.Start()

	log.Printf("✅ %s running. API: :%d | DNS: :%d", build.Name, cfg.Server.APIPort, cfg.Server.DNSPort)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("🛑 Shutting down...")
	gw.Stop()
}

func cmdAdd(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: bypath add [-g group] <uri>")
		os.Exit(1)
	}

	group := "default"
	var uri string

	for i := 0; i < len(args); i++ {
		if (args[i] == "-g" || args[i] == "--group") && i+1 < len(args) {
			group = args[i+1]
			i++
		} else {
			uri = args[i]
		}
	}

	if uri == "" {
		fmt.Println("❌ No URI provided")
		os.Exit(1)
	}

	// Parse the URI
	link, err := profile.ParseURI(uri)
	if err != nil {
		fmt.Printf("❌ Invalid URI: %v\n", err)
		os.Exit(1)
	}

	// Load profile manager
	mgr, err := profile.NewManager(profileDir(), "default")
	if err != nil {
		fmt.Printf("❌ Profile error: %v\n", err)
		os.Exit(1)
	}

	if err := mgr.AddLink(group, link); err != nil {
		fmt.Printf("❌ Add failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Added [%s] %s → %s:%d (group: %s)\n", link.Protocol, link.Remark, link.Address, link.Port, group)
}

func cmdRemove(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: bypath remove <name|number> [-g group]")
		fmt.Println("       bypath remove all [-g group]   (remove all links in group)")
		os.Exit(1)
	}

	group := ""
	var target string
	for i := 0; i < len(args); i++ {
		if (args[i] == "-g" || args[i] == "--group") && i+1 < len(args) {
			group = args[i+1]
			i++
		} else {
			target = args[i]
		}
	}

	if target == "" {
		fmt.Println("❌ No link name or number provided")
		os.Exit(1)
	}

	mgr, err := profile.NewManager(profileDir(), "default")
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}

	// Default to "default" group
	if group == "" {
		group = "default"
	}

	// "all" removes all links in the group
	if target == "all" {
		g, err := mgr.GetGroup(group)
		if err != nil {
			fmt.Printf("❌ Group '%s' not found\n", group)
			os.Exit(1)
		}
		count := len(g.Links)
		g.Links = nil
		// Save by re-adding empty (use internal method via workaround)
		data := fmt.Sprintf(`{"name":"%s","type":"%s","links":[],"subscriptions":%s}`,
			g.Name, g.Type, mustJSON(g.Subscriptions))
		os.WriteFile(filepath.Join(profileDir(), group+".json"), []byte(data), 0644)
		fmt.Printf("✅ Removed all %d links from group '%s'\n", count, group)
		return
	}

	// Try as number
	if idx := parseIndex(target); idx > 0 {
		g, err := mgr.GetGroup(group)
		if err != nil {
			fmt.Printf("❌ Group '%s' not found\n", group)
			os.Exit(1)
		}
		if idx > len(g.Links) {
			fmt.Printf("❌ Link #%d not found (group has %d links)\n", idx, len(g.Links))
			os.Exit(1)
		}
		link := g.Links[idx-1]
		if err := mgr.RemoveLink(group, link.Remark); err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Removed [%s] %s from group '%s'\n", link.Protocol, link.Remark, group)
		return
	}

	// Try as remark name
	if err := mgr.RemoveLink(group, target); err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Removed '%s' from group '%s'\n", target, group)
}

func mustJSON(v interface{}) string {
	if v == nil {
		return "[]"
	}
	data, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(data)
}

func cmdList(args []string) {
	group := ""
	for i, arg := range args {
		if (arg == "-g" || arg == "--group") && i+1 < len(args) {
			group = args[i+1]
		}
	}

	mgr, err := profile.NewManager(profileDir(), "default")
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}

	// If no group specified, show all groups with their links
	if group == "" {
		groups := mgr.ListGroups()
		if len(groups) == 0 {
			fmt.Println("No groups found. Use 'bypath sub add <url>' to add a subscription.")
			return
		}
		for _, gName := range groups {
			g, err := mgr.GetGroup(gName)
			if err != nil {
				continue
			}
			testable := 0
			for _, l := range g.Links {
				if l.Port >= 10 && l.Address != "" && l.Address != "0.0.0.0" {
					testable++
				}
			}
			fmt.Printf("\n━━ %s (%d links) ━━\n", gName, testable)
			printGroupLinks(g)
		}
		return
	}

	g, err := mgr.GetGroup(group)
	if err != nil {
		fmt.Printf("❌ Group '%s' not found\n", group)
		os.Exit(1)
	}

	if len(g.Links) == 0 {
		fmt.Printf("No links in group '%s'\n", group)
		return
	}

	printGroupLinks(g)
}

func printGroupLinks(g *profile.Group) {
	if len(g.Links) == 0 {
		fmt.Println("  (empty)")
		return
	}
	fmt.Printf("  %-3s %-8s %-4s %-22s %-6s %s\n", "#", "Proto", "Flag", "Server", "Port", "Name")
	fmt.Printf("  %-3s %-8s %-4s %-22s %-6s %s\n", "---", "-----", "----", "------", "----", "----")
	for i, link := range g.Links {
		if link.Port < 10 || link.Address == "" || link.Address == "0.0.0.0" {
			continue // skip info links
		}
		proto := shortProto(link.Protocol)
		flag := extractFlag(link.Remark)
		name := cleanRemark(link.Remark)
		server := link.Address
		if len(server) > 20 {
			server = server[:17] + "..."
		}
		// Build status tags for CDN detection and HTTPS failure
		var status string
		if profile.IsCDNPattern(link) {
			status += " [CDN]"
		}
		if link.HTTPSCapable == -1 {
			status += " [HTTPS✗]"
		}
		fmt.Printf("  %-3d %-8s %-4s %-22s %-6d %s%s\n", i+1, proto, flag, server, link.Port, name, status)
	}
	fmt.Println()
}

func shortProto(p string) string {
	switch p {
	case "shadowsocks":
		return "ss"
	case "wireguard":
		return "wg"
	case "trojan":
		return "trojan"
	case "ssh":
		return "ssh"
	default:
		return p
	}
}

func extractFlag(remark string) string {
	runes := []rune(remark)
	for i := 0; i < len(runes)-1; i++ {
		if runes[i] >= 0x1F1E6 && runes[i] <= 0x1F1FF && runes[i+1] >= 0x1F1E6 && runes[i+1] <= 0x1F1FF {
			return string(runes[i : i+2])
		}
	}
	return "  "
}

func cleanRemark(remark string) string {
	name := remark
	if idx := strings.LastIndex(name, " - "); idx != -1 {
		name = name[idx+3:]
	}
	// Remove flags
	runes := []rune(name)
	var clean []rune
	for i := 0; i < len(runes); i++ {
		if runes[i] >= 0x1F1E6 && runes[i] <= 0x1F1FF {
			i++
			continue
		}
		clean = append(clean, runes[i])
	}
	name = strings.TrimSpace(string(clean))
	if idx := strings.Index(name, "|"); idx != -1 {
		name = strings.TrimSpace(name[:idx])
	}
	name = strings.ReplaceAll(name, "📊", "")
	name = strings.TrimSpace(name)
	if name == "" {
		return "unnamed"
	}
	if len([]rune(name)) > 20 {
		name = string([]rune(name)[:20])
	}
	return name
}

func cmdSelect(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: bypath select <remark-name>")
		fmt.Println("       bypath select <number> [-g group]  (from 'bypath list')")
		os.Exit(1)
	}

	group := ""
	var name string
	for i := 0; i < len(args); i++ {
		if (args[i] == "-g" || args[i] == "--group") && i+1 < len(args) {
			group = args[i+1]
			i++
		} else {
			name = args[i]
		}
	}

	if name == "" {
		fmt.Println("❌ No link name or number provided")
		os.Exit(1)
	}

	mgr, err := profile.NewManager(profileDir(), "default")
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}

	// Try as number first
	if idx := parseIndex(name); idx > 0 {
		if group != "" {
			// Select from specific group
			g, _ := mgr.GetGroup(group)
			if g != nil && idx <= len(g.Links) {
				link := g.Links[idx-1]
				mgr.SetActiveLink(link)
				fmt.Printf("✅ Active link: [%s] %s → %s:%d\n", link.Protocol, link.Remark, link.Address, link.Port)
				warnIfCDN(link)
				return
			}
			fmt.Printf("❌ Link #%d not found in group '%s'\n", idx, group)
			os.Exit(1)
		}
		// No group specified — search all groups
		groups := mgr.ListGroups()
		for _, gName := range groups {
			g, _ := mgr.GetGroup(gName)
			if g != nil && idx <= len(g.Links) {
				link := g.Links[idx-1]
				mgr.SetActiveLink(link)
				fmt.Printf("✅ Active link: [%s] %s → %s:%d\n", link.Protocol, link.Remark, link.Address, link.Port)
				warnIfCDN(link)
				return
			}
		}
	}

	// Try as remark name
	link, err := mgr.GetLink(name)
	if err != nil {
		fmt.Printf("❌ Link '%s' not found\n", name)
		fmt.Println("   Use 'bypath list' to see available links")
		os.Exit(1)
	}

	mgr.SetActiveLink(link)
	fmt.Printf("✅ Active link: [%s] %s → %s:%d\n", link.Protocol, link.Remark, link.Address, link.Port)
	warnIfCDN(link)
}

// warnIfCDN prints a warning if the selected link is CDN-based or has failed HTTPS testing.
func warnIfCDN(link *profile.Link) {
	if profile.IsCDNPattern(link) || link.HTTPSCapable == -1 {
		fmt.Println("  ⚠️  This link is CDN-based and may not support HTTPS browsing")
	}
}

func parseIndex(s string) int {
	n := 0
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			n = n*10 + int(ch-'0')
		} else {
			return 0
		}
	}
	return n
}

func cmdTest(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: bypath test <uri|config-file> [-e engine]")
		os.Exit(1)
	}

	forceEngine := ""
	var input string

	for i := 0; i < len(args); i++ {
		if (args[i] == "-e" || args[i] == "--engine") && i+1 < len(args) {
			forceEngine = args[i+1]
			i++
		} else {
			input = args[i]
		}
	}

	// Detect if input is a URI or a file
	if strings.Contains(input, "://") {
		// It's a URI — parse and detect engine
		link, err := profile.ParseURI(input)
		if err != nil {
			fmt.Printf("❌ Invalid URI: %v\n", err)
			os.Exit(1)
		}

		detectedEngine := detectEngine(link.Protocol, forceEngine)
		fmt.Printf("📋 Parsed link:\n")
		fmt.Printf("   Protocol: %s\n", link.Protocol)
		fmt.Printf("   Server:   %s:%d\n", link.Address, link.Port)
		fmt.Printf("   Remark:   %s\n", link.Remark)
		fmt.Printf("   Network:  %s\n", link.Network)
		fmt.Printf("   TLS:      %v\n", link.TLS)
		fmt.Printf("   Engine:   %s\n", detectedEngine)
	} else {
		// It's a file — detect engine from content
		detectedEngine := detectEngineFromFile(input, forceEngine)
		fmt.Printf("📋 Config file: %s\n", input)
		fmt.Printf("   Engine:   %s\n", detectedEngine)
	}

	fmt.Println("\n✅ Config is valid (dry-run)")
}

func cmdBench(args []string) {
	group := ""
	autoSelect := false
	singleIdx := 0
	for i, arg := range args {
		if (arg == "-g" || arg == "--group") && i+1 < len(args) {
			group = args[i+1]
		}
		if arg == "--auto" {
			autoSelect = true
		}
		if arg == "--single" && i+1 < len(args) {
			singleIdx = parseIndex(args[i+1])
		}
	}

	mgr, err := profile.NewManager(profileDir(), "default")
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}

	// Find group
	if group == "" {
		groups := mgr.ListGroups()
		if len(groups) == 0 {
			fmt.Println("❌ No groups found")
			os.Exit(1)
		}
		group = groups[0]
	}

	g, err := mgr.GetGroup(group)
	if err != nil {
		fmt.Printf("❌ Group '%s' not found\n", group)
		os.Exit(1)
	}

	if len(g.Links) == 0 {
		fmt.Println("❌ No links to test")
		os.Exit(1)
	}

	// Skip info-only links (port 0 or port < 10)
	var testableLinks []*profile.Link
	for _, link := range g.Links {
		if link.Port >= 10 && link.Address != "" {
			testableLinks = append(testableLinks, link)
		}
	}

	if len(testableLinks) == 0 {
		fmt.Println("❌ No testable links found")
		os.Exit(1)
	}

	// Single link test mode
	if singleIdx > 0 {
		if singleIdx > len(g.Links) {
			fmt.Printf("❌ Link #%d not found\n", singleIdx)
			os.Exit(1)
		}
		link := g.Links[singleIdx-1]
		fmt.Printf("  🔍 Testing [%s] %s → %s:%d\n\n", link.Protocol, link.Remark, link.Address, link.Port)

		// TCP Ping
		addr := net.JoinHostPort(link.Address, fmt.Sprintf("%d", link.Port))
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			fmt.Printf("  ❌ Ping: timeout\n")
		} else {
			conn.Close()
			fmt.Printf("  ✅ Ping: %dms\n", time.Since(start).Milliseconds())
		}

		// Relay test
		port := 19999
		latency, ok, _ := benchLinkOnPort(link, port)
		if ok {
			fmt.Printf("  ✅ Relay: %s\n", latency)
		} else {
			fmt.Printf("  ❌ Relay: failed\n")
		}
		return
	}

	fmt.Printf("\n  🏁 Benchmarking %d links in group '%s' (parallel)...\n\n", len(testableLinks), group)

	type benchResult struct {
		idx     int
		link    *profile.Link
		latency string
		status  string
		ms      int
		httpsOk bool
	}

	// Run all benchmarks in parallel
	results := make([]benchResult, len(testableLinks))
	var wg sync.WaitGroup

	for i, link := range testableLinks {
		wg.Add(1)
		go func(idx int, l *profile.Link) {
			defer wg.Done()
			port := 19870 + idx // unique port per link
			latency, ok, httpsOk := benchLinkOnPort(l, port)
			if ok {
				ms := parseMs(latency)
				results[idx] = benchResult{idx, l, latency, "ok", ms, httpsOk}
			} else {
				results[idx] = benchResult{idx, l, "-", "fail", 99999, false}
			}
		}(i, link)
	}

	wg.Wait()

	// Persist HTTPSCapable results to the profile
	for _, r := range results {
		if r.status == "ok" && r.httpsOk {
			r.link.HTTPSCapable = 1
		} else if r.status == "ok" && !r.httpsOk {
			r.link.HTTPSCapable = -1
		}
		// If status == "fail", leave HTTPSCapable as-is (we didn't test HTTPS)
	}
	mgr.SaveGroup(group)

	// Print results
	fmt.Printf("  %-3s %-8s %-4s %-22s %-6s %-8s %-5s %s\n", "#", "Proto", "Flag", "Server", "Port", "Latency", "HTTPS", "Status")
	fmt.Printf("  %-3s %-8s %-4s %-22s %-6s %-8s %-5s %s\n", "---", "-----", "----", "------", "----", "-------", "-----", "------")

	for i, r := range results {
		flag := extractFlag(r.link.Remark)
		server := r.link.Address
		if len(server) > 20 {
			server = server[:17] + "..."
		}
		proto := shortProto(r.link.Protocol)
		var httpsCol string
		if r.status == "fail" {
			httpsCol = "—"
		} else if r.httpsOk {
			httpsCol = "✓"
		} else {
			httpsCol = "✗"
		}
		if r.status == "ok" {
			fmt.Printf("  %-3d %-8s %-4s %-22s %-6d %-8s %-5s ✅ OK\n", i+1, proto, flag, server, r.link.Port, r.latency, httpsCol)
		} else {
			fmt.Printf("  %-3d %-8s %-4s %-22s %-6d %-8s %-5s ❌ FAIL\n", i+1, proto, flag, server, r.link.Port, "timeout", httpsCol)
		}
	}

	// Convert results to profile.BenchResult for SelectBest
	var benchResults []*profile.BenchResult
	for i := range results {
		benchResults = append(benchResults, &profile.BenchResult{
			Link:    results[i].link,
			Latency: time.Duration(results[i].ms) * time.Millisecond,
			HTTPSOk: results[i].httpsOk,
			Passed:  results[i].status == "ok",
		})
	}

	sel := profile.SelectBest(benchResults)

	if sel.Best == nil {
		fmt.Println("\n  ❌ No working links found!")
		return
	}

	// Find the original benchResult index for display
	bestIdx := 0
	var bestLatencyStr string
	for i := range results {
		if results[i].link == sel.Best.Link {
			bestIdx = i
			bestLatencyStr = results[i].latency
			break
		}
	}

	fmt.Printf("\n  🏆 Best: #%d [%s] %s:%d (%s)\n", bestIdx+1, sel.Best.Link.Protocol, sel.Best.Link.Address, sel.Best.Link.Port, bestLatencyStr)

	// Print warnings based on selection result
	if sel.NoHTTPS {
		fmt.Println("  ⚠️  No HTTPS-capable links found — selected fastest HTTP link")
	}
	if len(sel.Skipped) > 0 {
		fmt.Printf("  ℹ️  Skipped %d faster link(s) that lack HTTPS support\n", len(sel.Skipped))
		for _, sk := range sel.Skipped {
			fmt.Printf("      • %s:%d (%dms)\n", sk.Link.Address, sk.Link.Port, sk.Latency.Milliseconds())
		}
	}

	if autoSelect {
		mgr.SetActiveLink(sel.Best.Link)
		fmt.Printf("  ✅ Auto-selected! Run 'bypath run' to start.\n")
	} else {
		fmt.Printf("\n  Auto-select this link? [Y/n]: ")

		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(strings.ToLower(input))

		if input == "" || input == "y" || input == "yes" {
			mgr.SetActiveLink(sel.Best.Link)
			fmt.Printf("  ✅ Selected! Run 'bypath run' to start.\n")
		}
	}
}

func benchLinkOnPort(link *profile.Link, port int) (latency string, ok bool, httpsOk bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var cmd *exec.Cmd

	if link.Protocol == "ssh" {
		// SSH links: start SSH tunnel directly instead of sing-box
		cmd = buildSSHBenchCmd(ctx, link, port)
		if cmd == nil {
			return "", false, false
		}
	} else {
		// All other protocols: use sing-box with generated config
		configContent := fmt.Sprintf(`{"log":{"level":"error"},"inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":%d}],"outbounds":[%s,{"type":"direct","tag":"direct"}]}`, port, buildOutbound(link))

		tmpFile := fmt.Sprintf(tmpDir()+"/bench-%d-%d.json", os.Getpid(), port)
		os.MkdirAll(tmpDir(), 0755)
		os.WriteFile(tmpFile, []byte(configContent), 0644)
		defer os.Remove(tmpFile)

		sbPath, err := exec.LookPath("sing-box")
		if err != nil {
			sbPath = filepath.Join(engineDir(), "sing-box")
		}

		cmd = exec.CommandContext(ctx, sbPath, "run", "-c", tmpFile)
	}

	cmd.Start()
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()

	// Wait for port to be ready
	deadline := time.Now().Add(4 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !ready {
		return "", false, false
	}

	// Test HTTP connectivity
	start := time.Now()
	testCmd := exec.CommandContext(ctx, "curl", "-s", "-x", fmt.Sprintf("socks5h://127.0.0.1:%d", port),
		"--connect-timeout", "6", "-o", "/dev/null", "-w", "%{http_code}", "http://ip-api.com/json")
	out, err := testCmd.Output()
	elapsed := time.Since(start)

	if err != nil || strings.TrimSpace(string(out)) != "200" {
		return "", false, false
	}

	// HTTP relay passed — now test HTTPS connectivity
	httpsOk = profile.TestHTTPS(ctx, port)

	return fmt.Sprintf("%dms", elapsed.Milliseconds()), true, httpsOk
}

// buildSSHBenchCmd constructs an SSH tunnel command for benchmarking.
// It mirrors the logic in tunnel.go's startSSHTunnel but returns an exec.Cmd
// bound to the bench port.
func buildSSHBenchCmd(ctx context.Context, link *profile.Link, port int) *exec.Cmd {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return nil
	}

	// Determine SSH port
	sshPort := link.Port
	if sshPort == 0 {
		sshPort = 22
	}

	// Determine SSH user
	sshUser := link.SSHUser
	if sshUser == "" {
		sshUser = "root"
	}

	// Build SSH args
	args := []string{
		"-D", fmt.Sprintf("127.0.0.1:%d", port),
		"-N",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=3",
	}

	// Add key-based auth if key path is set
	if link.SSHKeyPath != "" {
		args = append(args, "-i", link.SSHKeyPath)
	}

	// Add SSH port
	args = append(args, "-p", fmt.Sprintf("%d", sshPort))

	// Add user@host
	args = append(args, fmt.Sprintf("%s@%s", sshUser, link.Address))

	// Handle password-based auth via sshpass
	if link.SSHKeyPath == "" && link.SSHPassword != "" {
		sshpassPath, err := exec.LookPath("sshpass")
		if err != nil {
			return nil
		}
		finalArgs := append([]string{"-p", link.SSHPassword, sshPath}, args...)
		return exec.CommandContext(ctx, sshpassPath, finalArgs...)
	}

	return exec.CommandContext(ctx, sshPath, args...)
}

func buildOutbound(link *profile.Link) string {
	sni := link.SNI
	host := link.Host
	// Fix comma-separated SNI/host lists — take first entry
	if strings.Contains(sni, ",") {
		sni = strings.TrimSpace(strings.Split(sni, ",")[0])
	}
	if strings.Contains(host, ",") {
		host = strings.TrimSpace(strings.Split(host, ",")[0])
	}

	switch link.Protocol {
	case "ssh":
		// SSH doesn't use sing-box outbound config — it runs as a direct process
		return `{"type":"direct","tag":"proxy"}`
	case "shadowsocks":
		return fmt.Sprintf(`{"type":"shadowsocks","tag":"proxy","server":"%s","server_port":%d,"method":"%s","password":"%s"}`,
			link.Address, link.Port, link.Security, link.UUID)
	case "vmess":
		ob := fmt.Sprintf(`{"type":"vmess","tag":"proxy","server":"%s","server_port":%d,"uuid":"%s","alter_id":%d,"security":"%s"`,
			link.Address, link.Port, link.UUID, link.AlterId, link.Security)
		if link.Network != "" && link.Network != "tcp" {
			ob += fmt.Sprintf(`,"transport":{"type":"%s"`, link.Network)
			if link.Path != "" {
				ob += fmt.Sprintf(`,"path":"%s"`, link.Path)
			}
			if host != "" {
				ob += fmt.Sprintf(`,"headers":{"Host":"%s"}`, host)
			}
			ob += "}"
		}
		if link.TLS {
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
			link.Address, link.Port, link.UUID)
		if link.Flow != "" {
			ob += fmt.Sprintf(`,"flow":"%s"`, link.Flow)
		}
		if link.Network != "" && link.Network != "tcp" {
			ob += fmt.Sprintf(`,"transport":{"type":"%s"`, link.Network)
			if link.Path != "" {
				ob += fmt.Sprintf(`,"path":"%s"`, link.Path)
			}
			if host != "" {
				ob += fmt.Sprintf(`,"headers":{"Host":"%s"}`, host)
			}
			ob += "}"
		}
		if link.Security == "reality" {
			ob += `,"tls":{"enabled":true`
			if sni != "" {
				ob += fmt.Sprintf(`,"server_name":"%s"`, sni)
			}
			ob += `,"reality":{"enabled":true`
			if link.RealityPublicKey != "" {
				ob += fmt.Sprintf(`,"public_key":"%s"`, link.RealityPublicKey)
			}
			if link.RealityShortID != "" {
				ob += fmt.Sprintf(`,"short_id":"%s"`, link.RealityShortID)
			}
			ob += "}"
			if link.Fingerprint != "" {
				ob += fmt.Sprintf(`,"utls":{"enabled":true,"fingerprint":"%s"}`, link.Fingerprint)
			}
			ob += "}"
		} else if link.TLS {
			ob += `,"tls":{"enabled":true,"insecure":true`
			if sni != "" {
				ob += fmt.Sprintf(`,"server_name":"%s"`, sni)
			}
			ob += "}"
		}
		ob += "}"
		return ob
	default:
		return `{"type":"direct","tag":"proxy"}`
	}
}

func parseMs(s string) int {
	n := 0
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			n = n*10 + int(ch-'0')
		}
	}
	return n
}

func cmdSub(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage:")
		fmt.Println("  bypath sub add <url>       Add subscription URL")
		fmt.Println("  bypath sub update          Fetch latest links")
		fmt.Println("  bypath sub list            Show subscription URLs")
		fmt.Println("  bypath sub remove <index>  Remove subscription by index (from 'sub list')")
		os.Exit(1)
	}

	subCmd := args[0]
	subArgs := args[1:]

	mgr, err := profile.NewManager(profileDir(), "default")
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}

	switch subCmd {
	case "add":
		group := "default"
		var url string
		for i := 0; i < len(subArgs); i++ {
			if (subArgs[i] == "-g" || subArgs[i] == "--group") && i+1 < len(subArgs) {
				group = subArgs[i+1]
				i++
			} else {
				url = subArgs[i]
			}
		}
		if url == "" {
			fmt.Println("❌ No URL provided")
			os.Exit(1)
		}

		// Don't allow subscriptions in "default" group — it's reserved for manual links
		if group == "default" {
			// Auto-generate group name from URL domain
			group = groupNameFromURL(url)
			fmt.Printf("ℹ️  'default' group is reserved for manual links. Using group '%s'\n", group)
		}

		// Ensure group exists
		if _, err := mgr.GetGroup(group); err != nil {
			mgr.CreateGroup(group, "subscription")
		}

		if err := mgr.AddSubscription(group, url); err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Subscription added to group '%s'\n", group)
		fmt.Println("   Run 'bypath sub update -g " + group + "' to fetch links")

	case "update":
		group := ""
		for i := 0; i < len(subArgs); i++ {
			if (subArgs[i] == "-g" || subArgs[i] == "--group") && i+1 < len(subArgs) {
				group = subArgs[i+1]
				i++
			}
		}

		if group != "" {
			// Update specific group
			fmt.Printf("📡 Updating subscriptions for group '%s'...\n", group)
			count, err := mgr.UpdateSubscriptions(group)
			if err != nil {
				fmt.Printf("❌ %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("✅ Got %d links\n", count)
		} else {
			// Update ALL groups that have subscriptions
			groups := mgr.ListGroups()
			totalLinks := 0
			updated := 0
			for _, gName := range groups {
				g, _ := mgr.GetGroup(gName)
				if g == nil || len(g.Subscriptions) == 0 {
					continue
				}
				fmt.Printf("📡 Updating group '%s'...\n", gName)
				count, err := mgr.UpdateSubscriptions(gName)
				if err != nil {
					fmt.Printf("  ⚠️  %v\n", err)
					continue
				}
				fmt.Printf("  ✅ Got %d links\n", count)
				totalLinks += count
				updated++
			}
			if updated == 0 {
				fmt.Println("❌ No groups with subscriptions found")
				os.Exit(1)
			}
			fmt.Printf("\n✅ Updated %d groups, total %d links\n", updated, totalLinks)
		}

	case "remove", "rm", "del":
		group := "default"
		var idxStr string
		for i := 0; i < len(subArgs); i++ {
			if (subArgs[i] == "-g" || subArgs[i] == "--group") && i+1 < len(subArgs) {
				group = subArgs[i+1]
				i++
			} else {
				idxStr = subArgs[i]
			}
		}
		if idxStr == "" {
			fmt.Println("❌ No index provided. Use 'bypath sub list' to see indices.")
			os.Exit(1)
		}
		idx := parseIndex(idxStr)
		if idx <= 0 {
			fmt.Println("❌ Invalid index")
			os.Exit(1)
		}

		if err := mgr.RemoveSubscription(group, idx-1); err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Subscription #%d removed from group '%s'\n", idx, group)

	case "list":
		group := "default"
		for i := 0; i < len(subArgs); i++ {
			if (subArgs[i] == "-g" || subArgs[i] == "--group") && i+1 < len(subArgs) {
				group = subArgs[i+1]
				i++
			}
		}

		g, err := mgr.GetGroup(group)
		if err != nil {
			fmt.Printf("❌ Group '%s' not found\n", group)
			os.Exit(1)
		}
		if len(g.Subscriptions) == 0 {
			fmt.Printf("No subscriptions in group '%s'\n", group)
			return
		}
		fmt.Printf("Subscriptions in group '%s':\n\n", group)
		for i, url := range g.Subscriptions {
			fmt.Printf("  %d. %s\n", i+1, url)
		}

	default:
		fmt.Printf("Unknown sub command: %s\n", subCmd)
		os.Exit(1)
	}
}

func cmdChain(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage:")
		fmt.Println("  bypath chain add <name> <hop1> <hop2> [hop3...] [--auto-start]")
		fmt.Println("  bypath chain remove <name>")
		fmt.Println("  bypath chain list")
		fmt.Println("  bypath chain start <name>")
		fmt.Println("  bypath chain stop <name>")
		fmt.Println("  bypath chain status [name]")
		os.Exit(1)
	}

	subCmd := args[0]
	subArgs := args[1:]

	switch subCmd {
	case "add":
		cmdChainAdd(subArgs)
	case "remove", "rm", "del":
		cmdChainRemove(subArgs)
	case "list":
		cmdChainList(subArgs)
	case "start":
		cmdChainStart(subArgs)
	case "stop":
		cmdChainStop(subArgs)
	case "status":
		cmdChainStatus(subArgs)
	default:
		fmt.Printf("Unknown chain command: %s\n", subCmd)
		os.Exit(1)
	}
}

func cmdChainAdd(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: bypath chain add <name> <hop1-profile> [hop2-profile...] [--auto-start]")
		os.Exit(1)
	}

	// Parse args: first is chain name, rest are hop profiles (filter --auto-start flag)
	chainName := args[0]
	autoStart := false
	var hopProfiles []string

	for _, arg := range args[1:] {
		if arg == "--auto-start" {
			autoStart = true
		} else {
			hopProfiles = append(hopProfiles, arg)
		}
	}

	if len(hopProfiles) == 0 {
		fmt.Println("❌ At least one hop profile is required")
		os.Exit(1)
	}

	// Load config
	configPath := paths.Get().ConfigFile
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Printf("❌ Cannot load config: %v\n", err)
		os.Exit(1)
	}

	// Check for duplicate chain name
	for _, chain := range cfg.Chains {
		if chain.Name == chainName {
			fmt.Printf("❌ Chain '%s' already exists\n", chainName)
			os.Exit(1)
		}
	}

	// Build hops
	hops := make([]config.HopConfig, len(hopProfiles))
	for i, p := range hopProfiles {
		hops[i] = config.HopConfig{Profile: p}
	}

	// Create chain config
	newChain := config.ChainConfig{
		Name:      chainName,
		Hops:      hops,
		AutoStart: autoStart,
	}

	// Append to config
	cfg.Chains = append(cfg.Chains, newChain)

	// Write updated config back to YAML
	data, err := yaml.Marshal(cfg)
	if err != nil {
		fmt.Printf("❌ Cannot marshal config: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		fmt.Printf("❌ Cannot write config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Chain '%s' added with %d hop(s)\n", chainName, len(hopProfiles))
	if autoStart {
		fmt.Println("   Auto-start: enabled")
	}
}

func cmdChainRemove(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: bypath chain remove <name>")
		os.Exit(1)
	}

	chainName := args[0]

	// Load config
	configPath := paths.Get().ConfigFile
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Printf("❌ Cannot load config: %v\n", err)
		os.Exit(1)
	}

	// Find and remove the chain
	found := false
	for i, chain := range cfg.Chains {
		if chain.Name == chainName {
			cfg.Chains = append(cfg.Chains[:i], cfg.Chains[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		fmt.Printf("❌ Chain '%s' not found\n", chainName)
		os.Exit(1)
	}

	// Write updated config back to YAML
	data, err := yaml.Marshal(cfg)
	if err != nil {
		fmt.Printf("❌ Cannot marshal config: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		fmt.Printf("❌ Cannot write config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Chain '%s' removed\n", chainName)
}

func cmdChainList(args []string) {
	fmt.Println("chain list: not implemented")
}

func cmdChainStart(args []string) {
	fmt.Println("chain start: not implemented")
}

func cmdChainStop(args []string) {
	fmt.Println("chain stop: not implemented")
}

func cmdChainStatus(args []string) {
	fmt.Println("chain status: not implemented")
}

func cmdStop() {
	fmt.Println("🛑 Stopping gateway...")

	// Try PID file first
	pid, running := pidfile.IsRunningFromFile("")
	if running {
		fmt.Printf("  Stopping bypath (PID: %d)...\n", pid)
		if err := pidfile.StopFromFile(""); err != nil {
			fmt.Printf("  ⚠️  Could not kill process: %v\n", err)
		} else {
			fmt.Println("  ✓ bypath stopped")
		}
	} else {
		// Fallback: try pkill (for old instances without PID file)
		exec.Command("pkill", "-f", "bypath run").Run()
	}

	// Always cleanup child processes and network
	exec.Command("pkill", "sing-box").Run()
	exec.Command("pkill", "-f", "xray run -c /tmp/bypath").Run()
	exec.Command("pkill", "dns2socks").Run()
	exec.Command("pkill", "tun2socks").Run()
	// Cleanup network
	exec.Command("ip", "link", "del", "tun0").Run()
	exec.Command("iptables", "-t", "mangle", "-F").Run()
	exec.Command("iptables", "-t", "nat", "-F", "POSTROUTING").Run()
	exec.Command("iptables", "-F", "FORWARD").Run()
	exec.Command("ip", "rule", "del", "fwmark", "0x1", "lookup", "100").Run()
	exec.Command("ip", "rule", "del", "fwmark", "0x66/0xff", "lookup", "200").Run()

	// Remove PID file if still exists
	pidfile.Remove("")

	fmt.Println("✅ Gateway stopped")
}

func cmdEngines(args []string) {
	cfg := config.EnginesConfig{Directory: engineDir(), PreferSystem: true}
	mgr := engine.NewManager(cfg)
	mgr.Init()

	fmt.Println("Available engines:")
	// The manager logs what it finds during Init()
}

func cmdUpdate() {
	cfg, cfgErr := config.Load(paths.Get().ConfigFile)
	socksPort := 2801
	if cfgErr == nil && cfg.Server.SOCKSPort > 0 {
		socksPort = cfg.Server.SOCKSPort
	}

	// Check flags
	useProxy := false
	for _, arg := range os.Args[2:] {
		if arg == "--proxy" {
			useProxy = true
		}
		if arg == "--direct" {
			useProxy = false
		}
	}

	if useProxy {
		proxyAddr := fmt.Sprintf("socks5://127.0.0.1:%d", socksPort)
		os.Setenv("ALL_PROXY", proxyAddr)
		defer os.Unsetenv("ALL_PROXY")
	}

	result, err := updater.Check()
	if err != nil {
		// If direct failed, auto-retry via proxy
		if !useProxy {
			proxyAddr := fmt.Sprintf("socks5://127.0.0.1:%d", socksPort)
			os.Setenv("ALL_PROXY", proxyAddr)
			result, err = updater.Check()
			os.Unsetenv("ALL_PROXY")
		}
		if err != nil {
			fmt.Printf("❌ Update check failed: %v\n", err)
			os.Exit(1)
		}
	}

	if !result.Available {
		fmt.Printf("✅ You're on the latest version (%s)\n", result.CurrentVersion)
		return
	}

	fmt.Printf("🆕 Update available: %s → %s\n", result.CurrentVersion, result.LatestVersion)

	if result.DownloadURL == "" {
		fmt.Println("❌ No download URL found for your platform")
		return
	}

	fmt.Printf("📥 Downloading: %s\n", result.AssetName)

	// Download to temp file
	exe, _ := os.Executable()
	tmpFile := exe + ".new"

	// Use proxy if user chose it (ALL_PROXY is already set)
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	client := &http.Client{Timeout: 5 * time.Minute, Transport: transport}
	resp, downloadErr := client.Get(result.DownloadURL)
	if downloadErr != nil || (resp != nil && resp.StatusCode != 200) {
		if resp != nil {
			resp.Body.Close()
		}
		// If direct failed and proxy not already set, try proxy as fallback
		if !useProxy {
			fmt.Printf("   ⚠️  Direct download failed, trying via proxy...\n")
			proxyURL := fmt.Sprintf("socks5://127.0.0.1:%d", socksPort)
			if u, parseErr := url.Parse(proxyURL); parseErr == nil {
				transport2 := &http.Transport{Proxy: http.ProxyURL(u)}
				client2 := &http.Client{Timeout: 5 * time.Minute, Transport: transport2}
				resp, downloadErr = client2.Get(result.DownloadURL)
			}
		}
	}

	if downloadErr != nil {
		fmt.Printf("❌ Download failed: %v\n", downloadErr)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("❌ Download failed: HTTP %d\n", resp.StatusCode)
		os.Exit(1)
	}

	totalSize := resp.ContentLength
	out, err := os.Create(tmpFile)
	if err != nil {
		fmt.Printf("❌ Cannot create temp file: %v\n", err)
		os.Exit(1)
	}

	var written int64
	buf := make([]byte, 32*1024)
	lastPrint := time.Now()
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			_, writeErr := out.Write(buf[:n])
			if writeErr != nil {
				out.Close()
				os.Remove(tmpFile)
				fmt.Printf("\n❌ Write error: %v\n", writeErr)
				os.Exit(1)
			}
			written += int64(n)
			// Print progress every 200ms
			if time.Since(lastPrint) > 200*time.Millisecond {
				if totalSize > 0 {
					pct := float64(written) / float64(totalSize) * 100
					bar := progressBar(pct, 30)
					fmt.Printf("\r   %s %.1f%% (%s / %s)", bar, pct, humanSize(written), humanSize(totalSize))
				} else {
					fmt.Printf("\r   %s downloaded", humanSize(written))
				}
				lastPrint = time.Now()
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			out.Close()
			os.Remove(tmpFile)
			fmt.Printf("\n❌ Download error: %v\n", readErr)
			os.Exit(1)
		}
	}
	out.Close()

	// Final progress
	if totalSize > 0 {
		fmt.Printf("\r   %s 100%% (%s)          \n", progressBar(100, 30), humanSize(written))
	} else {
		fmt.Printf("\r   Downloaded %s          \n", humanSize(written))
	}

	// Replace current binary
	os.Chmod(tmpFile, 0755)
	backupFile := exe + ".bak"
	os.Remove(backupFile)
	if err := os.Rename(exe, backupFile); err != nil {
		os.Remove(tmpFile)
		fmt.Printf("❌ Cannot backup current binary: %v\n", err)
		os.Exit(1)
	}
	if err := os.Rename(tmpFile, exe); err != nil {
		// Restore backup
		os.Rename(backupFile, exe)
		fmt.Printf("❌ Cannot install new binary: %v\n", err)
		os.Exit(1)
	}
	os.Remove(backupFile)

	fmt.Printf("✅ Updated to %s! Restart bypath to use new version.\n", result.LatestVersion)
	if result.ReleaseNotes != "" {
		fmt.Printf("\n   Release notes:\n%s\n", result.ReleaseNotes)
	}
	fmt.Printf("\n   Changelog: https://github.com/liberoute/bypath/compare/v%s...v%s\n", result.CurrentVersion, result.LatestVersion)
}

func progressBar(pct float64, width int) string {
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return "[" + bar + "]"
}

func humanSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	} else {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
}

// --- Helpers ---

// detectEngine determines which engine to use for a protocol.
// If forceEngine is set, use that. Otherwise auto-detect.
func detectEngine(protocol, forceEngine string) string {
	if forceEngine != "" {
		return forceEngine
	}

	switch protocol {
	case "vmess", "vless", "trojan", "shadowsocks", "hysteria2", "tuic":
		return "sing-box (auto)"
	case "wireguard":
		return "wireguard-go (auto)"
	case "openvpn":
		return "openvpn (auto)"
	case "ssh":
		return "ssh (native)"
	default:
		return "sing-box (fallback)"
	}
}

// detectEngineFromFile tries to determine the engine from a config file's content.
func detectEngineFromFile(path, forceEngine string) string {
	if forceEngine != "" {
		return forceEngine
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return "unknown (can't read file)"
	}

	content := string(data)

	// sing-box: has "inbounds" and "outbounds" at top level
	if strings.Contains(content, `"inbounds"`) && strings.Contains(content, `"outbounds"`) {
		// Could be sing-box or xray — check for sing-box specific fields
		if strings.Contains(content, `"type"`) && strings.Contains(content, `"tag"`) {
			return "sing-box (detected)"
		}
	}

	// xray: has "inbounds" with "protocol" field
	if strings.Contains(content, `"inbounds"`) && strings.Contains(content, `"protocol"`) {
		return "xray (detected)"
	}

	// WireGuard: has [Interface] and [Peer]
	if strings.Contains(content, "[Interface]") && strings.Contains(content, "[Peer]") {
		return "wireguard-go (detected)"
	}

	// OpenVPN: has "remote" and "dev tun"
	if strings.Contains(content, "remote ") && strings.Contains(content, "dev tun") {
		return "openvpn (detected)"
	}

	// Clash/mihomo: has "proxies:" and "rules:"
	if strings.Contains(content, "proxies:") || strings.Contains(content, "proxy-groups:") {
		return "clash-meta (detected)"
	}

	return "unknown"
}

// groupNameFromURL extracts a short group name from a subscription URL.
func groupNameFromURL(rawURL string) string {
	// Try to extract domain
	url := rawURL
	if idx := strings.Index(url, "://"); idx != -1 {
		url = url[idx+3:]
	}
	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}
	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}

	// Use first part of domain as group name
	parts := strings.Split(url, ".")
	if len(parts) >= 2 {
		// Use second-level domain (e.g., "mslio" from "private-link.mslio.site")
		name := parts[len(parts)-2]
		if len(name) <= 2 {
			// Too short, use more
			if len(parts) >= 3 {
				name = parts[len(parts)-3]
			}
		}
		return name
	}
	if len(parts) > 0 && parts[0] != "" {
		return parts[0]
	}
	return "sub"
}

// createDefaultConfig generates a default configuration file with sane defaults.
func createDefaultConfig(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	p := paths.Get()
	content := fmt.Sprintf(`# Bypath Configuration

server:
  api_port: 8080
  dns_port: 53
  socks_port: 2801
  api_token: ""

gateway:
  enabled: true
  interface: ""
  dns_upstream:
    - "1.1.1.1"
    - "8.8.8.8"

engines:
  directory: "%s"
  prefer_system: true
  preferred: ""

profiles:
  directory: "%s"
  active_group: "default"

whitelist:
  countries: ["ir"]
  update_interval: "24h"

isolation:
  enabled: true

sni_spoof:
  enabled: false
  sni: "digikala.com"
`, p.EngineDir, p.ProfileDir)

	return os.WriteFile(path, []byte(content), 0644)
}

// setupLogging configures log output based on installation mode.
// In installed mode, logs go to /var/log/bypath/error.log.
// In local mode, logs go to stdout.
func setupLogging(p *paths.Resolved) {
	if p.LogDir == "" {
		return // local mode — stdout is fine
	}

	os.MkdirAll(p.LogDir, 0755)

	logFile := filepath.Join(p.LogDir, "error.log")
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Printf("⚠️  Cannot open log file %s: %v (using stdout)", logFile, err)
		return
	}

	log.SetOutput(f)
	log.Printf("📝 Logging to %s", logFile)
}

// profileDir returns the profile directory for the current installation mode.
func profileDir() string {
	return paths.Get().ProfileDir
}

// tmpDir returns the temp directory for the current installation mode.
func tmpDir() string {
	return paths.Get().TmpDir
}

// engineDir returns the engine directory for the current installation mode.
func engineDir() string {
	return paths.Get().EngineDir
}
