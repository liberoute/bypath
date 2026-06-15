package main

import (
	"bufio"
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

	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/tunnel"
)

func cmdBench(args []string) {
	targetGroup := ""
	autoSelect := false
	singleIdx := 0
	for i, arg := range args {
		if (arg == "-g" || arg == "--group") && i+1 < len(args) {
			targetGroup = args[i+1]
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

	allGroups := mgr.ListGroups()
	if len(allGroups) == 0 {
		fmt.Println("❌ No groups found")
		os.Exit(1)
	}

	var groupsToTest []string
	if targetGroup != "" {
		groupsToTest = []string{targetGroup}
	} else {
		groupsToTest = allGroups
	}

	if singleIdx > 0 {
		g, err := mgr.GetGroup(groupsToTest[0])
		if err != nil || singleIdx > len(g.Links) {
			fmt.Printf("❌ Link #%d not found in group '%s'\n", singleIdx, groupsToTest[0])
			os.Exit(1)
		}
		link := g.Links[singleIdx-1]
		fmt.Printf("  🔍 Testing [%s] %s → %s:%d\n\n", link.Protocol, link.Remark, link.Address, link.Port)

		addr := net.JoinHostPort(link.Address, fmt.Sprintf("%d", link.Port))
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			fmt.Printf("  ❌ Ping: timeout\n")
		} else {
			conn.Close()
			fmt.Printf("  ✅ Ping: %dms\n", time.Since(start).Milliseconds())
		}

		latency, ok, _ := benchLinkOnPort(link, 19999)
		if ok {
			fmt.Printf("  ✅ Relay: %s\n", latency)
		} else {
			fmt.Printf("  ❌ Relay: failed\n")
		}
		return
	}

	type benchResult struct {
		group   string
		link    *profile.Link
		latency string
		status  string
		ms      int
		httpsOk bool
	}

	type groupRange struct {
		name  string
		start int
		end   int
	}
	var allLinks []*profile.Link
	var ranges []groupRange

	for _, gname := range groupsToTest {
		g, err := mgr.GetGroup(gname)
		if err != nil {
			continue
		}
		start := len(allLinks)
		for _, l := range g.Links {
			if l.Port >= 10 && l.Address != "" {
				allLinks = append(allLinks, l)
			}
		}
		if len(allLinks) > start {
			ranges = append(ranges, groupRange{gname, start, len(allLinks)})
		}
	}

	if len(allLinks) == 0 {
		fmt.Println("❌ No testable links found")
		os.Exit(1)
	}

	totalGroups := len(ranges)
	if totalGroups > 1 {
		fmt.Printf("\n  🏁 Benchmarking %d links across %d groups (parallel)...\n", len(allLinks), totalGroups)
	} else {
		fmt.Printf("\n  🏁 Benchmarking %d links in group '%s' (parallel)...\n", len(allLinks), ranges[0].name)
	}

	results := make([]benchResult, len(allLinks))
	var wg sync.WaitGroup

	for _, gr := range ranges {
		for i := gr.start; i < gr.end; i++ {
			results[i].group = gr.name
		}
	}

	for i, link := range allLinks {
		wg.Add(1)
		go func(idx int, l *profile.Link) {
			defer wg.Done()
			port := 19870 + idx
			latency, ok, httpsOk := benchLinkOnPort(l, port)
			if ok {
				results[idx].link = l
				results[idx].latency = latency
				results[idx].status = "ok"
				results[idx].ms = parseMs(latency)
				results[idx].httpsOk = httpsOk
			} else {
				results[idx].link = l
				results[idx].latency = "-"
				results[idx].status = "fail"
				results[idx].ms = 99999
			}
		}(i, link)
	}

	wg.Wait()

	fmt.Println()
	fmt.Printf("  %-3s %-8s %-4s %-22s %-6s %-8s %-5s %s\n", "#", "Proto", "Flag", "Server", "Port", "Latency", "HTTPS", "Status")
	fmt.Printf("  %-3s %-8s %-4s %-22s %-6s %-8s %-5s %s\n", "---", "-----", "----", "------", "----", "-------", "-----", "------")

	globalIdx := 1
	for _, gr := range ranges {
		if totalGroups > 1 {
			fmt.Printf("\n  ━━ %s ━━\n", gr.name)
		}
		for i := gr.start; i < gr.end; i++ {
			r := results[i]
			flag := extractFlag(r.link.Remark)
			server := r.link.Address
			if len(server) > 20 {
				server = server[:17] + "..."
			}
			proto := shortProto(r.link.Protocol)
			var httpsCol string
			switch {
			case r.status == "fail":
				httpsCol = "—"
			case r.httpsOk:
				httpsCol = "✓"
			default:
				httpsCol = "✗"
			}
			if r.status == "ok" {
				fmt.Printf("  %-3d %-8s %-4s %-22s %-6d %-8s %-5s ✅ OK\n", globalIdx, proto, flag, server, r.link.Port, r.latency, httpsCol)
			} else {
				fmt.Printf("  %-3d %-8s %-4s %-22s %-6d %-8s %-5s ❌ FAIL\n", globalIdx, proto, flag, server, r.link.Port, "timeout", httpsCol)
			}
			globalIdx++
		}

		for i := gr.start; i < gr.end; i++ {
			r := results[i]
			if r.status == "ok" && r.httpsOk {
				r.link.HTTPSCapable = 1
			} else if r.status == "ok" && !r.httpsOk {
				r.link.HTTPSCapable = -1
			}
		}
		mgr.SaveGroup(gr.name)
	}

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

	bestDisplayIdx := 1
	var bestLatencyStr, bestGroup string
	displayIdx := 1
	for _, gr := range ranges {
		for i := gr.start; i < gr.end; i++ {
			if results[i].link == sel.Best.Link {
				bestDisplayIdx = displayIdx
				bestLatencyStr = results[i].latency
				bestGroup = gr.name
			}
			displayIdx++
		}
	}

	if totalGroups > 1 {
		fmt.Printf("\n  🏆 Best: #%d [%s] %s:%d (%s) — group '%s'\n",
			bestDisplayIdx, sel.Best.Link.Protocol, sel.Best.Link.Address, sel.Best.Link.Port, bestLatencyStr, bestGroup)
	} else {
		fmt.Printf("\n  🏆 Best: #%d [%s] %s:%d (%s)\n",
			bestDisplayIdx, sel.Best.Link.Protocol, sel.Best.Link.Address, sel.Best.Link.Port, bestLatencyStr)
	}

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
		cmd = buildSSHBenchCmd(ctx, link, port)
		if cmd == nil {
			return "", false, false
		}
	} else {
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

	start := time.Now()
	// Use 1.1.1.1 by IP so bypass_domains (domain-based) never intercepts this request.
	testCmd := exec.CommandContext(ctx, "curl", "-s", "-x", fmt.Sprintf("socks5h://127.0.0.1:%d", port),
		"--connect-timeout", "6", "-o", "/dev/null", "-w", "%{http_code}", "https://1.1.1.1/cdn-cgi/trace")
	out, err := testCmd.Output()
	elapsed := time.Since(start)

	if err != nil || strings.TrimSpace(string(out)) != "200" {
		return "", false, false
	}

	httpsOk = profile.TestHTTPS(ctx, port)

	return fmt.Sprintf("%dms", elapsed.Milliseconds()), true, httpsOk
}

func buildSSHBenchCmd(ctx context.Context, link *profile.Link, port int) *exec.Cmd {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return nil
	}

	sshPort := link.Port
	if sshPort == 0 {
		sshPort = 22
	}

	sshUser := link.SSHUser
	if sshUser == "" {
		sshUser = "root"
	}

	args := []string{
		"-D", fmt.Sprintf("127.0.0.1:%d", port),
		"-N",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=3",
	}

	if link.SSHKeyPath != "" {
		args = append(args, "-i", link.SSHKeyPath)
	}

	args = append(args, "-p", fmt.Sprintf("%d", sshPort))
	args = append(args, fmt.Sprintf("%s@%s", sshUser, link.Address))

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
	if link.Protocol == "ssh" {
		return `{"type":"direct","tag":"proxy"}`
	}

	cg := &tunnel.ConfigGenerator{}
	ob := cg.BuildSingboxOutbound(link)
	if ob == nil {
		return `{"type":"direct","tag":"proxy"}`
	}
	ob["tag"] = "proxy"

	b, err := json.Marshal(ob)
	if err != nil {
		return `{"type":"direct","tag":"proxy"}`
	}
	return string(b)
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
