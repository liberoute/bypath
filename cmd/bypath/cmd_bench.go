package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/liberoute/bypath/internal/bench"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
)

// benchOptions mirrors the daemon's engine selection and SSH trust policy so a
// CLI benchmark row is judged exactly like the connection the gateway starts.
func benchOptions() bench.Options {
	opts := bench.Options{
		HostKeyPolicy: config.SSHHostKeyAcceptNew,
		TmpDir:        tmpDir(),
		EngineDir:     engineDir(),
	}
	cfg, err := config.Load(paths.Get().ConfigFile)
	if err == nil {
		opts.HostKeyPolicy = cfg.Server.SSHHostKey
		opts.PreferredEngine = cfg.Engines.PreferredEngine
		opts.EngineOrder = cfg.Engines.Fallback.Order
		opts.FallbackEnabled = cfg.Engines.Fallback.Enabled
	}
	return opts
}

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
	opts := benchOptions()

	if singleIdx > 0 {
		runBenchSingle(mgr, targetGroup, singleIdx, opts)
		return
	}
	runBenchAll(mgr, targetGroup, autoSelect, opts)
}

// runBenchSingle checks one link chosen by its 'bypath list' row number.
func runBenchSingle(mgr *profile.Manager, targetGroup string, singleIdx int, opts bench.Options) {
	groups := mgr.ListGroups()
	if len(groups) == 0 {
		fmt.Println("❌ No groups found")
		os.Exit(1)
	}
	if targetGroup != "" {
		groups = []string{targetGroup}
	}

	g, err := mgr.GetGroup(groups[0])
	if err != nil {
		fmt.Printf("❌ Link #%d not found in group '%s'\n", singleIdx, groups[0])
		os.Exit(1)
	}
	// 'bypath list' numbers only routable links by remark, not by storage
	// order; --single must pick the same row the operator saw.
	var rows []bench.Row
	for _, l := range g.Links {
		if bench.Benchable(l) {
			rows = append(rows, bench.Row{Remark: l.Remark})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Remark < rows[j].Remark })
	if singleIdx > len(rows) {
		fmt.Printf("❌ Link #%d not found in group '%s'\n", singleIdx, groups[0])
		os.Exit(1)
	}

	var link *profile.Link
	want := rows[singleIdx-1].Remark
	for _, l := range g.Links {
		if l.Remark == want {
			link = l
			break
		}
	}
	fmt.Printf("  🔍 Testing [%s] %s → %s:%d\n\n", link.Protocol, link.Remark, link.Address, link.Port)

	p := bench.ProbeLink(context.Background(), link, opts)
	if p.PingOK {
		fmt.Printf("  ✅ Ping: %dms\n", p.Ping.Milliseconds())
	} else {
		fmt.Printf("  ❌ Ping: timeout\n")
	}
	if p.Passed {
		fmt.Printf("  ✅ Relay: %dms\n", p.Latency.Milliseconds())
	} else {
		fmt.Printf("  ❌ Relay: failed\n")
	}
}

func runBenchAll(mgr *profile.Manager, targetGroup string, autoSelect bool, opts bench.Options) {
	report, err := bench.Run(context.Background(), mgr, bench.Request{Group: targetGroup}, opts)
	if err != nil {
		switch {
		case errors.Is(err, bench.ErrNoGroups):
			if targetGroup != "" {
				fmt.Printf("❌ Group '%s' not found\n", targetGroup)
			} else {
				fmt.Println("❌ No groups found")
			}
		case errors.Is(err, bench.ErrNoLinks):
			fmt.Println("❌ No testable links found")
		default:
			fmt.Printf("❌ %v\n", err)
		}
		os.Exit(1)
	}

	if len(report.Groups) > 1 {
		fmt.Printf("  🏁 Benchmarked %d links across %d groups\n", len(report.Rows), len(report.Groups))
	} else {
		fmt.Printf("  🏁 Benchmarked %d links in group '%s'\n", len(report.Rows), report.Groups[0])
	}

	printBenchTable(report)

	if report.Best == nil {
		fmt.Println("\n  ❌ No working links found!")
		return
	}

	bestIdx := benchRowIndex(report.Rows, report.Best.Group, report.Best.Remark) + 1
	bestLatency := fmt.Sprintf("%dms", report.Best.Latency)
	if len(report.Groups) > 1 {
		fmt.Printf("\n  🏆 Best: #%d [%s] %s:%d (%s) — group '%s'\n",
			bestIdx, report.Best.Protocol, report.Best.Address, report.Best.Port, bestLatency, report.Best.Group)
	} else {
		fmt.Printf("\n  🏆 Best: #%d [%s] %s:%d (%s)\n",
			bestIdx, report.Best.Protocol, report.Best.Address, report.Best.Port, bestLatency)
	}

	if report.NoHTTPS {
		fmt.Println("  ⚠️  No HTTPS-capable links found — selected fastest HTTP link")
	}
	if len(report.Skipped) > 0 {
		fmt.Printf("  ℹ️  Skipped %d faster link(s) that lack HTTPS support\n", len(report.Skipped))
		for _, sk := range report.Skipped {
			fmt.Printf("      • %s:%d (%dms)\n", sk.Address, sk.Port, sk.Latency)
		}
	}

	if autoSelect {
		if err := bench.Activate(mgr, report.Best.Group, report.Best.Remark); err != nil {
			fmt.Printf("  ❌ %v\n", err)
			return
		}
		fmt.Printf("  ✅ Auto-selected! Run 'bypath run' to start.\n")
		return
	}

	fmt.Printf("\n  Auto-select this link? [Y/n]: ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	if input == "" || input == "y" || input == "yes" {
		if err := bench.Activate(mgr, report.Best.Group, report.Best.Remark); err != nil {
			fmt.Printf("  ❌ %v\n", err)
			return
		}
		fmt.Printf("  ✅ Selected! Run 'bypath run' to start.\n")
	}
}

func printBenchTable(report bench.Report) {
	fmt.Println()
	fmt.Printf("  %-3s %-8s %-4s %-22s %-6s %-8s %-5s %s\n", "#", "Proto", "Flag", "Server", "Port", "Latency", "HTTPS", "Status")
	fmt.Printf("  %-3s %-8s %-4s %-22s %-6s %-8s %-5s %s\n", "---", "-----", "----", "------", "----", "-------", "-----", "------")

	multi := len(report.Groups) > 1
	idx := 0
	for _, group := range report.Groups {
		printedHeader := false
		for _, r := range report.Rows {
			if r.Group != group {
				continue
			}
			if multi && !printedHeader {
				fmt.Printf("\n  ━━ %s ━━\n", group)
				printedHeader = true
			}
			printBenchRow(idx+1, r)
			idx++
		}
	}
}

func printBenchRow(idx int, r bench.Row) {
	flag := extractFlag(r.Remark)
	server := r.Address
	if len(server) > 20 {
		server = server[:17] + "..."
	}
	proto := shortProto(r.Protocol)
	httpsCol := "✗"
	if !r.Passed {
		httpsCol = "—"
	} else if r.HTTPS {
		httpsCol = "✓"
	}
	latency := fmt.Sprintf("%dms", r.Latency)
	status := "✅ OK"
	if !r.Passed {
		latency = "timeout"
		status = "❌ FAIL"
	}
	fmt.Printf("  %-3d %-8s %-4s %-22s %-6d %-8s %-5s %s\n", idx, proto, flag, server, r.Port, latency, httpsCol, status)
}

func benchRowIndex(rows []bench.Row, group, remark string) int {
	for i, r := range rows {
		if r.Group == group && r.Remark == remark {
			return i
		}
	}
	return 0
}
