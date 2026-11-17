package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/liberoute/bypath/internal/bench"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
)

const benchUsage = `Usage:
  bypath bench [options]

Benchmark links and show latency, HTTPS support and the best link.

Options:
  -g, --group NAME   Benchmark only this group
  --single N         Test only row #N of 'bypath list -g GROUP' (no selection)
  --auto             Select the best link automatically; still requires --yes,
                     or a 'y' at an interactive prompt
  --yes              Approve selecting the best link without prompting
  -h, --help         Show this help and exit

Selecting a link changes the next-start selection. Nothing is written unless
--yes is given or you answer 'y' at an interactive terminal; a non-interactive
run without --yes never approves a selection change.
`

// benchArgs is the fully validated form of 'bypath bench' arguments.
type benchArgs struct {
	group      string
	single     int
	autoSelect bool
	yes        bool
	help       bool
}

// parseBenchArgs is strict on purpose: an unknown option must never fall
// through to a full benchmark run. It only parses; it performs no I/O.
func parseBenchArgs(args []string) (benchArgs, error) {
	var b benchArgs
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; {
		case arg == "-h" || arg == "--help":
			b.help = true
		case arg == "-g" || arg == "--group":
			value, err := benchFlagValue(args, i, arg)
			if err != nil {
				return b, err
			}
			i++
			b.group = value
		case arg == "--single":
			value, err := benchFlagValue(args, i, arg)
			if err != nil {
				return b, err
			}
			i++
			n := parseIndex(value)
			if n <= 0 {
				return b, fmt.Errorf("invalid link number %q for --single", value)
			}
			b.single = n
		case arg == "--auto":
			b.autoSelect = true
		case arg == "--yes":
			b.yes = true
		case strings.HasPrefix(arg, "-"):
			return b, fmt.Errorf("unknown option %q", arg)
		default:
			return b, fmt.Errorf("unexpected argument %q", arg)
		}
	}
	return b, nil
}

func benchFlagValue(args []string, i int, flag string) (string, error) {
	if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
		return "", fmt.Errorf("%s requires a value", flag)
	}
	return args[i+1], nil
}

// benchDeps isolates the profile store and the network so argument rejection
// and approval handling can be tested without sessions or persistent state.
type benchDeps struct {
	newManager func() (*profile.Manager, error)
	options    func() bench.Options
	runAll     func(context.Context, *profile.Manager, bench.Request, bench.Options) (bench.Report, error)
	probe      func(context.Context, *profile.Link, bench.Options) bench.Probe
}

func productionBenchDeps() benchDeps {
	return benchDeps{
		newManager: func() (*profile.Manager, error) {
			return profile.NewManager(profileDir(), "default")
		},
		options: benchOptions,
		runAll:  bench.Run,
		probe:   bench.ProbeLink,
	}
}

func cmdBench(args []string, stdin io.Reader, stdout io.Writer, interactive bool) int {
	return runBench(args, stdin, stdout, interactive, productionBenchDeps())
}

// runBench validates arguments before touching the profile store, then runs
// the benchmark. A selection is written only after benchSelectionApproved.
func runBench(args []string, stdin io.Reader, stdout io.Writer, interactive bool, deps benchDeps) int {
	req, err := parseBenchArgs(args)
	if err != nil {
		fmt.Fprintf(stdout, "❌ %v\n\n", err)
		fmt.Fprint(stdout, benchUsage)
		return 1
	}
	if req.help {
		fmt.Fprint(stdout, benchUsage)
		return 0
	}
	if req.autoSelect && !req.yes && !interactive {
		fmt.Fprintln(stdout, "❌ --auto needs --yes when stdin is not a terminal; nothing was benchmarked and the selection is unchanged")
		return 1
	}

	mgr, err := deps.newManager()
	if err != nil {
		fmt.Fprintf(stdout, "❌ %v\n", err)
		return 1
	}
	opts := deps.options()

	if req.single > 0 {
		return runBenchSingle(stdout, mgr, req.group, req.single, opts, deps.probe)
	}
	return runBenchAll(stdout, mgr, req, opts, stdin, interactive, deps.runAll)
}

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

// runBenchSingle checks one link chosen by its 'bypath list' row number.
func runBenchSingle(stdout io.Writer, mgr *profile.Manager, targetGroup string, singleIdx int, opts bench.Options, probe func(context.Context, *profile.Link, bench.Options) bench.Probe) int {
	groups := mgr.ListGroups()
	if len(groups) == 0 {
		fmt.Fprintln(stdout, "❌ No groups found")
		return 1
	}
	if targetGroup != "" {
		groups = []string{targetGroup}
	}

	g, err := mgr.GetGroup(groups[0])
	if err != nil {
		fmt.Fprintf(stdout, "❌ Link #%d not found in group '%s'\n", singleIdx, groups[0])
		return 1
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
		fmt.Fprintf(stdout, "❌ Link #%d not found in group '%s'\n", singleIdx, groups[0])
		return 1
	}

	var link *profile.Link
	want := rows[singleIdx-1].Remark
	for _, l := range g.Links {
		if l.Remark == want {
			link = l
			break
		}
	}
	if link == nil {
		fmt.Fprintf(stdout, "❌ Link #%d not found in group '%s'\n", singleIdx, groups[0])
		return 1
	}
	fmt.Fprintf(stdout, "  🔍 Testing [%s] %s → %s:%d\n\n", link.Protocol, link.Remark, link.Address, link.Port)

	p := probe(context.Background(), link, opts)
	if p.PingOK {
		fmt.Fprintf(stdout, "  ✅ Ping: %dms\n", p.Ping.Milliseconds())
	} else {
		fmt.Fprintln(stdout, "  ❌ Ping: timeout")
	}
	if p.Passed {
		fmt.Fprintf(stdout, "  ✅ Relay: %dms\n", p.Latency.Milliseconds())
	} else {
		fmt.Fprintln(stdout, "  ❌ Relay: failed")
	}
	return 0
}

func runBenchAll(stdout io.Writer, mgr *profile.Manager, req benchArgs, opts bench.Options, stdin io.Reader, interactive bool, run func(context.Context, *profile.Manager, bench.Request, bench.Options) (bench.Report, error)) int {
	report, err := run(context.Background(), mgr, bench.Request{Group: req.group}, opts)
	if err != nil {
		switch {
		case errors.Is(err, bench.ErrNoGroups):
			if req.group != "" {
				fmt.Fprintf(stdout, "❌ Group '%s' not found\n", req.group)
			} else {
				fmt.Fprintln(stdout, "❌ No groups found")
			}
		case errors.Is(err, bench.ErrNoLinks):
			fmt.Fprintln(stdout, "❌ No testable links found")
		default:
			fmt.Fprintf(stdout, "❌ %v\n", err)
		}
		return 1
	}

	if len(report.Groups) > 1 {
		fmt.Fprintf(stdout, "  🏁 Benchmarked %d links across %d groups\n", len(report.Rows), len(report.Groups))
	} else {
		group := req.group
		if group == "" && len(report.Groups) == 1 {
			group = report.Groups[0]
		}
		fmt.Fprintf(stdout, "  🏁 Benchmarked %d links in group '%s'\n", len(report.Rows), group)
	}

	printBenchTableTo(stdout, report)

	if report.Best == nil {
		fmt.Fprintln(stdout, "\n  ❌ No working links found!")
		return 0
	}

	bestIdx := benchRowIndex(report.Rows, report.Best.Group, report.Best.Remark) + 1
	bestLatency := fmt.Sprintf("%dms", report.Best.Latency)
	if len(report.Groups) > 1 {
		fmt.Fprintf(stdout, "\n  🏆 Best: #%d [%s] %s:%d (%s) — group '%s'\n",
			bestIdx, report.Best.Protocol, report.Best.Address, report.Best.Port, bestLatency, report.Best.Group)
	} else {
		fmt.Fprintf(stdout, "\n  🏆 Best: #%d [%s] %s:%d (%s)\n",
			bestIdx, report.Best.Protocol, report.Best.Address, report.Best.Port, bestLatency)
	}

	if report.NoHTTPS {
		fmt.Fprintln(stdout, "  ⚠️  No HTTPS-capable links found — selected fastest HTTP link")
	}
	if len(report.Skipped) > 0 {
		fmt.Fprintf(stdout, "  ℹ️  Skipped %d faster link(s) that lack HTTPS support\n", len(report.Skipped))
		for _, sk := range report.Skipped {
			fmt.Fprintf(stdout, "      • %s:%d (%dms)\n", sk.Address, sk.Port, sk.Latency)
		}
	}

	if !benchSelectionApproved(req, stdin, stdout, interactive) {
		if !interactive {
			fmt.Fprintln(stdout, "  ℹ️  Selection unchanged (non-interactive; pass --yes to select the best link).")
		} else {
			fmt.Fprintln(stdout, "  ℹ️  Selection unchanged.")
		}
		return 0
	}

	if err := bench.Activate(mgr, report.Best.Group, report.Best.Remark); err != nil {
		fmt.Fprintf(stdout, "  ❌ %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "  ✅ Selected! Run 'bypath run' to start.")
	return 0
}

// benchSelectionApproved reports whether the next-start selection may change.
// Only an explicit --yes, or a 'y'/'yes' typed at an interactive terminal,
// approves. EOF, an empty line and a closed stdin never do.
func benchSelectionApproved(req benchArgs, stdin io.Reader, stdout io.Writer, interactive bool) bool {
	if req.yes {
		return true
	}
	if !interactive {
		return false
	}
	fmt.Fprint(stdout, "\n  Auto-select this link? [y/N]: ")
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	}
	return false
}

func printBenchTableTo(w io.Writer, report bench.Report) {
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  %-3s %-8s %-4s %-22s %-6s %-8s %-5s %s\n", "#", "Proto", "Flag", "Server", "Port", "Latency", "HTTPS", "Status")
	fmt.Fprintf(w, "  %-3s %-8s %-4s %-22s %-6s %-8s %-5s %s\n", "---", "-----", "----", "------", "------", "-------", "-----", "------")

	multi := len(report.Groups) > 1
	idx := 0
	for _, group := range report.Groups {
		printedHeader := false
		for _, r := range report.Rows {
			if r.Group != group {
				continue
			}
			if multi && !printedHeader {
				fmt.Fprintf(w, "\n  ━━ %s ━━\n", group)
				printedHeader = true
			}
			printBenchRowTo(w, idx+1, r)
			idx++
		}
	}
}

func printBenchRowTo(w io.Writer, idx int, r bench.Row) {
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
	fmt.Fprintf(w, "  %-3d %-8s %-4s %-22s %-6d %-8s %-5s %s\n", idx, proto, flag, server, r.Port, latency, httpsCol, status)
}

func benchRowIndex(rows []bench.Row, group, remark string) int {
	for i, r := range rows {
		if r.Group == group && r.Remark == remark {
			return i
		}
	}
	return 0
}
