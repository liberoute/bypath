package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/diag"
	"github.com/liberoute/bypath/internal/paths"
)

func cmdDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	jsonOut := fs.Bool("json", false, "emit the structured report on stdout")
	configPath := fs.String("config", "", "configuration file (default: the installation's)")
	configShort := fs.String("c", "", "alias for --config")
	egress := fs.Bool("egress", false, "measure the tunnel and direct exit addresses (sends network requests)")
	verbose := fs.Bool("v", false, "print detail lines for every check")
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	path := strings.TrimSpace(*configPath)
	if path == "" {
		path = strings.TrimSpace(*configShort)
	}
	if path == "" {
		path = paths.Get().ConfigFile
	}

	opts := diag.Options{ConfigPath: path, Host: diag.DefaultHost()}
	if *egress {
		opts.Egress = liveEgress(path)
	}
	report := diag.Run(context.Background(), opts)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "❌ %v\n", err)
			os.Exit(1)
		}
	} else {
		printDoctor(report, *verbose)
	}
	if report.Summary.Fail > 0 {
		os.Exit(1)
	}
}

// liveEgress queries the running gateway. When no gateway is listening the
// check reports that instead of starting one.
func liveEgress(configPath string) func(context.Context) (diag.Egress, error) {
	return func(ctx context.Context) (diag.Egress, error) {
		cfg, err := config.Load(configPath)
		if err != nil {
			return diag.Egress{}, err
		}
		p := paths.Get()
		var remote *app.Remote
		if p.ControlSocket != "" {
			if _, statErr := os.Stat(p.ControlSocket); statErr == nil {
				remote = app.NewRemoteSocket(p.ControlSocket)
			}
		}
		if remote == nil {
			remote = app.RemoteFromConfig(cfg)
		}
		check, err := remote.CheckEgress(ctx)
		if err != nil {
			return diag.Egress{}, err
		}
		return diag.Egress{
			Tunnel:      check.TunnelExit,
			TunnelError: check.TunnelError,
			Direct:      check.DirectIP,
			DirectError: check.DirectError,
			Same:        check.Same,
			Note:        check.Note,
		}, nil
	}
}

func printDoctor(report *diag.Report, verbose bool) {
	fmt.Printf("%s doctor — %s %s (%s, %s/%s)\n", report.Tool, report.Version, report.Commit, report.Variant, report.OS, report.Arch)
	fmt.Printf("config: %s\n", report.ConfigPath)
	fmt.Printf("generated: %s · read-only: %t\n\n", report.GeneratedAt, report.ReadOnly)
	for _, c := range report.Checks {
		fmt.Printf("%s %-14s %s\n", statusGlyph(c.Status), c.Title, c.Summary)
		if verbose || c.Status == diag.Fail || c.Status == diag.Warn {
			for _, line := range c.Detail {
				fmt.Printf("     · %s\n", line)
			}
		}
		if c.Remediation != "" && (verbose || c.Status == diag.Fail || c.Status == diag.Warn) {
			fmt.Printf("     → %s\n", c.Remediation)
		}
	}
	fmt.Printf("\n%d pass · %d warn · %d fail · %d skip · %d info\n",
		report.Summary.Pass, report.Summary.Warn, report.Summary.Fail, report.Summary.Skip, report.Summary.Info)
	if report.Summary.Fail > 0 {
		fmt.Println("Fix the failing checks above; doctor changes nothing on its own.")
	}
}

func statusGlyph(s diag.Status) string {
	switch s {
	case diag.Pass:
		return "✅"
	case diag.Warn:
		return "⚠️ "
	case diag.Fail:
		return "❌"
	case diag.Skip:
		return "⏭️ "
	default:
		return "ℹ️ "
	}
}
