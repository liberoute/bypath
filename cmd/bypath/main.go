package main

import (
	"fmt"
	"io"
	"os"

	"github.com/liberoute/bypath/internal/build"
	"golang.org/x/term"
)

func main() {
	ignoreSIGPIPE()
	os.Exit(runCLI(os.Args[1:], os.Stdout, isTerminal(os.Stdin) && isTerminal(os.Stdout)))
}

// runCLI keeps the dispatch table pure so help and error output are testable
// without a terminal, a TUI or a subprocess.
func runCLI(args []string, stdout io.Writer, interactive bool) int {
	if len(args) == 0 {
		// Without a terminal the TUI cannot initialise; printing usage is the
		// documented behaviour and never crashes a piped or service launch.
		if !interactive {
			printUsageTo(stdout)
			return 0
		}
		openTUI()
		return 0
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "run", "start":
		cmdRun(rest)
	case "add":
		cmdAdd(rest)
	case "remove", "rm", "del":
		cmdRemove(rest)
	case "list":
		cmdList(rest)
	case "select":
		cmdSelect(rest)
	case "bench":
		cmdBench(rest)
	case "stop":
		cmdStop(rest)
	case "status":
		cmdStatus(rest)
	case "test":
		cmdTest(rest)
	case "sub":
		cmdSub(rest)
	case "layer":
		cmdLayer(rest)
	case "group", "groups":
		cmdGroup(rest)
	case "chain":
		cmdChain(rest)
	case "service-worker":
		cmdServiceWorker(rest)
	case "host-dns":
		// Internal: the systemd unit's ExecStartPre/ExecStopPost hook that
		// restores the host resolver after an abnormal daemon exit.
		cmdHostDNS(rest)
	case "test-worker":
		// Internal: started by a daemon that runs inside the gateway network
		// namespace so an isolated measurement can execute in the host
		// namespace instead. Not part of the operator interface.
		cmdTestWorker(rest)
	case "engines":
		cmdEngines(rest)
	case "doctor":
		cmdDoctor(rest)
	case "setup":
		cmdSetup(rest)
	case "geo":
		cmdGeo(rest)
	case "update":
		cmdUpdate()
	case "version", "-v", "--version":
		dir, preferSystem := diagnosticEngines(rest)
		fmt.Print(build.PrintVersionInfo(dir, preferSystem))
	case "help", "-h", "--help":
		printUsageTo(stdout)
	default:
		fmt.Fprintf(stdout, "Unknown command: %s\n\n", cmd)
		printUsageTo(stdout)
		return 1
	}
	return 0
}

func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

func printUsage() {
	printUsageTo(os.Stdout)
}

func printUsageTo(w io.Writer) {
	// A closed pipe (for example `bypath --help | head`) must not turn help
	// into a crash: the text is best-effort and the exit code stays zero.
	fmt.Fprintf(w, `%s — Network Gateway & Tunnel Manager

Usage:
  bypath [command] [options]

  Run without a command to open the terminal menu (TUI).

Commands:
  run                     Start the gateway (main command)
    -c, --config PATH     Config file (default: configs/default.yaml)

  add <uri|profile.ovpn>  Add a proxy link or import an OpenVPN profile
    -g, --group NAME      Target group (default: "default")
    --name NAME           Display name (OpenVPN import)
    --auth-file PATH      Username/password file (OpenVPN import)

  list                    List all links in active group
    -g, --group NAME      Specific group

  select <name|number>    Set active link

  bench                   Test ALL links, show speed, auto-select best
    -g, --group NAME      Specific group

  sub add [-g group] <url>     Add a subscription URL
  sub preview <url|file>       Show what a subscription contains without storing it
  sub update [-g group]        Fetch latest links
  sub import [-g group] <file> Import links from a local dump (plain/base64)
  sub list [-g group]          Show subscriptions (URLs are redacted)
  sub remove [-g group] <#>    Remove a subscription by index
  sub dedupe                   Remove duplicate subscription URLs

  layer status                 Show organisation-layer state
  layer plan                   Show the first-run migration plan (no writes)
  layer migrate [--dry-run]    Migrate stable identities and groups
  layer rollback [--confirm]   Restore the migration backup

  group list                   List organisation groups
  group create <name>          Create an organisation group
  group rename <id> <name>     Rename a group
  group delete <id> [--members] Delete a group (members only with --members)
  group move <ids...> [--to G] Move connections between groups
  group name <id> <name>       Set a product display name
  group hide|unhide <ids...>   Hide or restore connections in the product view

  test <uri|file>         Test a config/link without starting gateway
    -e, --engine NAME     Force engine (sing-box, xray, auto)

  engines                 Show available engines and their status

  setup                   First-run configuration wizard
    --non-interactive     Take every answer from flags (see 'bypath setup --help')
    --dry-run             Show the resulting configuration without writing it
    --install-packages    Approve apt installation of missing gateway packages

  doctor                  Read-only installation and safety report
    --json                Structured output for automation
    --egress              Also compare the tunnel exit with the direct address

  geo update              Download/refresh geoip & geosite databases
  geo status              Show installed databases and rule coverage

  update                  Check for updates

  status                  Show what the running gateway is doing
    --json                Structured output for automation

  stop                    Stop the gateway
    --purge-firewall      Also remove retained fail-closed LAN containment

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
