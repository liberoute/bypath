package main

import (
	"fmt"
	"os"

	"github.com/liberoute/bypath/internal/build"
)

func main() {
	if len(os.Args) < 2 {
		openTUI()
		os.Exit(0)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "run", "start":
		cmdRun(args)
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
		cmdStop(args)
	case "status":
		cmdStatus(args)
	case "test":
		cmdTest(args)
	case "sub":
		cmdSub(args)
	case "layer":
		cmdLayer(args)
	case "group", "groups":
		cmdGroup(args)
	case "chain":
		cmdChain(args)
	case "service-worker":
		cmdServiceWorker(args)
	case "host-dns":
		// Internal: the systemd unit's ExecStartPre/ExecStopPost hook that
		// restores the host resolver after an abnormal daemon exit.
		cmdHostDNS(args)
	case "test-worker":
		// Internal: started by a daemon that runs inside the gateway network
		// namespace so an isolated measurement can execute in the host
		// namespace instead. Not part of the operator interface.
		cmdTestWorker(args)
	case "engines":
		cmdEngines(args)
	case "doctor":
		cmdDoctor(args)
	case "setup":
		cmdSetup(args)
	case "geo":
		cmdGeo(args)
	case "update":
		cmdUpdate()
	case "version", "-v", "--version":
		dir, preferSystem := diagnosticEngines(args)
		fmt.Print(build.PrintVersionInfo(dir, preferSystem))
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
