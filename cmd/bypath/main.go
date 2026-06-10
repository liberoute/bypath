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
