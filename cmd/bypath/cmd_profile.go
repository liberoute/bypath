package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/liberoute/bypath/internal/app"
)

func cmdAdd(args []string) {
	// OpenVPN profiles are files, not URIs.
	for _, arg := range args {
		if isOVPNPath(arg) {
			cmdAddOVPN(args)
			return
		}
	}

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

	svc, err := openService()
	if err != nil {
		fmt.Printf("❌ Profile error: %v\n", err)
		os.Exit(1)
	}
	res, err := svc.ImportURI(context.Background(), group, uri)
	if err != nil {
		fmt.Printf("❌ Add failed: %v\n", err)
		os.Exit(1)
	}
	if len(res.Created) == 0 {
		reason := "already exists"
		if len(res.Skipped) > 0 {
			reason = res.Skipped[0].Reason
		}
		fmt.Printf("ℹ️  Not added: %s\n", reason)
		return
	}
	c := res.Created[0]
	fmt.Printf("✅ Added [%s] %s → %s:%d (group: %s)\n", c.Protocol, c.Remark, c.Address, c.Port, c.Group)
}

func cmdRemove(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: bypath remove <name|number> [-g group] [--replace ID | --leave-unset]")
		fmt.Println("       bypath remove all [-g group]   (remove all links in group)")
		fmt.Println("A connection that carries traffic is refused; deleting the next-start")
		fmt.Println("selection needs --replace or --leave-unset.")
		os.Exit(1)
	}

	group := ""
	var target string
	for i := 0; i < len(args); i++ {
		switch {
		case (args[i] == "-g" || args[i] == "--group") && i+1 < len(args):
			group = args[i+1]
			i++
		case args[i] == "--replace" || args[i] == "-r":
			i++ // the replacement id is not the target
		case args[i] == "--leave-unset" || args[i] == "--acknowledge-unset":
		default:
			target = args[i]
		}
	}
	opts, err := parseDeleteOptions(args)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}

	if target == "" {
		fmt.Println("❌ No link name or number provided")
		os.Exit(1)
	}
	if group == "" {
		group = "default"
	}

	svc, err := openService()
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}
	ctx := context.Background()
	links, err := svc.ListConnections(ctx, app.ConnectionFilter{Group: group})
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}

	if target == "all" {
		for _, c := range links {
			if err := svc.DeleteConnectionWithOptions(ctx, c.ID, opts); err != nil {
				fmt.Printf("❌ %s: %v\n", c.Remark, err)
				os.Exit(1)
			}
		}
		fmt.Printf("✅ Removed all %d links from group '%s'\n", len(links), group)
		return
	}

	var victim *app.Connection
	if idx := parseIndex(target); idx > 0 {
		if idx > len(links) {
			fmt.Printf("❌ Link #%d not found (group has %d links)\n", idx, len(links))
			os.Exit(1)
		}
		victim = &links[idx-1]
	} else {
		for i := range links {
			if links[i].Remark == target {
				victim = &links[i]
				break
			}
		}
	}
	if victim == nil {
		fmt.Printf("❌ '%s' not found in group '%s'\n", target, group)
		os.Exit(1)
	}
	if err := svc.DeleteConnectionWithOptions(ctx, victim.ID, opts); err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Removed [%s] %s from group '%s'\n", victim.Protocol, victim.Remark, group)
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

	// Always go through the shared service: when a daemon owns the profiles
	// (and an unprivileged account may only reach it through the control
	// socket), reading the profile directory directly would show an empty or
	// stale view.
	svc, err := openService()
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}
	conns, err := svc.ListConnections(context.Background(), app.ConnectionFilter{Group: group})
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}
	if len(conns) == 0 {
		if group != "" {
			fmt.Printf("No links in group '%s'\n", group)
			return
		}
		fmt.Println("No groups found. Use 'bypath sub add <url>' to add a subscription.")
		return
	}

	groups := make(map[string][]app.Connection)
	var names []string
	for _, c := range conns {
		if _, seen := groups[c.Group]; !seen {
			names = append(names, c.Group)
		}
		groups[c.Group] = append(groups[c.Group], c)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Printf("\n━━ %s (%d links) ━━\n", name, len(groups[name]))
		printConnections(groups[name])
	}
}

func printConnections(conns []app.Connection) {
	if len(conns) == 0 {
		fmt.Println("  (empty)")
		return
	}
	fmt.Printf("  %-3s %-8s %-4s %-22s %-6s %s\n", "#", "Proto", "Flag", "Server", "Port", "Name")
	fmt.Printf("  %-3s %-8s %-4s %-22s %-6s %s\n", "---", "-----", "----", "------", "----", "----")
	for i, c := range conns {
		proto := shortProto(c.Protocol)
		flag := extractFlag(c.Remark)
		name := cleanRemark(c.Remark)
		server := c.Address
		if len(server) > 20 {
			server = server[:17] + "..."
		}
		var status string
		if c.CDN {
			status += " [CDN]"
		}
		if c.Active {
			status += " [active]"
		}
		fmt.Printf("  %-3d %-8s %-4s %-22s %-6d %s%s\n", i+1, proto, flag, server, c.Port, name, status)
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
