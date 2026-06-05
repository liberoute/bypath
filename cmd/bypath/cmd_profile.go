package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/liberoute/bypath/internal/profile"
)

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

	link, err := profile.ParseURI(uri)
	if err != nil {
		fmt.Printf("❌ Invalid URI: %v\n", err)
		os.Exit(1)
	}

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

	if group == "" {
		group = "default"
	}

	if target == "all" {
		g, err := mgr.GetGroup(group)
		if err != nil {
			fmt.Printf("❌ Group '%s' not found\n", group)
			os.Exit(1)
		}
		count := len(g.Links)
		g.Links = nil
		data := fmt.Sprintf(`{"name":"%s","type":"%s","links":[],"subscriptions":%s}`,
			g.Name, g.Type, mustJSON(g.Subscriptions))
		os.WriteFile(filepath.Join(profileDir(), group+".json"), []byte(data), 0644)
		fmt.Printf("✅ Removed all %d links from group '%s'\n", count, group)
		return
	}

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
			continue
		}
		proto := shortProto(link.Protocol)
		flag := extractFlag(link.Remark)
		name := cleanRemark(link.Remark)
		server := link.Address
		if len(server) > 20 {
			server = server[:17] + "..."
		}
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
