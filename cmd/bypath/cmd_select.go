package main

import (
	"fmt"
	"os"

	"github.com/liberoute/bypath/internal/profile"
)

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

	if idx := parseIndex(name); idx > 0 {
		if group != "" {
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
