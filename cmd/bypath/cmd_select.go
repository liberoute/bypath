package main

import (
	"context"
	"fmt"
	"os"

	"github.com/liberoute/bypath/internal/app"
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
	if group != "" && len(links) == 0 {
		fmt.Printf("❌ Group '%s' has no usable links\n", group)
		os.Exit(1)
	}

	var victim *app.Connection
	if idx := parseIndex(name); idx > 0 {
		if group != "" {
			if idx <= len(links) {
				victim = &links[idx-1]
			}
		} else {
			// Index is per group, matching 'bypath list'.
			counts := make(map[string]int)
			for i := range links {
				counts[links[i].Group]++
				if counts[links[i].Group] == idx {
					victim = &links[i]
					break
				}
			}
		}
	} else {
		for i := range links {
			if links[i].Remark == name {
				victim = &links[i]
				break
			}
		}
	}
	if victim == nil {
		fmt.Printf("❌ Link '%s' not found\n", name)
		fmt.Println("   Use 'bypath list' to see available links")
		os.Exit(1)
	}

	res, err := svc.SetActive(ctx, victim.ID)
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Active link: [%s] %s → %s:%d\n", victim.Protocol, victim.Remark, victim.Address, victim.Port)
	warnIfCDN(victim)
	fmt.Printf("  ℹ️  %s\n", res.Message)
}

func warnIfCDN(link *app.Connection) {
	if link.CDN || link.Health == "failed" {
		fmt.Println("  ⚠️  This link is CDN-based or failed validation and may not support HTTPS browsing")
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
