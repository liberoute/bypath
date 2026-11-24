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
	var ambiguous bool
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
		victim, ambiguous = matchRemark(links, name)
	}
	if ambiguous {
		fmt.Printf("❌ '%s' matches more than one link\n", name)
		fmt.Println("   Use the number from 'bypath list' instead")
		os.Exit(1)
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

// matchRemark resolves a name the way 'bypath list' prints it. The list view
// strips flag emoji, a "provider - " prefix and truncates the name, so
// comparing only the raw remark made every such profile unselectable by the
// name the operator was shown. An exact raw match still wins; a cleaned match
// is accepted only when it is unique.
func matchRemark(links []app.Connection, name string) (*app.Connection, bool) {
	for i := range links {
		if links[i].Remark == name {
			return &links[i], false
		}
	}
	var match *app.Connection
	for i := range links {
		if cleanRemark(links[i].Remark) != name {
			continue
		}
		if match != nil {
			return nil, true
		}
		match = &links[i]
	}
	return match, false
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
