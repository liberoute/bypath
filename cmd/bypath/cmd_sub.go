package main

import (
	"fmt"
	"os"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
)

func cmdSub(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage:")
		fmt.Println("  bypath sub add <url>       Add subscription URL")
		fmt.Println("  bypath sub update          Fetch latest links")
		fmt.Println("  bypath sub list            Show subscription URLs")
		fmt.Println("  bypath sub remove <index>  Remove subscription by index (from 'sub list')")
		os.Exit(1)
	}

	subCmd := args[0]
	subArgs := args[1:]

	mgr, err := profile.NewManager(profileDir(), "default")
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}

	switch subCmd {
	case "add":
		group := "default"
		var url string
		for i := 0; i < len(subArgs); i++ {
			if (subArgs[i] == "-g" || subArgs[i] == "--group") && i+1 < len(subArgs) {
				group = subArgs[i+1]
				i++
			} else {
				url = subArgs[i]
			}
		}
		if url == "" {
			fmt.Println("❌ No URL provided")
			os.Exit(1)
		}

		if group == "default" {
			group = groupNameFromURL(url)
			fmt.Printf("ℹ️  'default' group is reserved for manual links. Using group '%s'\n", group)
		}

		if _, err := mgr.GetGroup(group); err != nil {
			mgr.CreateGroup(group, "subscription")
		}

		if err := mgr.AddSubscription(group, url); err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Subscription added to group '%s'\n", group)
		fmt.Println("   Run 'bypath sub update -g " + group + "' to fetch links")

	case "update":
		group := ""
		for i := 0; i < len(subArgs); i++ {
			if (subArgs[i] == "-g" || subArgs[i] == "--group") && i+1 < len(subArgs) {
				group = subArgs[i+1]
				i++
			}
		}

		socksPort := 0
		if cfg, err := config.Load(paths.Get().ConfigFile); err == nil {
			socksPort = cfg.Server.SOCKSPort
		}

		if group != "" {
			fmt.Printf("📡 Updating subscriptions for group '%s'...\n", group)
			count, err := mgr.UpdateSubscriptions(group, socksPort)
			if err != nil {
				fmt.Printf("❌ %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("✅ Got %d links\n", count)
		} else {
			groups := mgr.ListGroups()
			totalLinks := 0
			updated := 0
			for _, gName := range groups {
				g, _ := mgr.GetGroup(gName)
				if g == nil || len(g.Subscriptions) == 0 {
					continue
				}
				fmt.Printf("📡 Updating group '%s'...\n", gName)
				count, err := mgr.UpdateSubscriptions(gName, socksPort)
				if err != nil {
					fmt.Printf("  ⚠️  %v\n", err)
					continue
				}
				fmt.Printf("  ✅ Got %d links\n", count)
				totalLinks += count
				updated++
			}
			if updated == 0 {
				fmt.Println("❌ No groups with subscriptions found")
				os.Exit(1)
			}
			fmt.Printf("\n✅ Updated %d groups, total %d links\n", updated, totalLinks)
		}

	case "remove", "rm", "del":
		group := "default"
		var idxStr string
		for i := 0; i < len(subArgs); i++ {
			if (subArgs[i] == "-g" || subArgs[i] == "--group") && i+1 < len(subArgs) {
				group = subArgs[i+1]
				i++
			} else {
				idxStr = subArgs[i]
			}
		}
		if idxStr == "" {
			fmt.Println("❌ No index provided. Use 'bypath sub list' to see indices.")
			os.Exit(1)
		}
		idx := parseIndex(idxStr)
		if idx <= 0 {
			fmt.Println("❌ Invalid index")
			os.Exit(1)
		}

		if err := mgr.RemoveSubscription(group, idx-1); err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Subscription #%d removed from group '%s'\n", idx, group)

	case "list":
		group := "default"
		for i := 0; i < len(subArgs); i++ {
			if (subArgs[i] == "-g" || subArgs[i] == "--group") && i+1 < len(subArgs) {
				group = subArgs[i+1]
				i++
			}
		}

		g, err := mgr.GetGroup(group)
		if err != nil {
			fmt.Printf("❌ Group '%s' not found\n", group)
			os.Exit(1)
		}
		if len(g.Subscriptions) == 0 {
			fmt.Printf("No subscriptions in group '%s'\n", group)
			return
		}
		fmt.Printf("Subscriptions in group '%s':\n\n", group)
		for i, url := range g.Subscriptions {
			fmt.Printf("  %d. %s\n", i+1, url)
		}

	default:
		fmt.Printf("Unknown sub command: %s\n", subCmd)
		os.Exit(1)
	}
}
