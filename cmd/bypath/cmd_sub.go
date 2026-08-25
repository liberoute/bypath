package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
)

// (sub import uses profile.ImportSubscriptionFile)

func cmdSub(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage:")
		fmt.Println("  bypath sub add <url>       Add subscription URL")
		fmt.Println("  bypath sub update          Fetch latest links")
		fmt.Println("  bypath sub import <file>   Import links from a local sub dump (plain/base64)")
		fmt.Println("  bypath sub list [all]      Show subscription URLs (all groups if no -g)")
		fmt.Println("  bypath sub dedupe          Remove duplicate subscription URLs")
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
		explicitGroup := false
		var url string
		for i := 0; i < len(subArgs); i++ {
			if (subArgs[i] == "-g" || subArgs[i] == "--group") && i+1 < len(subArgs) {
				group = subArgs[i+1]
				explicitGroup = true
				i++
			} else {
				url = subArgs[i]
			}
		}
		if url == "" {
			fmt.Println("❌ No URL provided")
			os.Exit(1)
		}

		// Desired name from URL #remark (v2rayN convention) or domain.
		desiredFromURL := groupNameFromURL(url)

		// Already registered anywhere? reuse — optionally rename domain group → #remark.
		if existing, ok := mgr.FindSubscription(url); ok {
			final := existing
			if !explicitGroup && desiredFromURL != "" && desiredFromURL != existing {
				if _, err := mgr.GetGroup(desiredFromURL); err != nil {
					if err := mgr.RenameGroup(existing, desiredFromURL); err == nil {
						fmt.Printf("ℹ️  Already existed as '%s' — renamed to '%s' (from URL #remark)\n", existing, desiredFromURL)
						final = desiredFromURL
					} else {
						fmt.Printf("ℹ️  Already exists in group '%s' (rename to '%s' failed: %v)\n", existing, desiredFromURL, err)
					}
				} else {
					fmt.Printf("ℹ️  Already exists in group '%s' (target name '%s' already taken)\n", existing, desiredFromURL)
				}
			} else {
				fmt.Printf("ℹ️  Already exists in group '%s' — not adding duplicate\n", existing)
			}
			fmt.Println("   Run 'bypath sub update -g " + final + "' to refresh links")
			return
		}

		if !explicitGroup {
			group = desiredFromURL
			if strings.Contains(url, "#") {
				fmt.Printf("ℹ️  Using group '%s' from URL #remark\n", group)
			} else {
				fmt.Printf("ℹ️  'default' group is reserved for manual links. Using group '%s'\n", group)
			}
		}

		if _, err := mgr.GetGroup(group); err != nil {
			if err := mgr.CreateGroup(group, "subscription"); err != nil {
				fmt.Printf("❌ %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("📁 Created group '%s'\n", group)
		} else if !explicitGroup {
			fmt.Printf("ℹ️  Group '%s' already exists — adding URL there\n", group)
		}

		if err := mgr.AddSubscription(group, url); err != nil {
			if errors.Is(err, profile.ErrSubscriptionExists) {
				fmt.Printf("ℹ️  %v\n", err)
				return
			}
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

	case "import":
		group := "default"
		var filePath string
		for i := 0; i < len(subArgs); i++ {
			if (subArgs[i] == "-g" || subArgs[i] == "--group") && i+1 < len(subArgs) {
				group = subArgs[i+1]
				i++
			} else {
				filePath = subArgs[i]
			}
		}
		if filePath == "" {
			fmt.Println("❌ Usage: bypath sub import [-g group] <file>")
			os.Exit(1)
		}
		if group == "default" {
			group = "imported"
			fmt.Printf("ℹ️  Using group '%s'\n", group)
		}
		if _, err := mgr.GetGroup(group); err != nil {
			mgr.CreateGroup(group, "subscription")
		}
		count, err := mgr.ImportSubscriptionFile(group, filePath)
		if err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Imported %d links into group '%s'\n", count, group)

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
		group := ""
		listAll := true
		for i := 0; i < len(subArgs); i++ {
			if (subArgs[i] == "-g" || subArgs[i] == "--group") && i+1 < len(subArgs) {
				group = subArgs[i+1]
				listAll = false
				i++
			} else if subArgs[i] == "all" {
				listAll = true
			}
		}

		if !listAll && group != "" {
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
			return
		}

		// All groups
		found := false
		for _, gName := range mgr.ListGroups() {
			g, _ := mgr.GetGroup(gName)
			if g == nil || len(g.Subscriptions) == 0 {
				continue
			}
			found = true
			fmt.Printf("━━ %s (%d) ━━\n", gName, len(g.Subscriptions))
			for i, url := range g.Subscriptions {
				fmt.Printf("  %d. %s\n", i+1, url)
			}
			fmt.Println()
		}
		if !found {
			fmt.Println("No subscriptions in any group")
		}

	case "dedupe":
		n, err := mgr.DedupeSubscriptions()
		if err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
		if n == 0 {
			fmt.Println("✅ No duplicate subscriptions")
		} else {
			fmt.Printf("✅ Removed %d duplicate subscription entry(ies)\n", n)
		}

	default:
		fmt.Printf("Unknown sub command: %s\n", subCmd)
		os.Exit(1)
	}
}
