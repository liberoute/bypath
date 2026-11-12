package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/liberoute/bypath/internal/app"
)

// cmdSub drives subcommands through the shared application service so the CLI
// and the TUI cannot disagree about subscription state.
func cmdSub(args []string) {
	if len(args) == 0 {
		printSubUsage()
		os.Exit(1)
	}
	subCmd := args[0]
	subArgs := args[1:]

	svc, err := openService()
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}
	ctx := context.Background()

	switch subCmd {
	case "add":
		group, rest := subGroupFlag(subArgs)
		url := lastArg(rest)
		if url == "" {
			fmt.Println("❌ No URL provided")
			printSubUsage()
			os.Exit(1)
		}
		if group == "" {
			group = groupNameFromURL(url)
			if group == "" || group == "default" {
				group = "sub"
			}
			if strings.Contains(url, "#") {
				fmt.Printf("ℹ️  Using group '%s' from URL #remark\n", group)
			} else {
				fmt.Printf("ℹ️  Using group '%s' derived from the URL host\n", group)
			}
		}
		sub, err := svc.AddSubscription(ctx, group, url)
		if err != nil {
			if app.CodeOf(err) == app.CodeConflict {
				fmt.Printf("ℹ️  %v\n", err)
				fmt.Println("   Run 'bypath sub update -g " + group + "' to refresh links")
				return
			}
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Subscription added to group '%s'\n", sub.Group)
		fmt.Println("   Run 'bypath sub preview <url>' to see what it contains without storing it")
		fmt.Println("   Run 'bypath sub update -g " + sub.Group + "' to fetch links")

	case "update":
		group, _ := subGroupFlag(subArgs)
		list, err := svc.ListSubscriptions(ctx)
		if err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
		list = filterSubscriptions(list, group)
		if len(list) == 0 {
			if group != "" {
				fmt.Printf("❌ No subscriptions in group '%s'\n", group)
			} else {
				fmt.Println("❌ No subscriptions found")
			}
			os.Exit(1)
		}

		ok, failed := 0, 0
		for _, sub := range list {
			fmt.Printf("📡 Updating %s (%s)...\n", sub.Group, sub.RedactedURL)
			refreshed, err := svc.RefreshSubscription(ctx, sub.Group, sub.URL, nil)
			if err != nil {
				failed++
				fmt.Printf("  ⚠️  %v\n", err)
				continue
			}
			ok++
			fmt.Printf("  ✅ Got %d links\n", refreshed.LinkCount)
		}
		if ok == 0 {
			fmt.Printf("❌ All %d subscription(s) failed to refresh\n", failed)
			os.Exit(1)
		}
		fmt.Printf("\n✅ Updated %d of %d subscription(s)\n", ok, ok+failed)

	case "preview":
		target := lastArg(subArgs)
		if target == "" {
			fmt.Println("❌ Usage: bypath sub preview <url|file>")
			os.Exit(1)
		}
		var preview app.SubscriptionPreview
		if info, statErr := os.Stat(target); statErr == nil && !info.IsDir() {
			text, err := readSubscriptionFile(target)
			if err != nil {
				fmt.Printf("❌ %v\n", err)
				os.Exit(1)
			}
			preview, err = svc.PreviewSubscriptionText(ctx, text)
			if err != nil {
				fmt.Printf("❌ %v\n", err)
				os.Exit(1)
			}
		} else {
			var err error
			preview, err = svc.PreviewSubscription(ctx, target)
			if err != nil {
				fmt.Printf("❌ %v\n", err)
				os.Exit(1)
			}
		}
		printSubscriptionPreview(preview)

	case "import":
		group, rest := subGroupFlag(subArgs)
		filePath := lastArg(rest)
		if filePath == "" {
			fmt.Println("❌ Usage: bypath sub import [-g group] <file>")
			os.Exit(1)
		}
		if group == "" || group == "default" {
			group = "imported"
		}
		text, err := readSubscriptionFile(filePath)
		if err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
		res, err := svc.ImportSubscriptionText(ctx, group, text)
		if err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Imported %d link(s) into group '%s'\n", len(res.Created), res.Group)
		if len(res.Skipped) > 0 {
			fmt.Printf("   Skipped %d duplicate/invalid entry(ies)\n", len(res.Skipped))
		}

	case "remove", "rm", "del":
		group, rest := subGroupFlag(subArgs)
		idx := parseIndex(lastArg(rest))
		if idx <= 0 {
			fmt.Println("❌ No valid index provided. Use 'bypath sub list' to see indices.")
			os.Exit(1)
		}
		list, err := svc.ListSubscriptions(ctx)
		if err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
		list = filterSubscriptions(list, group)
		if idx > len(list) {
			fmt.Printf("❌ Index %d out of range (%d subscription(s))\n", idx, len(list))
			os.Exit(1)
		}
		victim := list[idx-1]
		opts, optErr := parseDeleteOptions(subArgs)
		if optErr != nil {
			fmt.Printf("❌ %v\n", optErr)
			os.Exit(1)
		}
		if err := svc.RemoveSubscriptionWithOptions(ctx, victim.Group, victim.URL, opts); err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ Removed %s from group '%s' (and its linked servers)\n", victim.RedactedURL, victim.Group)

	case "dedupe":
		list, err := svc.ListSubscriptions(ctx)
		if err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
		seen := make(map[string]bool)
		removed := 0
		for _, sub := range list {
			key := sub.Group + "|" + sub.URL
			if seen[key] {
				if err := svc.RemoveSubscription(ctx, sub.Group, sub.URL); err != nil {
					fmt.Printf("  ⚠️  Removing duplicate %s: %v\n", sub.RedactedURL, err)
					continue
				}
				removed++
				continue
			}
			seen[key] = true
		}
		if removed == 0 {
			fmt.Println("✅ No duplicate subscriptions")
		} else {
			fmt.Printf("✅ Removed %d duplicate subscription entry(ies)\n", removed)
		}

	case "list":
		group, _ := subGroupFlag(subArgs)
		list, err := svc.ListSubscriptions(ctx)
		if err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
		list = filterSubscriptions(list, group)
		if len(list) == 0 {
			if group != "" {
				fmt.Printf("No subscriptions in group '%s'\n", group)
			} else {
				fmt.Println("No subscriptions in any group")
			}
			return
		}
		fmt.Printf("%-3s %-16s %-6s %-20s %s\n", "#", "GROUP", "LINKS", "REFRESHED", "URL")
		for i, sub := range list {
			refreshed := sub.LastRefresh
			if refreshed == "" {
				refreshed = "never"
			}
			if len(refreshed) > 19 {
				refreshed = refreshed[:19]
			}
			fmt.Printf("%-3d %-16s %-6d %-20s %s\n", i+1, sub.Group, sub.LinkCount, refreshed, sub.RedactedURL)
			if sub.LastError != "" {
				fmt.Printf("    ⚠️  %s\n", sub.LastError)
			}
		}

	default:
		fmt.Printf("Unknown sub command: %s\n\n", subCmd)
		printSubUsage()
		os.Exit(1)
	}
}

func printSubUsage() {
	fmt.Println("Usage:")
	fmt.Println("  bypath sub add [-g group] <url>     Add a subscription URL")
	fmt.Println("  bypath sub preview <url|file>       Fetch/parse and show contents without storing")
	fmt.Println("  bypath sub update [-g group]        Fetch latest links")
	fmt.Println("  bypath sub import [-g group] <file> Import links from a local dump (plain/base64)")
	fmt.Println("  bypath sub list [-g group]          Show subscriptions (URLs are redacted)")
	fmt.Println("  bypath sub remove [-g group] <#>    Remove a subscription by index")
	fmt.Println("  bypath sub dedupe                   Remove duplicate subscription URLs")
}

// subGroupFlag extracts -g/--group and returns the remaining positional args.
func subGroupFlag(args []string) (string, []string) {
	group := ""
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-g", "--group":
			if i+1 < len(args) {
				group = args[i+1]
				i++
			}
		default:
			rest = append(rest, args[i])
		}
	}
	return group, rest
}

func lastArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[len(args)-1]
}

func filterSubscriptions(list []app.Subscription, group string) []app.Subscription {
	if group == "" {
		return list
	}
	var out []app.Subscription
	for _, sub := range list {
		if sub.Group == group {
			out = append(out, sub)
		}
	}
	return out
}

func printSubscriptionPreview(p app.SubscriptionPreview) {
	source := p.RedactedURL
	if p.Group != "" && p.Group != "imported" {
		source += "  (group: " + p.Group + ")"
	}
	fmt.Printf("Preview of %s\n", source)
	fmt.Printf("  links: %d   duplicates already stored: %d\n", p.Total, p.Duplicates)
	if len(p.Links) == 0 {
		fmt.Println("  (no new links to import)")
		return
	}
	fmt.Println()
	fmt.Printf("  %-3s %-7s %-24s %-6s %s\n", "#", "PROTO", "ADDRESS", "PORT", "REMARK")
	limit := len(p.Links)
	if limit > 20 {
		limit = 20
	}
	for i := 0; i < limit; i++ {
		l := p.Links[i]
		flags := make([]string, 0, 4)
		if l.TLS {
			flags = append(flags, "tls")
		}
		if l.Reality {
			flags = append(flags, "reality")
		}
		if l.EncryptedVLESS {
			flags = append(flags, "encrypted")
		}
		if l.CDN {
			flags = append(flags, "cdn")
		}
		remark := l.Remark
		if len(flags) > 0 {
			remark += " [" + strings.Join(flags, ",") + "]"
		}
		fmt.Printf("  %-3d %-7s %-24s %-6d %s\n", i+1, l.Protocol, l.Address, l.Port, remark)
	}
	if limit < len(p.Links) {
		fmt.Printf("  … %d more link(s) not shown\n", len(p.Links)-limit)
	}
}

// readSubscriptionFile bounds how much a dump can pull into memory.
func readSubscriptionFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s is a directory", path)
	}
	const maxDump = 8 << 20
	if info.Size() > maxDump {
		return "", fmt.Errorf("file is larger than %d MiB", maxDump>>20)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
