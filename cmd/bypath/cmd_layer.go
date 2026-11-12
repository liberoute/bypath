package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/layer"
)

// cmdLayer exposes the organisation layer: migration, rollback and the
// durable connection groups. Every operation goes through the shared service,
// so the CLI, the TUI and the web panel always see the same state.
func cmdLayer(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: bypath layer <status|plan|migrate|rollback|groups>")
		os.Exit(1)
	}
	svc, err := openService()
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}
	ctx := context.Background()

	switch args[0] {
	case "status":
		st, err := svc.LayerStatus(ctx)
		if err != nil {
			fail(err)
		}
		if !st.Migrated {
			fmt.Println("ℹ️  Organisation layer: not migrated (legacy profile buckets only)")
			return
		}
		state := "active"
		if st.ReadOnly {
			state = "read-only"
		}
		fmt.Printf("✅ Organisation layer: %s\n", state)
		fmt.Printf("   groups: %d  connections: %d  orphaned: %d  hidden: %d\n",
			st.Groups, st.Entries, st.Orphaned, st.Hidden)
		if st.LastSelectionID != "" {
			fmt.Printf("   last user selection: %s (%s)\n", st.LastSelectionID, st.LastSelectionAt)
		}
		for _, c := range st.Corrupt {
			fmt.Printf("   ⚠️  corrupt file: %s (using backup)\n", c)
		}
	case "plan":
		plan, err := svc.LayerPlan(ctx)
		if err != nil {
			fail(err)
		}
		printMigrationPlan(plan)
	case "migrate":
		dry := hasFlag(args[1:], "--dry-run")
		plan, err := svc.LayerMigrate(ctx, dry)
		if err != nil {
			fail(err)
		}
		printMigrationPlan(plan)
		if dry {
			fmt.Println("ℹ️  Dry run: nothing was written.")
		} else if plan.AlreadyMigrated && plan.BackupDir == "" {
			fmt.Println("ℹ️  Already migrated; backup verified.")
		} else {
			fmt.Printf("✅ Migration complete. Backup: %s\n", plan.BackupDir)
		}
	case "rollback":
		confirm := hasFlag(args[1:], "--confirm")
		report, err := svc.LayerRollback(ctx, confirm)
		if err != nil {
			fail(err)
		}
		if !confirm {
			fmt.Printf("Plan: restore %d changed file(s), %d missing\n",
				len(report.ChangedFiles), len(report.MissingFiles))
			for _, f := range report.ChangedFiles {
				fmt.Printf("   would restore %s\n", f)
			}
			fmt.Println("ℹ️  Re-run with --confirm to roll back.")
			return
		}
		fmt.Printf("✅ Rolled back %d file(s); layer archived at %s\n",
			len(report.ChangedFiles), report.LayerArchived)
		if !report.SelectionResolves {
			fmt.Println("⚠️  The saved .active selection does not resolve after rollback.")
		}
	default:
		fmt.Printf("Unknown layer command: %s\n", args[0])
		os.Exit(1)
	}
}

func printMigrationPlan(plan layer.MigrationPlan) {
	if plan.AlreadyMigrated {
		fmt.Println("ℹ️  Organisation layer is already migrated.")
		return
	}
	fmt.Printf("Plan: %d bucket(s), %d connection(s)\n", len(plan.Buckets), len(plan.Entries))
	for _, b := range plan.Buckets {
		fmt.Printf("   %-20s %d link(s)\n", b.Name, b.Links)
	}
	if plan.SelectedBucket != "" {
		state := "resolves"
		if !plan.SelectedResolved {
			state = "does NOT resolve"
		}
		fmt.Printf("   next start: %s:%s (%s)\n", plan.SelectedBucket, plan.SelectedRemark, state)
	}
	for _, w := range plan.Warnings {
		fmt.Printf("   ⚠️  %s\n", w)
	}
}

// cmdGroup manages user groups and product-only overrides (display name,
// visibility). It never changes bucket remarks or .active.
func cmdGroup(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: bypath group <list|create|rename|delete|move|name|hide|unhide>")
		os.Exit(1)
	}
	svc, err := openService()
	if err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}
	ctx := context.Background()

	switch args[0] {
	case "list":
		groups, err := svc.LayerGroups(ctx)
		if err != nil {
			fail(err)
		}
		for _, g := range groups {
			name := g.Name
			if g.ID == "" {
				name = "Ungrouped"
			}
			fmt.Printf("%-14s %-24s %d connection(s)\n", displayGroupID(g.ID), name, g.Count)
		}
	case "create":
		if len(args) < 2 {
			fmt.Println("Usage: bypath group create <name>")
			os.Exit(1)
		}
		g, err := svc.CreateLayerGroup(ctx, strings.Join(args[1:], " "))
		if err != nil {
			fail(err)
		}
		fmt.Printf("✅ Created group %q (%s)\n", g.Name, g.ID)
	case "rename":
		if len(args) < 3 {
			fmt.Println("Usage: bypath group rename <group-id|name> <new-name>")
			os.Exit(1)
		}
		id := resolveGroupID(ctx, svc, args[1])
		if err := svc.RenameLayerGroup(ctx, id, strings.Join(args[2:], " ")); err != nil {
			fail(err)
		}
		fmt.Println("✅ Group renamed.")
	case "delete":
		if len(args) < 2 {
			fmt.Println("Usage: bypath group delete <group-id|name> [--members] [--replace ID | --leave-unset]")
			os.Exit(1)
		}
		id := resolveGroupID(ctx, svc, args[1])
		opts, err := parseDeleteOptions(args[2:])
		if err != nil {
			fail(err)
		}
		if err := svc.DeleteLayerGroup(ctx, id, hasFlag(args[2:], "--members"), opts); err != nil {
			fail(err)
		}
		fmt.Println("✅ Group deleted.")
	case "move":
		to := ""
		var ids []string
		args = args[1:]
		for i := 0; i < len(args); i++ {
			if (args[i] == "--to" || args[i] == "-t") && i+1 < len(args) {
				to = args[i+1]
				i++
				continue
			}
			ids = append(ids, args[i])
		}
		if len(ids) == 0 {
			fmt.Println("Usage: bypath group move <connection...> [--to <group-id|name>]")
			os.Exit(1)
		}
		if to != "" {
			to = resolveGroupID(ctx, svc, to)
		}
		if err := svc.MoveLayerConnections(ctx, ids, to); err != nil {
			fail(err)
		}
		fmt.Println("✅ Connections moved.")
	case "name":
		if len(args) < 3 {
			fmt.Println("Usage: bypath group name <connection-id> <display name>")
			os.Exit(1)
		}
		if err := svc.SetDisplayName(ctx, args[1], strings.Join(args[2:], " ")); err != nil {
			fail(err)
		}
		fmt.Println("✅ Display name updated.")
	case "hide", "unhide":
		if len(args) < 2 {
			fmt.Printf("Usage: bypath group %s <connection-id...>\n", args[0])
			os.Exit(1)
		}
		if err := svc.HideConnections(ctx, args[1:], args[0] == "hide"); err != nil {
			fail(err)
		}
		fmt.Println("✅ Visibility updated.")
	default:
		fmt.Printf("Unknown group command: %s\n", args[0])
		os.Exit(1)
	}
}

func displayGroupID(id string) string {
	if id == "" {
		return "-"
	}
	return id
}

func resolveGroupID(ctx context.Context, svc app.Contract, ref string) string {
	groups, err := svc.LayerGroups(ctx)
	if err != nil {
		fail(err)
	}
	for _, g := range groups {
		if g.ID == ref || strings.EqualFold(g.Name, ref) {
			return g.ID
		}
	}
	fmt.Printf("❌ Group %q not found\n", ref)
	os.Exit(1)
	return ""
}

// parseDeleteOptions reads the explicit choice required when a delete would
// remove the next-start selection.
func parseDeleteOptions(args []string) (app.DeleteOptions, error) {
	var opts app.DeleteOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--replace", "-r":
			if i+1 >= len(args) {
				return opts, fmt.Errorf("--replace needs a connection id")
			}
			opts.ReplaceWithID = args[i+1]
			i++
		case "--leave-unset", "--acknowledge-unset":
			opts.AcknowledgeUnset = true
		}
	}
	return opts, nil
}

func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == name {
			return true
		}
	}
	return false
}

func fail(err error) {
	fmt.Printf("❌ %v\n", err)
	if ae, ok := err.(*app.Error); ok && ae.Hint != "" {
		fmt.Printf("   %s\n", ae.Hint)
	}
	os.Exit(1)
}
