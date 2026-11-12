package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/liberoute/bypath/internal/profile"
)

const testVLESS2 = "vless://22222222-2222-2222-2222-222222222222@example.org:443?security=tls&type=ws#node-b"

func importTwo(t *testing.T, svc *Local) {
	t.Helper()
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "work", testVLESS); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ImportURI(ctx, "work", testVLESS2); err != nil {
		t.Fatal(err)
	}
}

func activePair(t *testing.T, svc *Local) (string, string, bool) {
	t.Helper()
	link := svc.profiles.GetActiveLink()
	if link == nil {
		return "", "", false
	}
	return link.Group, link.Remark, true
}

func TestDeletingTheSelectionRequiresAReplacement(t *testing.T) {
	svc, _ := newTestLocal(t)
	importTwo(t, svc)
	ctx := context.Background()

	nodeA, err := svc.GetConnection(ctx, "work:node-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetActive(ctx, nodeA.ID); err != nil {
		t.Fatal(err)
	}

	plan, err := svc.ConnectionDeletePlan(ctx, nodeA.ID)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Allowed || !plan.Selected || !plan.RequiresReplacement {
		t.Fatalf("delete plan did not guard the selection: %+v", plan)
	}
	if nodeA.StableID != "" && plan.StableID != nodeA.StableID {
		t.Fatalf("plan stable id mismatch: %q vs %q", plan.StableID, nodeA.StableID)
	}
	if err := svc.DeleteConnection(ctx, nodeA.ID); err == nil || CodeOf(err) != CodeConflict {
		t.Fatalf("selected delete was not refused: %v", err)
	}

	if err := svc.DeleteConnectionWithOptions(ctx, nodeA.ID, DeleteOptions{ReplaceWithID: "work:node-b"}); err != nil {
		t.Fatalf("delete with replacement: %v", err)
	}
	if g, r, ok := activePair(t, svc); !ok || g != "work" || r != "node-b" {
		t.Fatalf("replacement not selected: %q %q %v", g, r, ok)
	}
	if _, err := svc.GetConnection(ctx, nodeA.ID); err == nil {
		t.Fatal("connection still present after delete")
	}

	// The replacement is now the selection; an explicit acknowledgement may
	// leave the next start unset.
	if err := svc.DeleteConnectionWithOptions(ctx, "work:node-b", DeleteOptions{AcknowledgeUnset: true}); err != nil {
		t.Fatalf("delete with acknowledge: %v", err)
	}
	if _, _, ok := activePair(t, svc); ok {
		t.Fatal(".active still set after leaving the next start unset")
	}
}

func TestServingConnectionCannotBeDeletedOrHidden(t *testing.T) {
	svc, _ := newTestLocal(t)
	importTwo(t, svc)
	ctx := context.Background()

	if _, err := svc.LayerMigrate(ctx, false); err != nil {
		t.Fatal(err)
	}
	rt := &fakeRuntime{}
	rt.setServing("work", "node-a")
	svc.runtime = rt

	if err := svc.DeleteConnection(ctx, "work:node-a"); err == nil || CodeOf(err) != CodeConflict {
		t.Fatalf("serving connection delete was not refused: %v", err)
	}
	c, err := svc.GetConnection(ctx, "work:node-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.HideConnections(ctx, []string{c.StableID}, true); err == nil || CodeOf(err) != CodeConflict {
		t.Fatalf("serving connection hide was not refused: %v", err)
	}

	// The plan reports the serving state regardless of .active.
	plan, err := svc.ConnectionDeletePlan(ctx, "work:node-a")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Allowed || !plan.Serving {
		t.Fatalf("plan did not report serving: %+v", plan)
	}
}

func TestSelectionStates(t *testing.T) {
	svc, p := newTestLocal(t)
	importTwo(t, svc)
	ctx := context.Background()

	st, err := svc.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if st.Selection.State != SelectionUnset {
		t.Fatalf("expected S-UNSET, got %+v", st.Selection)
	}

	if err := os.WriteFile(filepath.Join(p.ProfileDir, ".active"), []byte("work\nghost\n"), 0644); err != nil {
		t.Fatal(err)
	}
	st, _ = svc.Status(ctx)
	if st.Selection.State != SelectionDangling {
		t.Fatalf("expected S-DANGLING, got %+v", st.Selection)
	}

	if _, err := svc.SetActive(ctx, "work:node-a"); err != nil {
		t.Fatal(err)
	}
	rt := &fakeRuntime{}
	rt.setServing("work", "node-b")
	svc.runtime = rt
	st, _ = svc.Status(ctx)
	if st.Selection.State != SelectionDiff {
		t.Fatalf("expected S-DIFF, got %+v", st.Selection)
	}
	if st.Selection.SelectedRemark != "node-a" || st.Selection.ServingRemark != "node-b" {
		t.Fatalf("selection did not report both sides: %+v", st.Selection)
	}
}

func TestGroupsDisplayNamesVisibilityAndMigration(t *testing.T) {
	svc, _ := newTestLocal(t)
	importTwo(t, svc)
	ctx := context.Background()

	plan, err := svc.LayerMigrate(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if plan.AlreadyMigrated {
		t.Fatal("dry run reported an existing migration")
	}
	if _, err := svc.LayerMigrate(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.LayerStatus(ctx); err != nil {
		t.Fatal(err)
	}

	groups, err := svc.LayerGroups(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var workGroup, ungrouped string
	for _, g := range groups {
		if g.Name == "work" {
			workGroup = g.ID
		}
		if g.ID == "" {
			ungrouped = g.Name
		}
	}
	if workGroup == "" || ungrouped != "Ungrouped" {
		t.Fatalf("unexpected groups: %+v", groups)
	}

	fast, err := svc.CreateLayerGroup(ctx, "Fast")
	if err != nil {
		t.Fatal(err)
	}
	list, _ := svc.ListConnections(ctx, ConnectionFilter{})
	if len(list) != 2 {
		t.Fatalf("unexpected list: %+v", list)
	}
	var nodeA, nodeB Connection
	for _, c := range list {
		if c.Remark == "node-a" {
			nodeA = c
		}
		if c.Remark == "node-b" {
			nodeB = c
		}
	}
	if nodeA.StableID == "" || nodeA.LayerGroup != "work" {
		t.Fatalf("connection lacks layer identity: %+v", nodeA)
	}
	if err := svc.MoveLayerConnections(ctx, []string{nodeB.StableID}, fast.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetDisplayName(ctx, "work:node-a", "Primary exit"); err != nil {
		t.Fatal(err)
	}
	list, _ = svc.ListConnections(ctx, ConnectionFilter{})
	for _, c := range list {
		if c.Remark == "node-a" && c.DisplayName != "Primary exit" {
			t.Fatalf("display name not applied: %+v", c)
		}
		if c.Remark == "node-b" && c.LayerGroup != "Fast" {
			t.Fatalf("move not reflected: %+v", c)
		}
	}

	if err := svc.HideConnections(ctx, []string{nodeB.StableID}, true); err != nil {
		t.Fatal(err)
	}
	list, _ = svc.ListConnections(ctx, ConnectionFilter{})
	if len(list) != 1 || list[0].Remark != "node-a" {
		t.Fatalf("hidden connection still listed: %+v", list)
	}
	all, _ := svc.ListConnections(ctx, ConnectionFilter{IncludeHidden: true})
	foundHidden := false
	for _, c := range all {
		if c.Remark == "node-b" && c.Hidden {
			foundHidden = true
		}
	}
	if !foundHidden {
		t.Fatalf("hidden connection not reported with IncludeHidden: %+v", all)
	}

	// Deleting the group without --members keeps the connection ungrouped.
	if err := svc.DeleteLayerGroup(ctx, fast.ID, false, DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetConnection(ctx, "work:node-b"); err != nil {
		t.Fatal("group delete removed a connection without --members")
	}
}

func TestRefreshMergeKeepsProviderRemovedLinks(t *testing.T) {
	svc, _ := newTestLocal(t)
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "work", testVLESS); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.LayerMigrate(ctx, false); err != nil {
		t.Fatal(err)
	}

	src := "src-1"
	old := &profile.Link{
		Remark: "old", Protocol: "vless", Address: "old.example", Port: 443,
		Network: "ws", Path: "/ws", UUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
		RawURI: "vless://old.example:443?type=ws#old", SourceID: src, Group: "work",
	}
	kept := &profile.Link{
		Remark: "kept", Protocol: "vless", Address: "keep.example", Port: 443,
		Network: "ws", Path: "/ws", UUID: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
		RawURI: "vless://keep.example:443?type=ws#kept", SourceID: src, Group: "work",
	}
	if err := svc.profiles.AddLink("work", old); err != nil {
		t.Fatal(err)
	}
	if err := svc.profiles.AddLink("work", kept); err != nil {
		t.Fatal(err)
	}
	svc.profiles.SetActiveLink(kept)
	svc.indexLayer()

	fetched := []*profile.Link{
		{
			Remark: "kept", Protocol: "vless", Address: "keep.example", Port: 443,
			Network: "ws", Path: "/ws", UUID: "cccccccc-cccc-cccc-cccc-cccccccccccc",
			RawURI:   "vless://keep.example:443?type=ws&uuid=cccccccc-cccc-cccc-cccc-cccccccccccc#kept",
			SourceID: src,
		},
		{
			Remark: "new", Protocol: "vless", Address: "new.example", Port: 443,
			Network: "ws", Path: "/ws", UUID: "dddddddd-dddd-dddd-dddd-dddddddddddd",
			RawURI: "vless://new.example:443?type=ws#new", SourceID: src,
		},
	}
	merged, orphanedIDs := svc.mergeFetchedLinks("work", src, fetched)
	if len(orphanedIDs) != 1 {
		t.Fatalf("provider-removed link not reported as orphan: %v", orphanedIDs)
	}
	if err := svc.profiles.ReplaceSource("work", src, "https://panel.example/sub", "", "", merged); err != nil {
		t.Fatal(err)
	}
	svc.indexLayer()
	if err := svc.layer.MarkOrphaned(orphanedIDs, true); err != nil {
		t.Fatal(err)
	}

	g, err := svc.profiles.GetGroup("work")
	if err != nil {
		t.Fatal(err)
	}
	byRemark := map[string]*profile.Link{}
	for _, l := range g.Links {
		byRemark[l.Remark] = l
	}
	if byRemark["old"] == nil {
		t.Fatal("provider-removed link was deleted")
	}
	if byRemark["kept"] == nil || byRemark["kept"].UUID != "cccccccc-cccc-cccc-cccc-cccccccccccc" {
		t.Fatalf("matched link was not updated in place: %+v", byRemark["kept"])
	}
	if g, r, ok := activePair(t, svc); !ok || g != "work" || r != "kept" {
		t.Fatalf("refresh invalidated .active: %q %q %v", g, r, ok)
	}

	list, _ := svc.ListConnections(ctx, ConnectionFilter{IncludeHidden: true})
	var oldView Connection
	for _, c := range list {
		if c.Remark == "old" {
			oldView = c
		}
	}
	if oldView.ID == "" || !oldView.Orphaned {
		t.Fatalf("orphaned view not flagged: %+v", oldView)
	}
}
