package app

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/liberoute/bypath/internal/layer"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
)

func newSubscriptionTestLocal(t *testing.T) (*Local, *paths.Resolved) {
	t.Helper()
	for _, key := range []string{"ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(key, "")
	}
	svc, p := newTestLocal(t)
	svc.Config().Server.SOCKSPort = 0
	return svc, p
}

func sourceTestBody(t *testing.T) (*httptest.Server, func(string)) {
	t.Helper()
	var mu sync.Mutex
	body := subBody
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, func(s string) { mu.Lock(); body = s; mu.Unlock() }
}

func sourceConnections(t *testing.T, svc *Local, bucket string) map[string]Connection {
	t.Helper()
	list, err := svc.ListConnections(context.Background(), ConnectionFilter{Group: bucket, IncludeHidden: true})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Connection{}
	for _, c := range list {
		out[c.Remark] = c
	}
	return out
}

func readSourceFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSubscriptionDefaultGroupAndDeterministicCollisions(t *testing.T) {
	svc, _ := newSubscriptionTestLocal(t)
	ctx := context.Background()
	if _, err := svc.LayerMigrate(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateLayerGroup(ctx, "Europe"); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"Europe (2)", "Europe (3)"} {
		sub, err := svc.AddSubscription(ctx, "", "https://panel.example/sub/"+string(rune('a'+i))+"#Europe")
		if err != nil {
			t.Fatal(err)
		}
		if sub.Group != want || sub.LayerGroup != want || sub.LayerGroupID == "" {
			t.Fatalf("default group: %+v, want %s", sub, want)
		}
		if strings.Contains(sub.URL, "#") {
			t.Fatalf("fragment persisted: %s", sub.URL)
		}
	}
	groupsBefore := len(svc.profiles.ListGroups())
	if _, err := svc.AddSubscription(ctx, "", "https://panel.example/sub/a#Other"); CodeOf(err) != CodeConflict {
		t.Fatalf("duplicate: %v", err)
	}
	if len(svc.profiles.ListGroups()) != groupsBefore {
		t.Fatal("duplicate created a bucket")
	}
}

func TestSubscriptionCollisionPreservesUnparsedBucket(t *testing.T) {
	svc, p := newSubscriptionTestLocal(t)
	ctx := context.Background()
	path := filepath.Join(p.ProfileDir, "Europe.json")
	original := []byte("unparsed user bucket data\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	sub, err := svc.AddSubscription(ctx, "", "https://panel.example/collision#Europe")
	if err != nil {
		t.Fatal(err)
	}
	if sub.Group != "Europe (2)" || !bytes.Equal(original, readSourceFile(t, path)) {
		t.Fatal("unparsed bucket was overwritten")
	}
	if _, err := svc.AddSubscription(ctx, "Europe", "https://panel.example/explicit"); CodeOf(err) != CodeConflict {
		t.Fatalf("explicit overwrite was not refused: %v", err)
	}
}

func TestSubscriptionLongNameCollisionAndLargeRemarkSet(t *testing.T) {
	svc, _ := newSubscriptionTestLocal(t)
	ctx := context.Background()
	base := strings.Repeat("x", 64)
	if _, err := svc.LayerMigrate(ctx, false); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateLayerGroup(ctx, base); err != nil {
		t.Fatal(err)
	}
	sub, err := svc.AddSubscription(ctx, "", "https://panel.example/long#"+base)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Group != strings.Repeat("x", 60)+" (2)" || len(sub.Group) > 64 {
		t.Fatalf("long collision: %+v", sub)
	}
	used := map[string]bool{"node": true}
	for i := 2; i <= 100; i++ {
		used[fmt.Sprintf("node (%d)", i)] = true
	}
	if got := uniqueName(used, "node"); got != "node (101)" {
		t.Fatalf("large remark collision: %s", got)
	}
}

func TestSubscriptionRefreshSourceGroupPreservesMovesUngroupedRotationAndActive(t *testing.T) {
	svc, p := newSubscriptionTestLocal(t)
	ctx := context.Background()
	srv, setBody := sourceTestBody(t)
	sub, err := svc.AddSubscription(ctx, "", srv.URL+"/source#Europe")
	if err != nil {
		t.Fatal(err)
	}
	if !svc.layer.Migrated() || sub.LayerGroupID == "" {
		t.Fatalf("source did not set up layer: %+v", sub)
	}
	if _, err := svc.RefreshSubscription(ctx, sub.Group, sub.URL, nil); err != nil {
		t.Fatal(err)
	}
	before := sourceConnections(t, svc, sub.Group)
	for _, c := range before {
		if c.StableID == "" || c.LayerGroupID != sub.LayerGroupID {
			t.Fatalf("initial group: %+v", c)
		}
	}
	other, err := svc.CreateLayerGroup(ctx, "Independent")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.MoveLayerConnections(ctx, []string{before["node-a"].StableID}, other.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.MoveLayerConnections(ctx, []string{before["node-b"].StableID}, ""); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetDisplayName(ctx, before["node-a"].ID, "Chosen exit"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetActive(ctx, before["node-a"].ID); err != nil {
		t.Fatal(err)
	}
	active := readSourceFile(t, filepath.Join(p.ProfileDir, ".active"))
	if err := svc.RenameLayerGroup(ctx, sub.LayerGroupID, "Renamed default"); err != nil {
		t.Fatal(err)
	}
	rotated := strings.Replace(testVLESS, "11111111-1111-1111-1111-111111111111", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 1)
	rotated = strings.Replace(rotated, "#node-a", "#provider-renamed", 1)
	const fresh = "vless://cccccccc-cccc-cccc-cccc-cccccccccccc@fresh.example:443?security=tls&type=ws#fresh"
	setBody(rotated + "\n" + strings.Split(subBody, "\n")[1] + "\n" + fresh)
	// Reopen the sidecar to prove ownership is persisted, not just remembered.
	svc.layer = layer.Open(p.ProfileDir)
	for i := 0; i < 2; i++ {
		if _, err := svc.RefreshSubscription(ctx, sub.Group, sub.URL, nil); err != nil {
			t.Fatal(err)
		}
	}
	after := sourceConnections(t, svc, sub.Group)
	if len(after) != 3 {
		t.Fatalf("refresh duplicated connections: %+v", after)
	}
	if c := after["node-a"]; c.StableID != before["node-a"].StableID || c.LayerGroupID != other.ID || c.DisplayName != "Chosen exit" {
		t.Fatalf("moved rotated link: %+v", c)
	}
	if c := after["node-b"]; c.StableID != before["node-b"].StableID || c.LayerGroupID != "" {
		t.Fatalf("explicit ungrouped: %+v", c)
	}
	if c := after["fresh"]; c.LayerGroupID != sub.LayerGroupID || c.LayerGroup != "Renamed default" {
		t.Fatalf("new link: %+v", c)
	}
	if got := readSourceFile(t, filepath.Join(p.ProfileDir, ".active")); !bytes.Equal(got, active) {
		t.Fatal("refresh rewrote .active")
	}
	g, _ := svc.profiles.GetGroup(sub.Group)
	if g.Links[0].UUID != "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa" {
		t.Fatal("credentials were not refreshed")
	}
	setBody(fresh)
	if _, err := svc.RefreshSubscription(ctx, sub.Group, sub.URL, nil); err != nil {
		t.Fatal(err)
	}
	if !sourceConnections(t, svc, sub.Group)["node-a"].Orphaned {
		t.Fatal("missing selected link not retained as orphan")
	}
	if got := readSourceFile(t, filepath.Join(p.ProfileDir, ".active")); !bytes.Equal(got, active) {
		t.Fatal("orphaning rewrote .active")
	}
}

func TestSubscriptionOrganizeMigratesWithoutRewritingLegacyFiles(t *testing.T) {
	for _, migrated := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "already-migrated"}[migrated], func(t *testing.T) {
			svc, p := newSubscriptionTestLocal(t)
			ctx := context.Background()
			raw := "https://panel.example/sub"
			if err := svc.profiles.CreateGroup("default", "subscription"); err != nil {
				t.Fatal(err)
			}
			if err := svc.profiles.AddSubscription("default", raw); err != nil {
				t.Fatal(err)
			}
			links, _ := profile.ParseSubscriptionContent(subBody)
			if err := svc.profiles.ReplaceSource("default", profile.SourceIDFor(raw), raw, "", "", links); err != nil {
				t.Fatal(err)
			}
			if _, err := svc.ImportURI(ctx, "default", "vless://dddddddd-dddd-dddd-dddd-dddddddddddd@manual.example:443?type=ws#manual"); err != nil {
				t.Fatal(err)
			}
			if _, err := svc.SetActive(ctx, "default:node-a"); err != nil {
				t.Fatal(err)
			}
			var oldID, ungroupedID string
			if migrated {
				if _, err := svc.LayerMigrate(ctx, false); err != nil {
					t.Fatal(err)
				}
				before := sourceConnections(t, svc, "default")
				oldID, ungroupedID = before["node-a"].StableID, before["node-b"].StableID
				// A deliberate Ungrouped choice is not undone by Organize either.
				if err := svc.MoveLayerConnections(ctx, []string{ungroupedID}, ""); err != nil {
					t.Fatal(err)
				}
			}
			bucketPath, activePath := filepath.Join(p.ProfileDir, "default.json"), filepath.Join(p.ProfileDir, ".active")
			bucket, active := readSourceFile(t, bucketPath), readSourceFile(t, activePath)
			out, err := svc.OrganizeSubscription(ctx, "default", raw, "")
			if err != nil {
				t.Fatal(err)
			}
			if out.LayerGroupID == "" || out.LayerGroup != "panel" {
				t.Fatalf("organize result: %+v", out)
			}
			after := sourceConnections(t, svc, "default")
			if after["node-a"].LayerGroupID != out.LayerGroupID {
				t.Fatalf("source not organized: %+v", after)
			}
			if after["manual"].LayerGroupID == out.LayerGroupID {
				t.Fatal("manual link was taken by source")
			}
			if migrated && (after["node-a"].StableID != oldID || after["node-b"].LayerGroupID != "" || after["node-b"].StableID != ungroupedID) {
				t.Fatalf("organize changed an existing identity/choice: %+v", after)
			}
			if !bytes.Equal(bucket, readSourceFile(t, bucketPath)) || !bytes.Equal(active, readSourceFile(t, activePath)) {
				t.Fatal("organize rewrote legacy files")
			}
			again, err := svc.OrganizeSubscription(ctx, "default", raw, "Different")
			if err != nil || again.LayerGroupID != out.LayerGroupID {
				t.Fatalf("organize not idempotent: %+v %v", again, err)
			}
			if _, err := svc.OrganizeSubscription(ctx, "default", "https://other.example/sub", ""); CodeOf(err) != CodeNotFound {
				t.Fatalf("unregistered organize: %v", err)
			}
		})
	}
}

func TestSubscriptionImportGroupsOnlyNewConnections(t *testing.T) {
	svc, _ := newSubscriptionTestLocal(t)
	ctx := context.Background()
	if _, err := svc.ImportURI(ctx, "bulk", testVLESS); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.LayerMigrate(ctx, false); err != nil {
		t.Fatal(err)
	}
	old := sourceConnections(t, svc, "bulk")["node-a"]
	if err := svc.MoveLayerConnections(ctx, []string{old.StableID}, ""); err != nil {
		t.Fatal(err)
	}
	res, err := svc.ImportSubscriptionText(ctx, "bulk", subBody)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Created) != 1 || len(res.Skipped) != 1 || res.Created[0].StableID == "" || res.Created[0].LayerGroupID == "" {
		t.Fatalf("import: %+v", res)
	}
	if c := sourceConnections(t, svc, "bulk")["node-a"]; c.StableID != old.StableID || c.LayerGroupID != "" {
		t.Fatalf("existing imported link moved: %+v", c)
	}
}

func TestSubscriptionSidecarFailureRollsBackBucketAndMemory(t *testing.T) {
	svc, p := newSubscriptionTestLocal(t)
	ctx := context.Background()
	srv, _ := sourceTestBody(t)
	sub, err := svc.AddSubscription(ctx, "panel", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RefreshSubscription(ctx, sub.Group, sub.URL, nil); err != nil {
		t.Fatal(err)
	}
	bucketPath := filepath.Join(p.ProfileDir, "panel.json")
	bucket := readSourceFile(t, bucketPath)
	before := sourceConnections(t, svc, "panel")
	filesBefore := map[string][]byte{}
	for _, name := range []string{layer.GroupsFile, layer.IDsFile, layer.GroupsFile + ".bak", layer.IDsFile + ".bak"} {
		filesBefore[name] = readSourceFile(t, filepath.Join(svc.layer.Dir(), name))
	}
	// Fail the groups save after the IDs generation has already been written.
	_, err = svc.applySubscriptionChange("panel", subscriptionIdentity(sub.URL), "", false, nil, func() error {
		if err := svc.profiles.AddLinks("panel", []*profile.Link{{Remark: "injected", Protocol: "vless", Address: "new.example", Port: 443, RawURI: "vless://new.example:443#injected", SourceID: profile.SourceIDFor(sub.URL)}}); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(svc.layer.Dir(), layer.GroupsFile+".bak")); err != nil && !os.IsNotExist(err) {
			return err
		}
		return os.Mkdir(filepath.Join(svc.layer.Dir(), layer.GroupsFile+".bak"), 0700)
	})
	if err == nil {
		t.Fatal("expected sidecar save failure")
	}
	if strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("rollback failed: %v", err)
	}
	for name, data := range filesBefore {
		if !bytes.Equal(data, readSourceFile(t, filepath.Join(svc.layer.Dir(), name))) {
			t.Fatalf("sidecar generation not restored: %s", name)
		}
	}
	if !bytes.Equal(bucket, readSourceFile(t, bucketPath)) {
		t.Fatal("bucket bytes not restored")
	}
	if after := sourceConnections(t, svc, "panel"); len(after) != len(before) || after["node-a"].StableID != before["node-a"].StableID {
		t.Fatalf("memory not restored: %+v", after)
	}
	freshLayer := layer.Open(p.ProfileDir)
	if len(freshLayer.Entries()) != len(before) {
		t.Fatal("disk sidecar not restored")
	}
}
