package layer

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/liberoute/bypath/internal/profile"
)

func sourceLayerProfiles(t *testing.T) (*Manager, *profile.Manager) {
	t.Helper()
	dir := t.TempDir()
	mgr, err := profile.NewManager(dir, "default")
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.CreateGroup("panel", "subscription"); err != nil {
		t.Fatal(err)
	}
	link := &profile.Link{Group: "panel", Remark: "node", Protocol: "vless", Address: "example.net", Port: 443, UUID: "initial", RawURI: "vless://initial@example.net:443#node", SourceID: "src"}
	if err := mgr.AddLink("panel", link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".active"), []byte("panel\nnode\n\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return Open(dir), mgr
}

func TestSourceGroupMigrationFailureRestoresSidecar(t *testing.T) {
	m, mgr := sourceLayerProfiles(t)
	bucket, _ := os.ReadFile(filepath.Join(m.profilesDir, "panel.json"))
	active, _ := os.ReadFile(filepath.Join(m.profilesDir, ".active"))
	fail := errors.New("import failed")
	if _, err := m.ApplySource(mgr, "panel", "sub:src", "panel", true, nil, func() error { return fail }); !errors.Is(err, fail) {
		t.Fatalf("error: %v", err)
	}
	if m.Migrated() || len(m.Entries()) != 0 || len(m.Groups()) != 0 {
		t.Fatal("failed migration left in-memory sidecar state")
	}
	fresh := Open(m.profilesDir)
	if fresh.Migrated() || len(fresh.Entries()) != 0 || len(fresh.Groups()) != 0 {
		t.Fatal("failed migration left disk sidecar state")
	}
	for path, want := range map[string][]byte{"panel.json": bucket, ".active": active} {
		got, err := os.ReadFile(filepath.Join(m.profilesDir, path))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("legacy file changed: %s", path)
		}
	}
	// The retained verified backup does not prevent a safe retry.
	if _, err := m.ApplySource(mgr, "panel", "sub:src", "panel", true, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !m.Migrated() {
		t.Fatal("retry did not migrate")
	}
}

func TestSourceGroupOwnershipSurvivesRenameAndDeletion(t *testing.T) {
	m, mgr := sourceLayerProfiles(t)
	g, err := m.ApplySource(mgr, "panel", "sub:src", "panel", true, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RenameGroup(g.ID, "Renamed"); err != nil {
		t.Fatal(err)
	}
	m = Open(m.profilesDir)
	if got, ok := m.SourceGroup("panel", "sub:src"); !ok || got.ID != g.ID || got.Name != "Renamed" {
		t.Fatalf("binding not persisted: %+v %v", got, ok)
	}
	if _, err := m.DeleteGroup(g.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := mgr.AddLink("panel", &profile.Link{Remark: "new", Protocol: "vless", Address: "new.example", Port: 443, SourceID: "src", RawURI: "vless://new@new.example:443#new"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.ApplySource(mgr, "panel", "sub:src", "", false, nil, nil); err != nil {
		t.Fatal(err)
	}
	if len(m.Groups()) != 0 {
		t.Fatal("refresh recreated deleted source group")
	}
	for _, e := range m.Entries() {
		if e.GroupID != "" {
			t.Fatalf("refresh regrouped after deletion: %+v", e)
		}
	}
}

func TestSourceGroupExplicitUngroupedSurvivesOrganize(t *testing.T) {
	m, mgr := sourceLayerProfiles(t)
	if _, err := m.Migrate(mgr, false); err != nil {
		t.Fatal(err)
	}
	e, ok := m.EntryForLink("panel", "node")
	if !ok {
		t.Fatal("entry missing")
	}
	if err := m.Move([]string{e.ID}, ""); err != nil {
		t.Fatal(err)
	}
	m = Open(m.profilesDir)
	if _, err := m.ApplySource(mgr, "panel", "sub:src", "panel", true, nil, nil); err != nil {
		t.Fatal(err)
	}
	if m.GroupForMember(e.ID) != "" {
		t.Fatal("organize overrode explicit Ungrouped")
	}
	if got, ok := m.EntryForLink("panel", "node"); !ok || got.ID != e.ID {
		t.Fatal("organize changed stable identity")
	}
}

func TestSourceGroupsChecksumAcceptsExistingV1Payload(t *testing.T) {
	// Optional ownership fields must not invalidate existing v1 documents.
	d := GroupsDoc{SchemaVersion: 1, MinReader: 1, Groups: []Group{}}
	d.Checksum = checksum(struct {
		SchemaVersion int     `json:"schema_version"`
		MinReader     int     `json:"min_reader"`
		Groups        []Group `json:"groups"`
	}{1, 1, []Group{}})
	if !d.valid() {
		t.Fatal("existing groups checksum no longer accepted")
	}
}
