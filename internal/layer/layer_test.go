package layer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/liberoute/bypath/internal/profile"
)

func testManager(t *testing.T) (string, *profile.Manager) {
	t.Helper()
	dir := t.TempDir()
	mgr, err := profile.NewManager(dir, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	return dir, mgr
}

func addLink(t *testing.T, mgr *profile.Manager, group string, l *profile.Link) *profile.Link {
	t.Helper()
	if err := mgr.AddLink(group, l); err != nil {
		t.Fatal(err)
	}
	return l
}

func vless(remark, host, uuid string) *profile.Link {
	return &profile.Link{
		Remark:   remark,
		Protocol: "vless",
		Address:  host,
		Port:     443,
		Network:  "ws",
		Path:     "/ws",
		SNI:      host,
		UUID:     uuid,
		Security: "tls",
		RawURI:   "vless://" + host + ":443?security=tls&type=ws#" + remark,
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// Open, Status and Plan are read-only: they must not create .layer/.
func TestReadOnlyViewsWriteNothing(t *testing.T) {
	dir, mgr := testManager(t)
	one := addLink(t, mgr, "alpha", vless("one", "a.example", "11111111-1111-1111-1111-111111111111"))
	mgr.SetActiveLink(one)
	bucketBefore := readFile(t, filepath.Join(dir, "alpha.json"))
	activeBefore := readFile(t, filepath.Join(dir, ".active"))

	lay := Open(dir)
	if _, err := lay.Plan(mgr); err != nil {
		t.Fatal(err)
	}
	if lay.Migrated() {
		t.Fatal("reported migrated before migration")
	}
	if _, err := os.Stat(filepath.Join(dir, DirName)); !os.IsNotExist(err) {
		t.Fatalf("Open/Plan created %s", DirName)
	}
	if string(bucketBefore) != string(readFile(t, filepath.Join(dir, "alpha.json"))) {
		t.Fatal("bucket changed during plan")
	}
	if string(activeBefore) != string(readFile(t, filepath.Join(dir, ".active"))) {
		t.Fatal(".active changed during plan")
	}
}

func TestMigratePreservesBucketsAndActive(t *testing.T) {
	dir, mgr := testManager(t)
	one := addLink(t, mgr, "alpha", vless("one", "a.example", "11111111-1111-1111-1111-111111111111"))
	addLink(t, mgr, "beta", vless("two", "b.example", "22222222-2222-2222-2222-222222222222"))
	mgr.SetActiveLink(one)

	bucketBefore := map[string][]byte{}
	for _, name := range mgr.ListGroups() {
		bucketBefore[name] = readFile(t, filepath.Join(dir, name+".json"))
	}
	activeBefore := readFile(t, filepath.Join(dir, ".active"))

	lay := Open(dir)
	plan, err := lay.Migrate(mgr, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Buckets) != 2 || len(plan.Entries) != 2 || !plan.SelectedResolved {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if _, err := os.Stat(filepath.Join(dir, DirName)); !os.IsNotExist(err) {
		t.Fatal("dry-run migration created .layer")
	}

	plan, err = lay.Migrate(mgr, false)
	if err != nil {
		t.Fatal(err)
	}
	if plan.BackupDir == "" || plan.ManifestHash == "" {
		t.Fatalf("migration did not report its backup: %+v", plan)
	}
	for name, before := range bucketBefore {
		if string(before) != string(readFile(t, filepath.Join(dir, name+".json"))) {
			t.Fatalf("bucket %q changed during migration", name)
		}
	}
	if string(activeBefore) != string(readFile(t, filepath.Join(dir, ".active"))) {
		t.Fatal(".active changed during migration")
	}
	st := lay.Status()
	if !st.Migrated || st.Groups != 2 || st.Entries != 2 {
		t.Fatalf("unexpected status: %+v", st)
	}
	sel, at := lay.LastSelection()
	if sel != "" || at != "" {
		t.Fatal("migration must not invent a user selection")
	}

	// Re-running is a verification, not a second migration.
	if _, err := lay.Migrate(mgr, false); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if err := lay.VerifyBackup(); err != nil {
		t.Fatalf("verify backup: %v", err)
	}

	// Rollback without changes restores nothing, and with confirm archives.
	rep, err := lay.Rollback(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.ChangedFiles) != 0 || rep.Restored {
		t.Fatalf("unexpected pre-rollback report: %+v", rep)
	}
	rep, err = lay.Rollback(true)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Restored || !rep.SelectionResolves || rep.LayerArchived == "" {
		t.Fatalf("unexpected rollback: %+v", rep)
	}
	if _, err := os.Stat(filepath.Join(dir, DirName)); !os.IsNotExist(err) {
		t.Fatal(".layer still exists after rollback")
	}
	if _, err := os.Stat(rep.LayerArchived); err != nil {
		t.Fatalf("archive missing: %v", err)
	}
	for name, before := range bucketBefore {
		if string(before) != string(readFile(t, filepath.Join(dir, name+".json"))) {
			t.Fatalf("bucket %q changed after rollback", name)
		}
	}
	if string(activeBefore) != string(readFile(t, filepath.Join(dir, ".active"))) {
		t.Fatal(".active changed after rollback")
	}
}

func migrateForTest(t *testing.T, dir string, mgr *profile.Manager) *Manager {
	t.Helper()
	lay := Open(dir)
	if _, err := lay.Migrate(mgr, false); err != nil {
		t.Fatal(err)
	}
	return lay
}

func TestIdentitySurvivesRotationAndRemarkMatch(t *testing.T) {
	dir, mgr := testManager(t)
	l := addLink(t, mgr, "alpha", vless("one", "a.example", "11111111-1111-1111-1111-111111111111"))
	addLink(t, mgr, "alpha", vless("two", "b.example", "22222222-2222-2222-2222-222222222222"))
	lay := migrateForTest(t, dir, mgr)

	before, ok := lay.EntryForLink("alpha", "one")
	if !ok {
		t.Fatal("entry missing")
	}

	// Credential rotation: tuple and remark stay, secret changes. T2 must keep
	// the id and record the rotation.
	l.UUID = "33333333-3333-3333-3333-333333333333"
	l.RawURI = "vless://a.example:443?security=tls&type=ws&uuid=33333333-3333-3333-3333-333333333333#one"
	if err := mgr.SaveGroup("alpha"); err != nil {
		t.Fatal(err)
	}
	rep, err := lay.Index(mgr)
	if err != nil {
		t.Fatal(err)
	}
	if rep.CredentialRotations != 1 {
		t.Fatalf("rotation not detected: %+v", rep)
	}
	rotated, _ := lay.EntryForLink("alpha", "one")
	if rotated.ID != before.ID || !rotated.CredentialsChange {
		t.Fatalf("rotation changed identity: %+v vs %+v", rotated, before)
	}

	// T3: the transport tuple changes and the raw URI changes, but the
	// provider remark is unique, so the id follows the remark.
	other, _ := lay.EntryForLink("alpha", "two")
	otherLink := &profile.Link{}
	for _, gl := range mustGroup(t, mgr, "alpha").Links {
		if gl.Remark == "two" {
			otherLink = gl
		}
	}
	otherLink.Address = "c.example"
	otherLink.SNI = "c.example"
	otherLink.RawURI = "vless://c.example:443?security=tls&type=ws#two"
	if err := mgr.SaveGroup("alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := lay.Index(mgr); err != nil {
		t.Fatal(err)
	}
	after, ok := lay.EntryForLink("alpha", "two")
	if !ok {
		t.Fatal("remark-matched entry missing")
	}
	if after.ID != other.ID || !after.MatchedByRemark || after.Address != "c.example" {
		t.Fatalf("T3 did not follow the remark: %+v", after)
	}
}

func mustGroup(t *testing.T, mgr *profile.Manager, name string) *profile.Group {
	t.Helper()
	g, err := mgr.GetGroup(name)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestAmbiguousIdentityNeverMerges(t *testing.T) {
	dir, mgr := testManager(t)
	a := vless("one", "a.example", "11111111-1111-1111-1111-111111111111")
	b := vless("two", "a.example", "22222222-2222-2222-2222-222222222222")
	addLink(t, mgr, "alpha", a)
	addLink(t, mgr, "alpha", b)
	lay := migrateForTest(t, dir, mgr)

	// If the provider returns one connection with the same tuple and a new
	// secret, it could be either stored entry rotated; matching must mint a new
	// id instead of guessing.
	c := vless("three", "a.example", "33333333-3333-3333-3333-333333333333")
	res := MatchEntries(entriesOf(t, lay), []Item{ItemFromLink(c, "alpha", 2)})
	if res.Ambiguous != 1 {
		t.Fatalf("ambiguous match not reported: %+v", res)
	}
	last := res.Matches[len(res.Matches)-1]
	if !last.New || !last.Ambiguous {
		t.Fatalf("ambiguous item merged: %+v", last)
	}
}

func entriesOf(t *testing.T, lay *Manager) []Entry {
	t.Helper()
	views := lay.Entries()
	out := make([]Entry, 0, len(views))
	for _, v := range views {
		e, ok := lay.EntryByID(v.ID)
		if !ok {
			t.Fatal("entry vanished")
		}
		out = append(out, e)
	}
	return out
}

func TestHiddenSurvivesRotationAndUnhide(t *testing.T) {
	dir, mgr := testManager(t)
	l := addLink(t, mgr, "alpha", vless("one", "a.example", "11111111-1111-1111-1111-111111111111"))
	lay := migrateForTest(t, dir, mgr)
	e, _ := lay.EntryForLink("alpha", "one")
	if err := lay.Hide([]string{e.ID}); err != nil {
		t.Fatal(err)
	}

	l.UUID = "44444444-4444-4444-4444-444444444444"
	l.RawURI = "vless://a.example:443?security=tls&type=ws&uuid=44444444-4444-4444-4444-444444444444#one"
	if err := mgr.SaveGroup("alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := lay.Index(mgr); err != nil {
		t.Fatal(err)
	}
	hidden, ok := lay.EntryForLink("alpha", "one")
	if !ok || hidden.ID != e.ID || !hidden.Hidden {
		t.Fatalf("hidden tombstone lost across rotation: %+v", hidden)
	}

	// Reopening from disk must keep the tombstone.
	reopened := Open(dir)
	if got, ok := reopened.EntryForLink("alpha", "one"); !ok || !got.Hidden {
		t.Fatalf("hidden state not persisted: %+v", got)
	}
	if err := reopened.Unhide([]string{e.ID}); err != nil {
		t.Fatal(err)
	}
	if got, _ := reopened.EntryForLink("alpha", "one"); got.Hidden {
		t.Fatal("unhide did not clear the tombstone")
	}
}

func TestCorruptDocumentFallsBackToBackup(t *testing.T) {
	dir, mgr := testManager(t)
	addLink(t, mgr, "alpha", vless("one", "a.example", "11111111-1111-1111-1111-111111111111"))
	lay := migrateForTest(t, dir, mgr)
	// Produce a second generation so ids.json.bak exists.
	if err := lay.SetDisplayName(mustID(t, lay, "alpha", "one"), "Primary"); err != nil {
		t.Fatal(err)
	}
	if _, err := lay.Index(mgr); err != nil {
		t.Fatal(err)
	}
	idsPath := filepath.Join(dir, DirName, IDsFile)
	if _, err := os.Stat(idsPath + ".bak"); err != nil {
		t.Skipf("no backup generation was written: %v", err)
	}
	if err := os.WriteFile(idsPath, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	reopened := Open(dir)
	if _, ok := reopened.EntryForLink("alpha", "one"); !ok {
		t.Fatal("entry lost after corrupt primary; backup was not used")
	}
	if files := reopened.CorruptFiles(); len(files) != 0 {
		t.Fatalf("fallback should be silent, got %v", files)
	}

	// With both generations broken the file must be reported, not trusted.
	if err := os.WriteFile(idsPath+".bak", []byte("also broken"), 0600); err != nil {
		t.Fatal(err)
	}
	broken := Open(dir)
	if _, ok := broken.EntryForLink("alpha", "one"); ok {
		t.Fatal("corrupt ids.json was trusted")
	}
	found := false
	for _, name := range broken.CorruptFiles() {
		if name == IDsFile {
			found = true
		}
	}
	if !found {
		t.Fatalf("corruption not surfaced: %v", broken.CorruptFiles())
	}
}

func mustID(t *testing.T, lay *Manager, bucket, remark string) string {
	t.Helper()
	e, ok := lay.EntryForLink(bucket, remark)
	if !ok {
		t.Fatalf("no entry for %s:%s", bucket, remark)
	}
	return e.ID
}

func TestSidecarStoresNoSecrets(t *testing.T) {
	dir, mgr := testManager(t)
	l := vless("secret-node", "a.example", "5ec2e8b0-1111-2222-3333-444455556666")
	l.SSHPassword = "hunter2-do-not-store"
	l.OVPNAuthUserPassFile = "/root/auth.txt"
	addLink(t, mgr, "alpha", l)
	migrateForTest(t, dir, mgr)

	entries, err := os.ReadDir(filepath.Join(dir, DirName))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data := readFile(t, filepath.Join(dir, DirName, entry.Name()))
		text := string(data)
		for _, secret := range []string{
			"5ec2e8b0-1111-2222-3333-444455556666",
			"hunter2-do-not-store",
			"/root/auth.txt",
			"vless://a.example",
			"a.example:443?",
		} {
			if contains(text, secret) {
				t.Fatalf("%s leaked %q", entry.Name(), secret)
			}
		}
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func TestConcurrentGroupWritesDoNotLoseData(t *testing.T) {
	dir, mgr := testManager(t)
	addLink(t, mgr, "alpha", vless("one", "a.example", "11111111-1111-1111-1111-111111111111"))
	lay := migrateForTest(t, dir, mgr)

	names := []string{"g1", "g2", "g3", "g4", "g5", "g6", "g7", "g8"}
	errCh := make(chan error, len(names))
	for _, name := range names {
		go func(n string) {
			_, err := lay.CreateGroup(n)
			errCh <- err
		}(name)
	}
	for range names {
		if err := <-errCh; err != nil {
			t.Fatalf("concurrent create: %v", err)
		}
	}
	reopened := Open(dir)
	if got := len(reopened.Groups()); got != 1+len(names) {
		t.Fatalf("lost group writes: have %d, want %d", got, 1+len(names))
	}
}

func TestMigrationRecordIsChecksummed(t *testing.T) {
	dir, mgr := testManager(t)
	addLink(t, mgr, "alpha", vless("one", "a.example", "11111111-1111-1111-1111-111111111111"))
	migrateForTest(t, dir, mgr)
	path := filepath.Join(dir, DirName, MigratedFile)
	var rec MigratedRecord
	if err := json.Unmarshal(readFile(t, path), &rec); err != nil {
		t.Fatal(err)
	}
	rec.SelectedID = "tampered"
	data, _ := json.MarshalIndent(rec, "", "  ")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	reopened := Open(dir)
	if reopened.Migrated() {
		t.Fatal("tampered migration record accepted")
	}
}

func TestSaveTestResultKeepsTheNewestTen(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	m := Open(filepath.Join(dir, "profiles"))
	for i := 0; i < 12; i++ {
		raw := []byte(`{"seq":` + string(rune('0'+i%10)) + `}`)
		if err := m.SaveTestResult("stable-a", raw); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	got, err := m.TestResults("stable-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 10 {
		t.Fatalf("stored %d results, want 10", len(got))
	}
	var newest struct {
		Seq int `json:"seq"`
	}
	if err := json.Unmarshal(got[9], &newest); err != nil || newest.Seq != 1 {
		t.Fatalf("newest result = %s (err %v), want the 12th write", got[9], err)
	}
	if err := m.ClearTestResults("stable-a"); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.TestResults("stable-a"); len(got) != 0 {
		t.Fatalf("clear left %d results", len(got))
	}
}

func TestTargetsAndUsageRoundTrip(t *testing.T) {
	dir := t.TempDir()
	m := Open(dir)
	if items, err := m.Targets(); err != nil || len(items) != 0 {
		t.Fatalf("empty registry: %v %v", items, err)
	}
	items := []json.RawMessage{
		json.RawMessage(`{"id":"t_1","host":"speed.example.net","path":"/p"}`),
		json.RawMessage(`{"id":"t_2","host":"dl.google.com","path":"/p"}`),
	}
	if err := m.SaveTargets(items); err != nil {
		t.Fatal(err)
	}
	got, err := Open(dir).Targets()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("targets were not persisted: %v", got)
	}
	var first struct{ Host string }
	json.Unmarshal(got[0], &first)
	if first.Host != "speed.example.net" {
		t.Fatalf("unexpected first target: %s", got[0])
	}

	tooMany := make([]json.RawMessage, maxTargets+1)
	if err := m.SaveTargets(tooMany); err == nil {
		t.Fatal("registry accepted more than the limit")
	}

	if u, err := m.AddUsage("2026-11", 1024); err != nil || u.Bytes != 1024 {
		t.Fatalf("first usage: %+v %v", u, err)
	}
	if u, err := m.AddUsage("2026-11", 2048); err != nil || u.Bytes != 3072 {
		t.Fatalf("same-month usage did not accumulate: %+v %v", u, err)
	}
	if u, err := m.AddUsage("2026-12", 10); err != nil || u.Bytes != 10 {
		t.Fatalf("month rollover did not reset: %+v %v", u, err)
	}
	read, err := Open(dir).Usage()
	if err != nil || read.Month != "2026-12" || read.Bytes != 10 {
		t.Fatalf("usage was not persisted: %+v %v", read, err)
	}
	// Targets and usage live in the sidecar, never in a profile bucket.
	for _, name := range []string{TargetsFile, UsageFile} {
		if _, err := os.Stat(filepath.Join(dir, DirName, name)); err != nil {
			t.Fatalf("%s missing from the sidecar: %v", name, err)
		}
	}
}
