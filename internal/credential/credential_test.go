package credential

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/liberoute/bypath/internal/profile"
)

func testLink() *profile.Link {
	return &profile.Link{
		Protocol: "openvpn",
		Remark:   "office",
		Address:  "vpn.example.net",
		Port:     443,
		RawURI:   "openvpn://vpn.example.net:443",
		OVPNPath: "/tmp/office.ovpn",
	}
}

func TestSaveEncryptsAtRest(t *testing.T) {
	dir := t.TempDir()
	s := Open(filepath.Join(dir, "creds"), filepath.Join(dir, "session"))
	link := testLink()
	key := KeyFor(link)

	if err := s.Save(key, Credentials{Username: "alice", Password: "s3cr3t-pw"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "creds", key+".cred"))
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	if bytes.Contains(raw, []byte("alice")) || bytes.Contains(raw, []byte("s3cr3t-pw")) {
		t.Fatal("record contains plaintext credentials")
	}
	if len(raw) == 0 || raw[0] != '{' {
		t.Fatalf("record is not a JSON envelope: %q", raw)
	}

	got, ok := s.LookupSaved(key)
	if !ok || got.Username != "alice" || got.Password != "s3cr3t-pw" {
		t.Fatalf("LookupSaved = %+v, %v", got, ok)
	}
	if !s.HasSaved(key) {
		t.Fatal("HasSaved = false")
	}
}

func TestLookupPrefersSession(t *testing.T) {
	dir := t.TempDir()
	s := Open(filepath.Join(dir, "creds"), filepath.Join(dir, "session"))
	key := KeyFor(testLink())

	if err := s.Save(key, Credentials{Username: "saved", Password: "one"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.SetSession(key, Credentials{Username: "session", Password: "two"}); err != nil {
		t.Fatalf("SetSession: %v", err)
	}
	got, ok := s.Lookup(key)
	if !ok || got.Username != "session" {
		t.Fatalf("Lookup = %+v, %v (want session credentials)", got, ok)
	}
	if err := s.ClearSession(); err != nil {
		t.Fatalf("ClearSession: %v", err)
	}
	got, ok = s.Lookup(key)
	if !ok || got.Username != "saved" {
		t.Fatalf("Lookup after clear = %+v, %v (want saved credentials)", got, ok)
	}
}

func TestSessionSurvivesRestartAndIsCleared(t *testing.T) {
	dir := t.TempDir()
	sessionDir := filepath.Join(dir, "session")
	s := Open(filepath.Join(dir, "creds"), sessionDir)
	key := KeyFor(testLink())
	if err := s.SetSession(key, Credentials{Username: "u", Password: "p"}); err != nil {
		t.Fatalf("SetSession: %v", err)
	}

	// A new store (a gateway process starting after the TUI import) must see it.
	s2 := Open(filepath.Join(dir, "creds"), sessionDir)
	got, ok := s2.LookupSession(key)
	if !ok || got.Username != "u" {
		t.Fatalf("LookupSession after reopen = %+v, %v", got, ok)
	}
	if err := s2.ClearSession(); err != nil {
		t.Fatalf("ClearSession: %v", err)
	}
	s3 := Open(filepath.Join(dir, "creds"), sessionDir)
	if _, ok := s3.LookupSession(key); ok {
		t.Fatal("session credentials survived ClearSession")
	}
}

func TestKeyIsStableAcrossRenameAndGroupMove(t *testing.T) {
	link := testLink()
	key := KeyFor(link)
	link.Remark = "renamed"
	link.Group = "other"
	if got := KeyFor(link); got != key {
		t.Fatalf("KeyFor changed after rename/group move: %s != %s", got, key)
	}
	link.Address = "other.example.net"
	if got := KeyFor(link); got == key {
		t.Fatal("KeyFor did not change after the server changed")
	}
}

func TestNoStoreIsSafe(t *testing.T) {
	SetDefault(nil)
	if _, ok := Lookup(testLink()); ok {
		t.Fatal("Lookup with no default store returned credentials")
	}
	var nilStore *Store
	if _, ok := nilStore.Lookup("x"); ok {
		t.Fatal("nil store returned credentials")
	}
}

func contains(b []byte, s string) bool {
	return bytes.Contains(b, []byte(s))
}

func TestClearSessionDirRemovesCrashedRunLeftovers(t *testing.T) {
	dir := t.TempDir()
	sessionDir := filepath.Join(dir, "session")
	key := KeyFor(testLink())
	s := Open(filepath.Join(dir, "creds"), sessionDir)
	if err := s.SetSession(key, Credentials{Username: "u", Password: "p"}); err != nil {
		t.Fatalf("SetSession: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sessionDir, "keep.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := ClearSessionDir(sessionDir); err != nil {
		t.Fatalf("ClearSessionDir: %v", err)
	}
	if _, ok := Open(filepath.Join(dir, "creds"), sessionDir).LookupSession(key); ok {
		t.Fatal("a previous run's session credentials were reloaded")
	}
	if _, err := os.Stat(filepath.Join(sessionDir, "keep.txt")); err != nil {
		t.Fatalf("non-credential file was removed: %v", err)
	}
	if err := ClearSessionDir(filepath.Join(dir, "missing")); err != nil {
		t.Fatalf("missing directory: %v", err)
	}
}
