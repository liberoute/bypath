package tui

import (
	"os"
	"path/filepath"
	"testing"
)

// OpenVPN profiles may reference material in subdirectories. The TUI stages the
// files, so reading them back must preserve the relative reference instead of
// silently dropping it.
func TestStagedSourceIncludesSubdirectoryRefs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "profile.ovpn"), []byte("client\nca keys/ca.crt\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys", "ca.crt"), []byte("cert"), 0600); err != nil {
		t.Fatal(err)
	}
	src, err := stagedSource(dir, "test")
	if err != nil {
		t.Fatalf("stagedSource: %v", err)
	}
	if len(src.Refs) != 1 || src.Refs[0].Name != "keys/ca.crt" || src.Refs[0].Content != "cert" {
		t.Fatalf("nested ref not preserved: %+v", src.Refs)
	}
}
