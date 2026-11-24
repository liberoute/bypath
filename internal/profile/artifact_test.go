package profile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveArtifactPathHandlesMigratedReferences(t *testing.T) {
	root := t.TempDir()
	artifacts := filepath.Join(root, "ovpn")
	if err := os.MkdirAll(artifacts, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(artifacts, "office.ovpn")
	if err := os.WriteFile(target, []byte("client\nremote vpn.example 443 udp\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []string{
		"data/profiles/ovpn/office.ovpn",
		"profiles/ovpn/office.ovpn",
		"ovpn/office.ovpn",
		target,
	}
	for _, recorded := range cases {
		got, err := ResolveArtifactPath(root, recorded)
		if err != nil {
			t.Fatalf("%q: %v", recorded, err)
		}
		if got != target {
			t.Fatalf("%q resolved to %q, want %q", recorded, got, target)
		}
	}
}

func TestResolveArtifactPathRejectsEscapes(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.ovpn")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, recorded := range []string{
		"../secret.ovpn",
		"ovpn/../../secret.ovpn",
		"ovpn/../../" + filepath.Base(outside),
	} {
		if got, err := ResolveArtifactPath(root, recorded); err == nil {
			t.Fatalf("%q escaped to %q", recorded, got)
		}
	}
}

func TestResolveArtifactPathRejectsSymlinkedArtifact(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.ovpn")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "ovpn"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "ovpn", "link.ovpn")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if got, err := ResolveArtifactPath(root, "ovpn/link.ovpn"); err == nil {
		t.Fatalf("symlinked artifact accepted: %q", got)
	}
}

func TestResolveArtifactPathReportsSearchedPaths(t *testing.T) {
	root := t.TempDir()
	_, err := ResolveArtifactPath(root, "data/profiles/ovpn/missing.ovpn")
	if err == nil {
		t.Fatal("missing artifact resolved")
	}
	if msg := err.Error(); !strings.Contains(msg, "missing.ovpn") || !strings.Contains(msg, "tried") {
		t.Fatalf("error does not explain what was searched: %v", err)
	}
}

func TestResolveArtifactPathRecoversAfterInstallMove(t *testing.T) {
	root := t.TempDir()
	artifacts := filepath.Join(root, "ovpn")
	if err := os.MkdirAll(artifacts, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(artifacts, "moved.ovpn")
	if err := os.WriteFile(target, []byte("client\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(t.TempDir(), "profiles", "ovpn", "moved.ovpn")
	got, err := ResolveArtifactPath(root, stale)
	if err != nil {
		t.Fatalf("stale absolute reference: %v", err)
	}
	if got != target {
		t.Fatalf("resolved %q, want %q", got, target)
	}
}
