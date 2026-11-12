package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
)

func TestIsOVPNPath(t *testing.T) {
	dir := t.TempDir()
	ovpn := filepath.Join(dir, "profile.ovpn")
	if err := os.WriteFile(ovpn, []byte("client\n"), 0600); err != nil {
		t.Fatal(err)
	}
	txt := filepath.Join(dir, "profile.txt")
	if err := os.WriteFile(txt, []byte("client\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if !isOVPNPath(ovpn) {
		t.Fatal("existing .ovpn file not recognised")
	}
	if isOVPNPath(txt) {
		t.Fatal(".txt file recognised as OpenVPN profile")
	}
	if isOVPNPath(filepath.Join(dir, "missing.ovpn")) {
		t.Fatal("missing .ovpn recognised")
	}
	if isOVPNPath("--name") {
		t.Fatal("flag recognised as path")
	}
}

func TestSanitizeOVPNName(t *testing.T) {
	cases := map[string]string{
		"Example VPN Netherlands": "Example_VPN_Netherlands",
		"../etc/passwd":      "etc_passwd",
		"":                   "profile",
		"..":                 "profile",
		"  spaced  ":         "spaced",
		"vpn_01.final":       "vpn_01.final",
	}
	for in, want := range cases {
		if got := sanitizeOVPNName(in); got != want {
			t.Errorf("sanitizeOVPNName(%q) = %q, want %q", in, got, want)
		}
	}
	long := ""
	for len(long) < 100 {
		long += "a"
	}
	if got := sanitizeOVPNName(long); len(got) != 64 {
		t.Errorf("long name length = %d, want 64", len(got))
	}
}

func TestCopyProfileNeverSharesArtifacts(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "vpn.ovpn")

	first, created, err := copyProfile([]byte("client\nremote a 1194\n"), dest)
	if err != nil {
		t.Fatal(err)
	}
	if first != dest || !created {
		t.Fatalf("first copy = %q created=%v", first, created)
	}

	// Identical content still gets its own file: links must never share a
	// deletable artifact.
	again, created, err := copyProfile([]byte("client\nremote a 1194\n"), dest)
	if err != nil {
		t.Fatal(err)
	}
	if again == dest || !created {
		t.Fatalf("identical copy = %q created=%v, want a distinct file", again, created)
	}

	other, created, err := copyProfile([]byte("client\nremote b 1194\n"), dest)
	if err != nil {
		t.Fatal(err)
	}
	if other == dest || other == again || !created {
		t.Fatalf("third copy = %q created=%v", other, created)
	}
	original, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(original) != "client\nremote a 1194\n" {
		t.Fatalf("original profile changed: %q", original)
	}
}

// TestCopyProfileConcurrentImportsAreUnique proves that allocation and creation
// are one atomic step: parallel imports of the same requested name each get a
// distinct file whose bytes are not overwritten by a competitor.
func TestCopyProfileConcurrentImportsAreUnique(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "vpn.ovpn")
	const n = 24

	paths := make([]string, n)
	errs := make([]error, n)
	bodies := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		bodies[i] = fmt.Sprintf("client\nremote host-%02d 1194\n", i)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			paths[i], _, errs[i] = copyProfile([]byte(bodies[i]), dest)
		}(i)
	}
	wg.Wait()

	seen := make(map[string]bool, n)
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("import %d: %v", i, errs[i])
		}
		if seen[paths[i]] {
			t.Fatalf("two imports claimed %s", paths[i])
		}
		seen[paths[i]] = true
		data, err := os.ReadFile(paths[i])
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != bodies[i] {
			t.Fatalf("import %d content was overwritten: %q", i, data)
		}
	}
}

func TestCleanupOVPNArtifactsStaysInsideArtifactDirectory(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)
	paths.Reset()
	t.Cleanup(paths.Reset)

	ovpnDir := filepath.Join(work, "data", "profiles", "ovpn")
	if err := os.MkdirAll(ovpnDir, 0700); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(ovpnDir, "owned.ovpn")
	insideAuth := inside + ".auth"
	outside := filepath.Join(work, "outside.secret")
	for _, p := range []string{inside, insideAuth, outside} {
		if err := os.WriteFile(p, []byte("secret"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	cleanupOVPNArtifacts(&profile.Link{
		Protocol:             "openvpn",
		OVPNPath:             inside,
		OVPNAuthUserPassFile: insideAuth,
	})
	for _, p := range []string{inside, insideAuth} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("owned artifact %s survived cleanup (err=%v)", p, err)
		}
	}
	if _, err := os.Stat(outside); err != nil {
		t.Errorf("cleanup removed a file outside the artifact directory: %v", err)
	}

	// A traversal path and an absolute path outside the directory are refused.
	if err := os.WriteFile(outside, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	cleanupOVPNArtifacts(&profile.Link{
		Protocol:             "openvpn",
		OVPNPath:             outside,
		OVPNAuthUserPassFile: filepath.Join(ovpnDir, "..", "..", "..", "outside.secret"),
	})
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("cleanup deleted a file outside the artifact directory")
	}

	// Directories are never removed by artifact cleanup.
	sub := filepath.Join(ovpnDir, "sub")
	if err := os.Mkdir(sub, 0700); err != nil {
		t.Fatal(err)
	}
	cleanupOVPNArtifacts(&profile.Link{Protocol: "openvpn", OVPNPath: sub})
	if _, err := os.Stat(sub); err != nil {
		t.Fatal("cleanup removed a directory")
	}
}
