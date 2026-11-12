package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSafeRefNameAllowsNestedRelativePaths(t *testing.T) {
	valid := []string{"ca.crt", "keys/ca.crt", "keys/client.key", "a/b/c.pem"}
	for _, name := range valid {
		if !safeRefName(name) {
			t.Errorf("safeRefName(%q) = false, want true", name)
		}
	}
	invalid := []string{"", ".", "..", "../ca.crt", "keys/../ca.crt", "/etc/passwd", `keys\ca.crt`, "C:/x", "keys//ca.crt", "keys/", "./ca.crt"}
	for _, name := range invalid {
		if safeRefName(name) {
			t.Errorf("safeRefName(%q) = true, want false", name)
		}
	}
}

func TestValidateOVPNRefsAcceptsSubdirectoryRefs(t *testing.T) {
	refs := []OVPNRef{{Name: "keys/ca.crt", Content: "ca"}, {Name: "ca.crt", Content: "ca"}}
	if err := ValidateOVPNRefs(refs); err != nil {
		t.Fatalf("nested refs rejected: %v", err)
	}
	bad := []OVPNRef{{Name: "../ca.crt", Content: "ca"}}
	if err := ValidateOVPNRefs(bad); err == nil {
		t.Fatal("traversal ref accepted")
	}
}

func TestWriteOVPNRefsCreatesSubdirectories(t *testing.T) {
	dir := t.TempDir()
	refs := []OVPNRef{{Name: "keys/ca.crt", Content: "cert-bytes"}}
	if err := writeOVPNRefs(dir, refs); err != nil {
		t.Fatalf("writeOVPNRefs: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "keys", "ca.crt"))
	if err != nil {
		t.Fatalf("nested ref not written: %v", err)
	}
	if string(data) != "cert-bytes" {
		t.Fatalf("nested ref content = %q", data)
	}
}

func TestImportSubscriptionTextRejectsSSHKeyPath(t *testing.T) {
	svc, _ := newTestLocal(t)
	body := "ssh://root@example.com:22?key=/root/.ssh/id_rsa#bad\n"
	if _, err := svc.ImportSubscriptionText(context.Background(), "sub", body); err == nil {
		t.Fatal("subscription import accepted a caller-supplied SSH key path")
	}
}
