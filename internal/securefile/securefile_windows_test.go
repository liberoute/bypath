//go:build windows

package securefile

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func applySDDL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("SecurityDescriptorFromString(%q): %v", sddl, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatalf("SetNamedSecurityInfo: %v", err)
	}
}

func TestRestrictFileRemovesOtherTrustees(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	// Grant BUILTIN\Users read access on top of the owner ACE.
	applySDDL(t, path, "D:P(A;;FA;;;OW)(A;;FR;;;BU)")
	if IsOwnerOnly(path) {
		t.Fatal("IsOwnerOnly true for a DACL that also grants BUILTIN\\Users")
	}
	if err := RestrictFile(path); err != nil {
		t.Fatalf("RestrictFile: %v", err)
	}
	if !IsOwnerOnly(path) {
		t.Fatal("IsOwnerOnly false after RestrictFile")
	}
}

func TestRestrictFileReplacesInheritedDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "generated.json")
	if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	// Remove the protection flag and add a wide ACE to simulate an inherited ACL.
	applySDDL(t, path, "D:(A;;FA;;;OW)(A;;FR;;;WD)")
	if IsOwnerOnly(path) {
		t.Fatal("IsOwnerOnly true for an unprotected DACL open to Everyone")
	}
	if err := WriteFile(path, []byte(`{"k":"v"}`)); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if !IsOwnerOnly(path) {
		t.Fatal("WriteFile did not install a protected owner-only DACL")
	}
}

func TestRestrictDirGrantsInheritableOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gen-1")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	applySDDL(t, dir, "D:(A;OICI;FA;;;OW)(A;OICI;FR;;;BU)")
	if IsOwnerOnly(dir) {
		t.Fatal("IsOwnerOnly true for a directory DACL open to BUILTIN\\Users")
	}
	if err := RestrictDir(dir); err != nil {
		t.Fatalf("RestrictDir: %v", err)
	}
	if !IsOwnerOnly(dir) {
		t.Fatal("IsOwnerOnly false after RestrictDir")
	}
}
