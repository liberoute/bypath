package securefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFileIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	if err := WriteFile(path, []byte("s3cr3t-bytes")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "s3cr3t-bytes" {
		t.Fatalf("content = %q", data)
	}
	if !IsOwnerOnly(path) {
		t.Fatalf("file %s is not owner-only after WriteFile", path)
	}
}

func TestWriteFileExclusiveRefusesExistingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	if err := WriteFileExclusive(path, []byte("first")); err != nil {
		t.Fatalf("WriteFileExclusive: %v", err)
	}
	err := WriteFileExclusive(path, []byte("second"))
	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("exclusive overwrite err = %v, want fs.ErrExist", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "first" {
		t.Fatalf("existing content was modified: %q", data)
	}
	if !IsOwnerOnly(path) {
		t.Fatal("exclusively created file is not owner-only")
	}
}

func TestWriteFileTightensExistingPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.key")
	if err := os.WriteFile(path, []byte("old"), 0666); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("new-secret")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if !IsOwnerOnly(path) {
		t.Fatal("pre-existing file kept permissive permissions")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new-secret" {
		t.Fatalf("content = %q", data)
	}
}

func TestMkdirAllIsOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	if err := MkdirAll(dir); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if !IsOwnerOnly(dir) {
		t.Fatalf("directory %s is not owner-only after MkdirAll", dir)
	}
}

func TestIsOwnerOnlyMissingPath(t *testing.T) {
	if IsOwnerOnly(filepath.Join(t.TempDir(), "absent")) {
		t.Fatal("IsOwnerOnly reported true for a missing path")
	}
}
