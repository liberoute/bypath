package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrintEnginesHonorsConfiguredDirectory(t *testing.T) {
	dir := t.TempDir()
	want := filepath.Join(dir, "openvpn")
	if err := os.WriteFile(want, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	printEngines(&buf, dir, false)
	out := buf.String()

	if !strings.Contains(out, "Engines (directory: "+dir) {
		t.Fatalf("report does not name the configured directory %q:\n%s", dir, out)
	}
	if !strings.Contains(out, want) {
		t.Fatalf("report does not resolve openvpn inside %q:\n%s", dir, out)
	}
}
