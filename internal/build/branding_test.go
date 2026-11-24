package build

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeExecutableStub creates a file that only needs to exist for path
// resolution; version probing fails and is reported as "?".
func writeExecutableStub(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDetectEnginesHonorsConfiguredDirectory(t *testing.T) {
	dir := t.TempDir()
	want := writeExecutableStub(t, dir, "openconnect")

	info := EngineInfo{Name: "openconnect", Source: "not found"}
	for _, e := range detectEngines(dir, false) {
		if e.Name == "openconnect" {
			info = e
			break
		}
	}
	if info.Source != "local" || info.Path != want {
		t.Fatalf("openconnect resolved to %q (%s), want %q (local)", info.Path, info.Source, want)
	}
}

func TestDetectHelpersHonorsConfiguredDirectory(t *testing.T) {
	dir := t.TempDir()
	want := writeExecutableStub(t, dir, "dns2socks")

	found := false
	for _, line := range detectHelpers(dir, false) {
		if strings.Contains(line, "dns2socks") && strings.Contains(line, want) {
			found = true
		}
	}
	if !found {
		t.Fatalf("dns2socks in %s not reported:\n%s", dir, strings.Join(detectHelpers(dir, false), "\n"))
	}
}

func TestPrintVersionInfoReportsEnginesDirectory(t *testing.T) {
	dir := t.TempDir()
	out := PrintVersionInfo(dir, false)
	if !strings.Contains(out, "Engines (directory: "+dir+")") {
		t.Fatalf("version report does not name the configured directory %q:\n%s", dir, out)
	}
	if !strings.Contains(out, "Variant:") {
		t.Fatalf("version report has no variant line:\n%s", out)
	}
	if !strings.Contains(out, "Gateway Helpers:") {
		t.Fatalf("version report has no helper section:\n%s", out)
	}
}

func TestEngineCandidatesOrder(t *testing.T) {
	dir := t.TempDir()
	local := writeExecutableStub(t, dir, "definitely-not-a-real-engine")

	got := engineCandidates([]string{"definitely-not-a-real-engine"}, dir, false)
	if len(got) != 1 || got[0].path != local || got[0].source != "local" {
		t.Fatalf("directory-first order returned %+v, want local %s", got, local)
	}

	got = engineCandidates([]string{"definitely-not-a-real-engine"}, dir, true)
	if len(got) == 0 {
		t.Fatal("no candidate returned with system-first order")
	}
	if got[len(got)-1].path != local || got[len(got)-1].source != "local" {
		t.Fatalf("system-first order does not end with the local binary: %+v", got)
	}
}

func TestLocalBinaryPlatformSuffix(t *testing.T) {
	dir := t.TempDir()
	name := "engine"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := localBinary(dir, "engine"); got != path {
		t.Fatalf("localBinary = %q, want %q", got, path)
	}
	if localBinary(filepath.Join(dir, "missing"), "engine") != "" {
		t.Fatal("localBinary found a binary in a directory that does not exist")
	}
}

func TestShortDigest(t *testing.T) {
	if got := shortDigest("0123456789abcdef"); got != "0123456789ab" {
		t.Fatalf("shortDigest = %q", got)
	}
	if got := shortDigest("abc"); got != "abc" {
		t.Fatalf("shortDigest short = %q", got)
	}
}

// TestFullVersionCarriesExactCommit proves a release binary identifies the
// revision it was built from, not just the release number.
func TestFullVersionCarriesExactCommit(t *testing.T) {
	oldVersion, oldCommit, oldDate, oldVariant := Version, Commit, BuildDate, Variant
	t.Cleanup(func() {
		Version, Commit, BuildDate, Variant = oldVersion, oldCommit, oldDate, oldVariant
	})

	Version = "3.0.0"
	Commit = "8ed3a18d065f354cf84389628ad5956bd9f7b67e"
	BuildDate = "2026-11-09T14:55:05Z"
	Variant = "full"

	want := "Bypath v3.0.0-8ed3a18d065f354cf84389628ad5956bd9f7b67e [FULL] built 2026-11-09T14:55:05Z"
	if got := FullVersion(); got != want {
		t.Fatalf("FullVersion() = %q, want %q", got, want)
	}
}

// TestUnstampedBuildKeepsBareVersion keeps a plain `go build` readable instead
// of tagging it with an unknown commit.
func TestUnstampedBuildKeepsBareVersion(t *testing.T) {
	oldVersion, oldCommit, oldDate, oldVariant := Version, Commit, BuildDate, Variant
	t.Cleanup(func() {
		Version, Commit, BuildDate, Variant = oldVersion, oldCommit, oldDate, oldVariant
	})

	Version = "3.0.0"
	Commit = "unknown"
	BuildDate = "unknown"
	Variant = "lite"

	if got := FullVersion(); got != "Bypath v3.0.0 [LITE] built unknown" {
		t.Fatalf("FullVersion() = %q", got)
	}
}
