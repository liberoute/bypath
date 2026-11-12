package engine

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestDownloadVerifiedAcceptsMatchingChecksum(t *testing.T) {
	payload := []byte("verified engine bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "engine")
	if err := downloadVerified(srv.URL+"/engine.tar.gz", dest, sha256Hex(payload)); err != nil {
		t.Fatalf("downloadVerified: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("content mismatch")
	}
}

func TestDownloadVerifiedRejectsMismatchAndRemovesFile(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("tampered"))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "engine")
	err := downloadVerified(srv.URL+"/engine.tar.gz", dest, strings64("0"))
	if err == nil {
		t.Fatal("downloadVerified accepted a checksum mismatch")
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Fatalf("mismatched download survived: %v", statErr)
	}
}

func TestDownloadVerifiedRejectsInvalidPinnedChecksum(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "engine")
	if err := downloadVerified("https://example.invalid/engine", dest, "not-a-hash"); err == nil {
		t.Fatal("downloadVerified accepted a malformed pinned checksum")
	}
}

func TestDownloadVerifiedRejectsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "engine")
	if err := downloadVerified(srv.URL+"/engine", dest, strings64("a")); err == nil {
		t.Fatal("downloadVerified accepted HTTP 404")
	}
}

func strings64(c string) string {
	out := ""
	for len(out) < 64 {
		out += c
	}
	return out
}

func makeTarGz(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	for name, body := range entries {
		hdr := &tar.Header{Name: name, Mode: 0755, Size: int64(len(body)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func makeZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInstallArtifactExtractsOnlyExpectedBinary(t *testing.T) {
	dir := t.TempDir()
	archive := writeTemp(t, "sing-box.tar.gz", makeTarGz(t, map[string]string{
		"sing-box-1.14.4-linux-amd64/sing-box":  "real-binary",
		"sing-box-1.14.4-linux-amd64/evil":      "malware",
		"sing-box-1.14.4-linux-amd64/README.md": "docs",
	}))

	if err := installArtifact(archive, "sing-box-1.14.4-linux-amd64.tar.gz", dir, "sing-box"); err != nil {
		t.Fatalf("installArtifact: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "sing-box"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "real-binary" {
		t.Fatalf("binary content = %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "evil")); !os.IsNotExist(err) {
		t.Fatal("installer extracted an entry other than the expected binary")
	}
}

func TestInstallArtifactRejectsArchiveWithoutBinary(t *testing.T) {
	dir := t.TempDir()
	archive := writeTemp(t, "xray.zip", makeZip(t, map[string]string{
		"Xray-linux-64/geoip.dat": "data",
	}))
	if err := installArtifact(archive, "Xray-linux-64.zip", dir, "xray"); err == nil {
		t.Fatal("installArtifact accepted an archive without the expected binary")
	}
}

func TestInstallArtifactRejectsDuplicateBinaries(t *testing.T) {
	dir := t.TempDir()
	archive := writeTemp(t, "xray.zip", makeZip(t, map[string]string{
		"a/xray": "one",
		"b/xray": "two",
	}))
	if err := installArtifact(archive, "Xray-linux-64.zip", dir, "xray"); err == nil {
		t.Fatal("installArtifact accepted an archive with two candidate binaries")
	}
}

func TestInstallArtifactKeepsPreviousBinaryOnFailure(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "xray")
	if err := os.WriteFile(dest, []byte("working"), 0755); err != nil {
		t.Fatal(err)
	}
	archive := writeTemp(t, "xray.zip", makeZip(t, map[string]string{
		"Xray-linux-64/README.md": "docs",
	}))
	if err := installArtifact(archive, "Xray-linux-64.zip", dir, "xray"); err == nil {
		t.Fatal("expected failure")
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "working" {
		t.Fatalf("failed install replaced the working binary with %q", got)
	}
}

func TestDownloadVerifiedDoesNotRetryHTTPStatus(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "engine")
	if err := downloadVerified(srv.URL+"/engine", dest, strings64("a")); err == nil {
		t.Fatal("downloadVerified accepted HTTP 404")
	}
	if hits != 1 {
		t.Fatalf("server saw %d requests, want 1 (status errors must not retry)", hits)
	}
}
