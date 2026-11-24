package geo

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDefaultSourcesArePinned is the F-002 regression: a moving branch means
// the shipped direct-routing policy can change without a product change.
func TestDefaultSourcesArePinned(t *testing.T) {
	for name, url := range map[string]string{"geoip": GeoipSRSURL, "geosite": GeositeSRSURL} {
		if !strings.Contains(url, "/raw.githubusercontent.com/") {
			t.Errorf("%s source %q does not address a commit-pinned file", name, url)
		}
		if strings.Contains(url, "/raw/rule-set/") || strings.Contains(url, "/main/") {
			t.Errorf("%s source %q addresses a moving ref", name, url)
		}
		commit := url[strings.Index(url, "/SagerNet/")+len("/SagerNet/"):]
		commit = commit[strings.Index(commit, "/")+1:]
		commit = commit[:strings.Index(commit, "/")]
		if len(commit) != 40 || strings.Trim(commit, "0123456789abcdef") != "" {
			t.Errorf("%s source %q does not carry a 40-hex commit", name, url)
		}
	}
}

func TestProvenanceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	asset := filepath.Join(dir, "geosite-ir.srs")
	payload := validSRS(t)
	if err := os.WriteFile(asset, payload, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := WriteProvenance(asset, "https://example.invalid/geosite-ir.srs"); err != nil {
		t.Fatalf("WriteProvenance: %v", err)
	}
	record, err := ReadProvenance(asset)
	if err != nil {
		t.Fatalf("ReadProvenance: %v", err)
	}
	if record.SourceURL != "https://example.invalid/geosite-ir.srs" {
		t.Errorf("source URL = %q", record.SourceURL)
	}
	if record.Size != int64(len(payload)) {
		t.Errorf("size = %d, want %d", record.Size, len(payload))
	}
	if record.SHA256 == "" || len(record.SHA256) != 64 {
		t.Errorf("sha256 = %q", record.SHA256)
	}
	if time.Since(record.FetchedAt) > time.Minute {
		t.Errorf("fetched_at = %v, not recent", record.FetchedAt)
	}
}

// TestDownloadRecordsProvenanceOfTheServedBytes ties the sidecar to the actual
// installed file, not to the request: a re-download must update both.
func TestDownloadRecordsProvenanceOfTheServedBytes(t *testing.T) {
	payload := validSRS(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer server.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "geoip-ir.srs")
	if err := downloadToFile(server.URL+"/pinned/geoip-ir.srs", dest); err != nil {
		t.Fatalf("downloadToFile: %v", err)
	}
	record, err := ReadProvenance(dest)
	if err != nil {
		t.Fatalf("ReadProvenance: %v", err)
	}
	if record.SourceURL != server.URL+"/pinned/geoip-ir.srs" {
		t.Errorf("source URL = %q", record.SourceURL)
	}
	installed, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	sum, size, err := hashFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if record.SHA256 != sum || record.Size != size {
		t.Errorf("sidecar does not match the installed bytes")
	}
	if !bytes.Equal(installed, payload) {
		t.Errorf("installed file does not match the served payload")
	}
}

// TestRejectedDownloadKeepsPreviousProvenance keeps the audit trail honest: a
// payload that fails validation must not replace the live sidecar either.
func TestRejectedDownloadKeepsPreviousProvenance(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "geosite-ir.srs")
	if err := os.WriteFile(dest, validSRS(t), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteProvenance(dest, "https://example.invalid/pinned.srs"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(ProvenancePath(dest))
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("SRS\x00stub"))
	}))
	defer server.Close()
	if err := downloadToFile(server.URL+"/broken.srs", dest); err == nil {
		t.Fatal("broken payload accepted")
	}

	after, err := os.ReadFile(ProvenancePath(dest))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a rejected download rewrote the provenance sidecar")
	}
	var record Provenance
	if err := json.Unmarshal(after, &record); err != nil {
		t.Fatal(err)
	}
	if record.SourceURL != "https://example.invalid/pinned.srs" {
		t.Fatalf("sidecar now describes %q", record.SourceURL)
	}
}
