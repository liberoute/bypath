package geo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

// validSRS returns a payload sing-box's own reader accepts. Provisioning now
// validates with srs.Read, so a magic-only stub would be rejected.
func validSRS(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	set := option.PlainRuleSet{Rules: []option.HeadlessRule{{
		Type:           C.RuleTypeDefault,
		DefaultOptions: option.DefaultHeadlessRule{DomainSuffix: []string{"fixture.example"}},
	}}}
	if err := srs.Write(&buf, set, C.RuleSetVersionCurrent); err != nil {
		t.Fatalf("encode fixture: %v", err)
	}
	return buf.Bytes()
}

func TestDownloadGeositeFiles_ReplacesCountryPlaceholder(t *testing.T) {
	payload := validSRS(t)
	// Track which URLs were requested
	var requestedURLs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedURLs = append(requestedURLs, r.URL.Path)
		w.Write(payload)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	urlTemplate := server.URL + "/geosite-{country}.srs"

	err := DownloadGeositeFiles(urlTemplate, []string{"de", "cn"}, tmpDir, 24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify correct URLs were requested
	expected := []string{"/geosite-de.srs", "/geosite-cn.srs"}
	if len(requestedURLs) != len(expected) {
		t.Fatalf("expected %d requests, got %d", len(expected), len(requestedURLs))
	}
	for i, url := range requestedURLs {
		if url != expected[i] {
			t.Errorf("request %d: expected %s, got %s", i, expected[i], url)
		}
	}
}

func TestDownloadGeositeFiles_SavesCorrectFilenames(t *testing.T) {
	payload := validSRS(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	urlTemplate := server.URL + "/geosite-{country}.srs"

	err := DownloadGeositeFiles(urlTemplate, []string{"de"}, tmpDir, 24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify file was saved with correct name
	expectedPath := filepath.Join(tmpDir, "geosite-de.srs")
	data, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("expected file at %s: %v", expectedPath, err)
	}
	if !bytes.Equal(data, payload) {
		t.Errorf("stored file does not match the served payload (%d vs %d bytes)", len(data), len(payload))
	}
}

func TestDownloadGeositeFiles_SkipsWhenFresh(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Write([]byte("fresh-data"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	urlTemplate := server.URL + "/geosite-{country}.srs"

	// Create a fresh file
	freshFile := filepath.Join(tmpDir, "geosite-de.srs")
	os.WriteFile(freshFile, []byte("existing-data"), 0644)

	err := DownloadGeositeFiles(urlTemplate, []string{"de"}, tmpDir, 24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should not have made any HTTP requests
	if requestCount != 0 {
		t.Errorf("expected 0 requests (file is fresh), got %d", requestCount)
	}

	// File should still have original content
	data, _ := os.ReadFile(freshFile)
	if string(data) != "existing-data" {
		t.Errorf("file should not have been overwritten")
	}
}

func TestDownloadGeositeFiles_RedownloadsWhenStale(t *testing.T) {
	payload := validSRS(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	urlTemplate := server.URL + "/geosite-{country}.srs"

	// Create a stale file (modified time in the past)
	staleFile := filepath.Join(tmpDir, "geosite-de.srs")
	os.WriteFile(staleFile, []byte("old-data"), 0644)
	pastTime := time.Now().Add(-48 * time.Hour)
	os.Chtimes(staleFile, pastTime, pastTime)

	err := DownloadGeositeFiles(urlTemplate, []string{"de"}, tmpDir, 24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// File should have been updated
	data, _ := os.ReadFile(staleFile)
	if !bytes.Equal(data, payload) {
		t.Errorf("stale file was not replaced by the served payload")
	}
}

func TestDownloadGeositeFiles_EmptyCountries(t *testing.T) {
	err := DownloadGeositeFiles("http://example.com/{country}.srs", nil, t.TempDir(), 24*time.Hour)
	if err != nil {
		t.Fatalf("expected nil error for empty countries, got: %v", err)
	}
}

func TestDownloadGeositeFiles_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	urlTemplate := server.URL + "/geosite-{country}.srs"

	err := DownloadGeositeFiles(urlTemplate, []string{"de"}, tmpDir, 24*time.Hour)
	if err == nil {
		t.Fatal("expected error for HTTP 404, got nil")
	}

	// File should not exist
	_, statErr := os.Stat(filepath.Join(tmpDir, "geosite-de.srs"))
	if !os.IsNotExist(statErr) {
		t.Error("file should not exist after failed download")
	}
}

func TestGeositeURLCandidatesBuiltinOrder(t *testing.T) {
	got := geositeURLCandidates(GeositeSRSURL, "ir")
	want := []string{
		"https://raw.githubusercontent.com/SagerNet/sing-geosite/26c0cb522fec8baeb3cd48497ebec30866512ad2/geosite-ir.srs",
		"https://raw.githubusercontent.com/SagerNet/sing-geosite/26c0cb522fec8baeb3cd48497ebec30866512ad2/geosite-category-ir.srs",
	}
	if len(got) != len(want) {
		t.Fatalf("candidates %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestGeositeURLCandidatesCustomTemplateKeepsItsHost(t *testing.T) {
	template := "https://mirror.example.net/geo/geosite-{country}.srs"
	got := geositeURLCandidates(template, "ir")
	if len(got) != 2 {
		t.Fatalf("candidates %v, want a plain and a category URL", got)
	}
	if got[1] != "https://mirror.example.net/geo/geosite-category-ir.srs" {
		t.Fatalf("category candidate %q does not stay on the operator's host", got[1])
	}

	noCountryName := geositeURLCandidates("https://mirror.example.net/lists/{country}.srs", "ir")
	if len(noCountryName) != 1 {
		t.Fatalf("template without a geosite- file name gained candidates: %v", noCountryName)
	}
}

// TestDownloadGeositeFilesFallsBackToCategoryName pins the source fix: the
// country split needs geosite-category-ir.srs because no geosite-ir.srs exists.
func TestDownloadGeositeFilesFallsBackToCategoryName(t *testing.T) {
	payload := validSRS(t)
	var requested []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = append(requested, r.URL.Path)
		if r.URL.Path == "/geosite-ir.srs" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write(payload)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	err := DownloadGeositeFiles(server.URL+"/geosite-{country}.srs", []string{"ir"}, tmpDir, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(requested) != 2 || requested[1] != "/geosite-category-ir.srs" {
		t.Fatalf("requests %v, want a fallback to the category file", requested)
	}
	data, readErr := os.ReadFile(filepath.Join(tmpDir, "geosite-ir.srs"))
	if readErr != nil {
		t.Fatalf("expected the local file name to stay geosite-ir.srs: %v", readErr)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("stored file does not match the served payload")
	}
}

func TestDownloadGeositeFiles_WarnsOnUpdateFailureWithExistingFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	urlTemplate := server.URL + "/geosite-{country}.srs"

	// Create a stale file (will trigger update attempt)
	staleFile := filepath.Join(tmpDir, "geosite-de.srs")
	os.WriteFile(staleFile, []byte("existing-data"), 0644)
	pastTime := time.Now().Add(-48 * time.Hour)
	os.Chtimes(staleFile, pastTime, pastTime)

	err := DownloadGeositeFiles(urlTemplate, []string{"de"}, tmpDir, 24*time.Hour)
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}

	// Existing file should still be present (not deleted)
	data, readErr := os.ReadFile(staleFile)
	if readErr != nil {
		t.Fatalf("existing file should still be present: %v", readErr)
	}
	if string(data) != "existing-data" {
		t.Errorf("existing file content should be preserved, got '%s'", string(data))
	}
}

func TestDownloadGeositeFiles_ErrorsOnFailureWithNoExistingFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	urlTemplate := server.URL + "/geosite-{country}.srs"

	// No existing file — download failure should result in error
	err := DownloadGeositeFiles(urlTemplate, []string{"de"}, tmpDir, 24*time.Hour)
	if err == nil {
		t.Fatal("expected error for HTTP 404 with no existing file, got nil")
	}

	// File should not exist
	_, statErr := os.Stat(filepath.Join(tmpDir, "geosite-de.srs"))
	if !os.IsNotExist(statErr) {
		t.Error("file should not exist after failed download with no existing file")
	}
}

func TestValidateGeositeFiles_ReturnsOnlyExistingCountries(t *testing.T) {
	tmpDir := t.TempDir()

	// Create files for "de" and "cn" but not "us"
	payload := validSRS(t)
	os.WriteFile(filepath.Join(tmpDir, "geosite-de.srs"), payload, 0644)
	os.WriteFile(filepath.Join(tmpDir, "geosite-cn.srs"), payload, 0644)

	result := ValidateGeositeFiles([]string{"de", "cn", "us"}, tmpDir)

	if len(result) != 2 {
		t.Fatalf("expected 2 valid countries, got %d: %v", len(result), result)
	}
	if result[0] != "de" || result[1] != "cn" {
		t.Errorf("expected [de cn], got %v", result)
	}
}

func TestValidateGeositeFiles_EmptyCountries(t *testing.T) {
	result := ValidateGeositeFiles(nil, t.TempDir())
	if result != nil {
		t.Errorf("expected nil for empty countries, got %v", result)
	}
}

func TestValidateGeositeFiles_NoneExist(t *testing.T) {
	tmpDir := t.TempDir()
	result := ValidateGeositeFiles([]string{"de", "cn"}, tmpDir)
	if len(result) != 0 {
		t.Errorf("expected empty result when no files exist, got %v", result)
	}
}

func TestNeedsUpdate_FileDoesNotExist(t *testing.T) {
	if !needsUpdate("/nonexistent/path", 24*time.Hour) {
		t.Error("expected needsUpdate=true for nonexistent file")
	}
}

func TestNeedsUpdate_FreshFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.srs")
	os.WriteFile(tmpFile, []byte("data"), 0644)

	if needsUpdate(tmpFile, 24*time.Hour) {
		t.Error("expected needsUpdate=false for fresh file")
	}
}

func TestNeedsUpdate_StaleFile(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "test.srs")
	os.WriteFile(tmpFile, []byte("data"), 0644)
	pastTime := time.Now().Add(-48 * time.Hour)
	os.Chtimes(tmpFile, pastTime, pastTime)

	if !needsUpdate(tmpFile, 24*time.Hour) {
		t.Error("expected needsUpdate=true for stale file")
	}
}

// TestDownloadRejectsTruncatedSRS is the F-007 regression: an 8-byte "SRS"
// stub used to pass provisioning and then made sing-box refuse the whole
// configuration at the next start.
func TestDownloadRejectsTruncatedSRS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("SRS\x00stub"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	dest := filepath.Join(tmpDir, "geosite-de.srs")
	existing := validSRS(t)
	if err := os.WriteFile(dest, existing, 0644); err != nil {
		t.Fatal(err)
	}

	if err := downloadToFile(server.URL+"/geosite-de.srs", dest); err == nil {
		t.Fatal("truncated stub was accepted")
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("working asset disappeared: %v", err)
	}
	if !bytes.Equal(data, existing) {
		t.Fatal("a rejected download replaced the working asset")
	}
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
}

// TestDownloadRejectsUnsupportedSRSVersion covers the second half of the same
// defect: a file with valid magic but a format version newer than the engine
// supports is refused by srs.Read and must not be installed.
func TestDownloadRejectsUnsupportedSRSVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(append([]byte("SRS"), 0xff, 0x00, 0x00))
	}))
	defer server.Close()

	dest := filepath.Join(t.TempDir(), "geoip-de.srs")
	if err := downloadToFile(server.URL+"/geoip-de.srs", dest); err == nil {
		t.Fatal("unsupported format version was accepted")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("rejected download was installed")
	}
}

func TestValidateGeositeFilesRejectsStub(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "geosite-de.srs"), []byte("SRS\x00stub"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := ValidateGeositeFiles([]string{"de"}, dir); len(got) != 0 {
		t.Fatalf("magic-only stub counted as usable: %v", got)
	}
}

func TestDownloadRejectsMalformedDat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte("<html>error page</html>"), 100))
	}))
	defer server.Close()

	dest := filepath.Join(t.TempDir(), "geoip.dat")
	if err := downloadToFile(server.URL+"/geoip.dat", dest); err == nil {
		t.Fatal("HTML payload was installed as a geo database")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("rejected download was installed")
	}
}

func datDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TestDownloadXraySourcesVerifiesPinnedDigest is the R2-16 contract: a .dat is
// installed only when it matches the pinned SHA-256, and a mismatch leaves the
// existing asset untouched.
func TestDownloadXraySourcesVerifiesPinnedDigest(t *testing.T) {
	payload := buildDat([]string{"IR"}, 1200)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer server.Close()

	dir := t.TempDir()
	source := xrayGeoSource{url: server.URL + "/geoip.dat", dest: "geoip.dat", sha256: datDigest(payload)}
	if err := downloadXraySources([]xrayGeoSource{source}, dir, 0); err != nil {
		t.Fatalf("pinned download: %v", err)
	}
	dest := filepath.Join(dir, "geoip.dat")
	if !HasXrayCategory(dest, "IR") {
		t.Fatal("pinned database was not installed")
	}
	before, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}

	source.sha256 = strings.Repeat("0", 64)
	if err := downloadXraySources([]xrayGeoSource{source}, dir, 0); err == nil {
		t.Fatal("a database with a mismatched digest was accepted")
	}
	after, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a mismatched download replaced the installed asset")
	}
}

// TestDownloadRejectsOversizedAsset enforces the size cap before the payload is
// considered.
func TestDownloadRejectsOversizedAsset(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte("A"), 2048))
	}))
	defer server.Close()

	dest := filepath.Join(t.TempDir(), "geoip.dat")
	if err := downloadToFileChecked(server.URL+"/geoip.dat", dest, "", 1024); err == nil {
		t.Fatal("oversized asset was accepted")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("oversized download was installed")
	}
}
