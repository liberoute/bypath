package geo

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDownloadGeositeFiles_ReplacesCountryPlaceholder(t *testing.T) {
	// Track which URLs were requested
	var requestedURLs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedURLs = append(requestedURLs, r.URL.Path)
		w.Write([]byte("fake-srs-data"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	urlTemplate := server.URL + "/geosite-{country}.srs"

	err := DownloadGeositeFiles(urlTemplate, []string{"ir", "cn"}, tmpDir, 24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify correct URLs were requested
	expected := []string{"/geosite-ir.srs", "/geosite-cn.srs"}
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("fake-srs-data"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	urlTemplate := server.URL + "/geosite-{country}.srs"

	err := DownloadGeositeFiles(urlTemplate, []string{"ir"}, tmpDir, 24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify file was saved with correct name
	expectedPath := filepath.Join(tmpDir, "geosite-ir.srs")
	data, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("expected file at %s: %v", expectedPath, err)
	}
	if string(data) != "fake-srs-data" {
		t.Errorf("expected file content 'fake-srs-data', got '%s'", string(data))
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
	freshFile := filepath.Join(tmpDir, "geosite-ir.srs")
	os.WriteFile(freshFile, []byte("existing-data"), 0644)

	err := DownloadGeositeFiles(urlTemplate, []string{"ir"}, tmpDir, 24*time.Hour)
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
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("new-data"))
	}))
	defer server.Close()

	tmpDir := t.TempDir()
	urlTemplate := server.URL + "/geosite-{country}.srs"

	// Create a stale file (modified time in the past)
	staleFile := filepath.Join(tmpDir, "geosite-ir.srs")
	os.WriteFile(staleFile, []byte("old-data"), 0644)
	pastTime := time.Now().Add(-48 * time.Hour)
	os.Chtimes(staleFile, pastTime, pastTime)

	err := DownloadGeositeFiles(urlTemplate, []string{"ir"}, tmpDir, 24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// File should have been updated
	data, _ := os.ReadFile(staleFile)
	if string(data) != "new-data" {
		t.Errorf("expected 'new-data', got '%s'", string(data))
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

	err := DownloadGeositeFiles(urlTemplate, []string{"ir"}, tmpDir, 24*time.Hour)
	if err == nil {
		t.Fatal("expected error for HTTP 404, got nil")
	}

	// File should not exist
	_, statErr := os.Stat(filepath.Join(tmpDir, "geosite-ir.srs"))
	if !os.IsNotExist(statErr) {
		t.Error("file should not exist after failed download")
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
	staleFile := filepath.Join(tmpDir, "geosite-ir.srs")
	os.WriteFile(staleFile, []byte("existing-data"), 0644)
	pastTime := time.Now().Add(-48 * time.Hour)
	os.Chtimes(staleFile, pastTime, pastTime)

	err := DownloadGeositeFiles(urlTemplate, []string{"ir"}, tmpDir, 24*time.Hour)
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
	err := DownloadGeositeFiles(urlTemplate, []string{"ir"}, tmpDir, 24*time.Hour)
	if err == nil {
		t.Fatal("expected error for HTTP 404 with no existing file, got nil")
	}

	// File should not exist
	_, statErr := os.Stat(filepath.Join(tmpDir, "geosite-ir.srs"))
	if !os.IsNotExist(statErr) {
		t.Error("file should not exist after failed download with no existing file")
	}
}

func TestValidateGeositeFiles_ReturnsOnlyExistingCountries(t *testing.T) {
	tmpDir := t.TempDir()

	// Create files for "ir" and "cn" but not "us"
	os.WriteFile(filepath.Join(tmpDir, "geosite-ir.srs"), []byte("data"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "geosite-cn.srs"), []byte("data"), 0644)

	result := ValidateGeositeFiles([]string{"ir", "cn", "us"}, tmpDir)

	if len(result) != 2 {
		t.Fatalf("expected 2 valid countries, got %d: %v", len(result), result)
	}
	if result[0] != "ir" || result[1] != "cn" {
		t.Errorf("expected [ir cn], got %v", result)
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
	result := ValidateGeositeFiles([]string{"ir", "cn"}, tmpDir)
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
