package updater

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/build"
)

func feedAssetName(variant string) string {
	name := fmt.Sprintf("%s-%s-%s-%s", strings.ToLower(build.Name), variant, runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return name
}

// TestCheckURLNoFeed keeps an unconfigured build offline instead of querying
// another project's release line.
func TestCheckURLNoFeed(t *testing.T) {
	result, err := CheckURL("")
	if err != nil {
		t.Fatalf("CheckURL(\"\") returned an error: %v", err)
	}
	if result.Available {
		t.Fatal("CheckURL(\"\") reported an available update")
	}
}

func TestCheckURLRelease(t *testing.T) {
	lite, full := feedAssetName("lite"), feedAssetName("full")
	digest := "sha256:" + sampleSHA
	feed := fmt.Sprintf(`{
		"tag_name": "v99.0.0",
		"body": "test release",
		"assets": [
			{"name": %q, "browser_download_url": "https://example.invalid/lite", "size": 1, "digest": %q},
			{"name": %q, "browser_download_url": "https://example.invalid/full", "size": 2, "digest": %q}
		]
	}`, lite, digest, full, digest)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got == "" {
			t.Errorf("update check sent no User-Agent")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, feed)
	}))
	defer srv.Close()

	result, err := CheckURL(srv.URL)
	if err != nil {
		t.Fatalf("CheckURL: %v", err)
	}
	if !result.Available {
		t.Fatalf("newer tag was not reported as available: %+v", result)
	}
	if result.LatestVersion != "99.0.0" {
		t.Errorf("LatestVersion = %q, want 99.0.0", result.LatestVersion)
	}
	if result.ReleaseNotes != "test release" {
		t.Errorf("ReleaseNotes = %q", result.ReleaseNotes)
	}
	if result.AssetName == "" || (result.AssetName != lite && result.AssetName != full) {
		t.Errorf("AssetName = %q, want one of the published assets", result.AssetName)
	}
	if result.DownloadURL == "" {
		t.Error("DownloadURL is empty for a matched asset")
	}
	if result.DownloadDigest != digest {
		t.Errorf("DownloadDigest = %q, want %q", result.DownloadDigest, digest)
	}
}

func TestCheckURLSameVersion(t *testing.T) {
	feed := fmt.Sprintf(`{"tag_name": "v%s", "assets": []}`, strings.TrimPrefix(build.Version, "v"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, feed)
	}))
	defer srv.Close()

	result, err := CheckURL(srv.URL)
	if err != nil {
		t.Fatalf("CheckURL: %v", err)
	}
	if result.Available {
		t.Fatalf("current version was reported as an update: %+v", result)
	}
}

func TestCheckURLErrors(t *testing.T) {
	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer notFound.Close()

	badJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json")
	}))
	defer badJSON.Close()

	if _, err := CheckURL(notFound.URL); err == nil {
		t.Error("non-200 feed response was accepted")
	}
	if _, err := CheckURL(badJSON.URL); err == nil {
		t.Error("malformed feed body was accepted")
	}
	if _, err := CheckURL("http://127.0.0.1:1/unreachable"); err == nil {
		t.Error("unreachable feed was accepted")
	}
}
