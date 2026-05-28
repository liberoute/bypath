// Package updater checks for new versions and optionally self-updates.
package updater

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/liberoute/bypath/internal/build"
)

// Release represents a GitHub release.
type Release struct {
	TagName string  `json:"tag_name"`
	Name    string  `json:"name"`
	Body    string  `json:"body"`
	Assets  []Asset `json:"assets"`
}

// Asset represents a downloadable file in a release.
type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// CheckResult holds the result of an update check.
type CheckResult struct {
	Available      bool   `json:"available"`
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	ReleaseNotes   string `json:"release_notes,omitempty"`
	DownloadURL    string `json:"download_url,omitempty"`
	AssetName      string `json:"asset_name,omitempty"`
}

// Check queries the update URL for a newer version.
func Check() (*CheckResult, error) {
	if build.UpdateURL == "" {
		return &CheckResult{Available: false, CurrentVersion: build.Version}, nil
	}

	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", build.UpdateURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", build.UserAgent())

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("checking for updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update check returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var release Release
	if err := json.Unmarshal(body, &release); err != nil {
		return nil, fmt.Errorf("parsing release: %w", err)
	}

	latestVersion := strings.TrimPrefix(release.TagName, "v")
	currentVersion := strings.TrimPrefix(build.Version, "v")

	result := &CheckResult{
		CurrentVersion: currentVersion,
		LatestVersion:  latestVersion,
		ReleaseNotes:   release.Body,
	}

	// Simple version comparison (works for semver)
	if latestVersion != currentVersion && latestVersion > currentVersion {
		result.Available = true

		// Find matching asset for current OS/arch
		assetName := findAsset(release.Assets)
		if assetName != "" {
			for _, asset := range release.Assets {
				if asset.Name == assetName {
					result.DownloadURL = asset.BrowserDownloadURL
					result.AssetName = asset.Name
					break
				}
			}
		}
	}

	return result, nil
}

// CheckAndLog performs an update check and logs the result.
func CheckAndLog() {
	result, err := Check()
	if err != nil {
		log.Printf("⚠️  Update check failed: %v", err)
		return
	}

	if result.Available {
		log.Printf("🆕 New version available: %s → %s", result.CurrentVersion, result.LatestVersion)
		if result.DownloadURL != "" {
			log.Printf("   Download: %s", result.DownloadURL)
		}
	}
}

// findAsset determines the expected asset filename for the current platform.
// Format: bypath-{lite|full}-{os}-{arch}[.exe]
func findAsset(assets []Asset) string {
	os := runtime.GOOS
	arch := runtime.GOARCH
	ext := ""
	if os == "windows" {
		ext = ".exe"
	}

	// Try full first, then lite
	patterns := []string{
		fmt.Sprintf("%s-full-%s-%s%s", strings.ToLower(build.Name), os, arch, ext),
		fmt.Sprintf("%s-lite-%s-%s%s", strings.ToLower(build.Name), os, arch, ext),
		fmt.Sprintf("%s-%s-%s%s", strings.ToLower(build.Name), os, arch, ext),
	}

	for _, pattern := range patterns {
		for _, asset := range assets {
			if strings.EqualFold(asset.Name, pattern) {
				return asset.Name
			}
		}
	}

	return ""
}
