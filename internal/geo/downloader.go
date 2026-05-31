// Package geo handles downloading and updating geoip/geosite rule set files.
package geo

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DownloadGeositeFiles downloads geosite .srs files for the given countries.
// It replaces {country} in urlTemplate with each country code and saves to geoDir/geosite-{country}.srs.
// Files are only re-downloaded if they don't exist or are older than updateInterval.
//
// Error handling:
//   - If a file exists but the update download fails: logs a warning (⚠️) and continues with the existing file.
//   - If a file does not exist and the download fails: logs an error (❌) — the country will have no valid file.
//
// Use ValidateGeositeFiles after calling this to determine which countries have usable files.
func DownloadGeositeFiles(urlTemplate string, countries []string, geoDir string, updateInterval time.Duration) error {
	if len(countries) == 0 {
		return nil
	}

	// Ensure geoDir exists
	if err := os.MkdirAll(geoDir, 0755); err != nil {
		return fmt.Errorf("creating geo directory: %w", err)
	}

	var lastErr error
	for _, country := range countries {
		filename := fmt.Sprintf("geosite-%s.srs", country)
		destPath := filepath.Join(geoDir, filename)

		// Check if file exists and is fresh enough
		if !needsUpdate(destPath, updateInterval) {
			log.Printf("  ✅ %s is up to date", filename)
			continue
		}

		// Determine if an existing file is available before attempting download
		_, existsErr := os.Stat(destPath)
		fileExists := existsErr == nil

		// Build download URL from template
		url := strings.ReplaceAll(urlTemplate, "{country}", country)

		log.Printf("🌍 Downloading %s ...", filename)
		if err := downloadToFile(url, destPath); err != nil {
			lastErr = err
			if fileExists {
				// File exists but update failed — warn and continue with existing file
				log.Printf("⚠️  Failed to update %s: %v (using existing file)", filename, err)
			} else {
				// File doesn't exist and download failed — error, geosite rules must be skipped for this country
				log.Printf("❌ Failed to download %s: %v (no existing file, geosite rules will be skipped for %s)", filename, err, country)
			}
			continue
		}
		log.Printf("  ✅ Downloaded %s", filename)
	}

	return lastErr
}

// ValidateGeositeFiles returns only the countries whose geosite .srs files
// actually exist in geoDir. This should be called after DownloadGeositeFiles
// to filter the country list to only those with available rule set files.
func ValidateGeositeFiles(countries []string, geoDir string) []string {
	if len(countries) == 0 {
		return nil
	}

	var valid []string
	for _, country := range countries {
		filename := fmt.Sprintf("geosite-%s.srs", country)
		destPath := filepath.Join(geoDir, filename)
		if _, err := os.Stat(destPath); err == nil {
			valid = append(valid, country)
		}
	}
	return valid
}

// DownloadGeoipFiles downloads geoip .srs files for the given countries.
// It replaces {country} in urlTemplate with each country code and saves to geoDir/geoip-{country}.srs.
// Files are only re-downloaded if they don't exist or are older than updateInterval.
func DownloadGeoipFiles(urlTemplate string, countries []string, geoDir string, updateInterval time.Duration) error {
	if len(countries) == 0 {
		return nil
	}

	// Ensure geoDir exists
	if err := os.MkdirAll(geoDir, 0755); err != nil {
		return fmt.Errorf("creating geo directory: %w", err)
	}

	var lastErr error
	for _, country := range countries {
		filename := fmt.Sprintf("geoip-%s.srs", country)
		destPath := filepath.Join(geoDir, filename)

		// Check if file exists and is fresh enough
		if !needsUpdate(destPath, updateInterval) {
			log.Printf("  ✅ %s is up to date", filename)
			continue
		}

		// Build download URL from template
		url := strings.ReplaceAll(urlTemplate, "{country}", country)

		log.Printf("🌍 Downloading %s ...", filename)
		if err := downloadToFile(url, destPath); err != nil {
			lastErr = err
			log.Printf("⚠️  Failed to download %s: %v", filename, err)
			continue
		}
		log.Printf("  ✅ Downloaded %s", filename)
	}

	return lastErr
}

// needsUpdate returns true if the file doesn't exist or is older than maxAge.
func needsUpdate(path string, maxAge time.Duration) bool {
	info, err := os.Stat(path)
	if err != nil {
		// File doesn't exist or can't be read
		return true
	}
	return time.Since(info.ModTime()) > maxAge
}

// downloadToFile downloads a URL and saves it to destPath.
// It writes to a temporary file first, then renames to avoid partial files.
func downloadToFile(url, destPath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Write to temp file in the same directory (for atomic rename)
	dir := filepath.Dir(destPath)
	tmpFile, err := os.CreateTemp(dir, "geo-download-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	_, err = io.Copy(tmpFile, resp.Body)
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("writing file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, destPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("renaming temp file: %w", err)
	}

	return nil
}
