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
// exist in geoDir and carry the sing-box binary rule-set magic. This should be
// called after DownloadGeositeFiles to filter the country list to only those
// with usable files; a corrupt file must not be referenced by the engine.
func ValidateGeositeFiles(countries []string, geoDir string) []string {
	if len(countries) == 0 {
		return nil
	}

	var valid []string
	for _, country := range countries {
		filename := fmt.Sprintf("geosite-%s.srs", country)
		destPath := filepath.Join(geoDir, filename)
		if ValidSRSFile(destPath) {
			valid = append(valid, country)
		}
	}
	return valid
}

// ValidSRSFile reports whether path exists and starts with the sing-box binary
// rule-set magic.
func ValidSRSFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 3)
	if _, err := io.ReadFull(f, head); err != nil {
		return false
	}
	return ValidateSRS(head)
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

// DownloadXrayGeoFiles downloads geoip.dat and geosite.dat in xray/v2ray format.
// These are different from the sing-box .srs rule-set files and are required
// by the xray engine for routing rules like "geoip:cc".
// Files are saved as geoDir/geoip.dat and geoDir/geosite.dat.
// Files are only re-downloaded if they don't exist or are older than updateInterval.
func DownloadXrayGeoFiles(geoDir string, updateInterval time.Duration) error {
	if err := os.MkdirAll(geoDir, 0755); err != nil {
		return fmt.Errorf("creating geo directory: %w", err)
	}

	files := []struct {
		url  string
		dest string
	}{
		{"https://github.com/v2fly/geoip/releases/latest/download/geoip.dat", "geoip.dat"},
		// dlc.dat is the v2fly domain-list-community release — saved as geosite.dat (xray convention)
		{"https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat", "geosite.dat"},
	}

	var lastErr error
	for _, f := range files {
		destPath := filepath.Join(geoDir, f.dest)
		if !needsUpdate(destPath, updateInterval) {
			log.Printf("  ✅ %s is up to date", f.dest)
			continue
		}

		_, existsErr := os.Stat(destPath)
		fileExists := existsErr == nil

		log.Printf("🌍 Downloading %s (xray format)...", f.dest)
		if err := downloadToFile(f.url, destPath); err != nil {
			lastErr = err
			if fileExists {
				log.Printf("⚠️  Failed to update %s: %v (using existing file)", f.dest, err)
			} else {
				log.Printf("❌ Failed to download %s: %v (xray routing rules will be skipped)", f.dest, err)
			}
			continue
		}
		log.Printf("  ✅ Downloaded %s", f.dest)
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

// downloadHTTPTimeout bounds one geo asset download. Without it a stalled
// connection would hold startup inside the download path forever.
const downloadHTTPTimeout = 90 * time.Second

// downloadToFile downloads a URL and saves it to destPath.
// It writes to a temporary file, validates the payload, then renames it into
// place, so a partial body or an HTML error page served with HTTP 200 can never
// replace a working asset.
func downloadToFile(url, destPath string) error {
	client := &http.Client{Timeout: downloadHTTPTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	dir := filepath.Dir(destPath)
	tmpFile, err := os.CreateTemp(dir, "geo-download-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	head := make([]byte, 3)
	n, headErr := io.ReadFull(resp.Body, head)
	if headErr != nil && headErr != io.ErrUnexpectedEOF {
		tmpFile.Close()
		cleanup()
		return fmt.Errorf("reading response: %w", headErr)
	}
	if _, err := tmpFile.Write(head[:n]); err != nil {
		tmpFile.Close()
		cleanup()
		return fmt.Errorf("writing file: %w", err)
	}
	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		tmpFile.Close()
		cleanup()
		return fmt.Errorf("writing file: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		cleanup()
		return fmt.Errorf("flushing file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		cleanup()
		return fmt.Errorf("closing file: %w", err)
	}

	if err := validateAsset(tmpPath, destPath, head[:n]); err != nil {
		cleanup()
		return err
	}

	// Atomic rename. Windows refuses to rename over an existing file.
	if err := os.Rename(tmpPath, destPath); err != nil {
		_ = os.Remove(destPath)
		if err2 := os.Rename(tmpPath, destPath); err2 != nil {
			cleanup()
			return fmt.Errorf("renaming temp file: %w", err2)
		}
	}
	return nil
}

// validateAsset rejects payloads the engines cannot load. sing-box rule sets are
// binary "SRS" documents; xray .dat files are protobuf category lists. Both
// checks also catch captive-portal HTML that arrives with a 200 status.
func validateAsset(tmpPath, destPath string, head []byte) error {
	switch {
	case strings.HasSuffix(destPath, ".srs"):
		if !ValidateSRS(head) {
			return fmt.Errorf("downloaded rule set is not a binary sing-box rule set (bad magic)")
		}
	case strings.HasSuffix(destPath, ".dat"):
		if len(head) < 1 || head[0] != 0x0a {
			return fmt.Errorf("downloaded geo database is not an xray/v2fly category list")
		}
		if info, err := os.Stat(tmpPath); err != nil || info.Size() < 1000 {
			return fmt.Errorf("downloaded geo database is implausibly small")
		}
	}
	return nil
}
