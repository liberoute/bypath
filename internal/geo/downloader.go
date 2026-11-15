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

	"github.com/sagernet/sing-box/common/srs"
)

// GeoipSRSURL and GeositeSRSURL are the default binary rule-set sources. They
// address immutable upstream commits, not the moving rule-set branch: the
// shipped policy must not change because someone pushed upstream, and an
// operator who wants fresher data sets whitelist.geoip_url / geosite_url
// explicitly.
//
// sing-geosite publishes its lists under their v2fly tag names, and country
// lists are usually named category-<cc> with no plain geosite-<cc> file at all.
// The category name is therefore tried when the plain file is absent.
const (
	GeoipSRSURL   = "https://raw.githubusercontent.com/SagerNet/sing-geoip/66c864fcfe1535549e0658569cb514dbd35756ba/geoip-{country}.srs"
	GeositeSRSURL = "https://raw.githubusercontent.com/SagerNet/sing-geosite/26c0cb522fec8baeb3cd48497ebec30866512ad2/geosite-{country}.srs"
)

// geositeURLCandidates lists the sources to try for one country, in order. The
// category variant keeps the operator's host and path and only changes the
// published file name, so a custom endpoint is never mixed with the built-in
// source.
func geositeURLCandidates(template, country string) []string {
	primary := strings.ReplaceAll(template, "{country}", country)
	candidates := []string{primary}
	if slash := strings.LastIndex(template, "/"); slash >= 0 && strings.HasPrefix(template[slash+1:], "geosite-") {
		fallback := template[:slash+1] + "geosite-category-" + template[slash+1+len("geosite-"):]
		candidates = append(candidates, strings.ReplaceAll(fallback, "{country}", country))
	}
	return candidates
}

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

		log.Printf("🌍 Downloading %s ...", filename)
		var err error
		for _, url := range geositeURLCandidates(urlTemplate, country) {
			if err = downloadToFile(url, destPath); err == nil {
				break
			}
		}
		if err != nil {
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

// ValidSRSFile reports whether path is a binary rule set the engine can load.
// It calls the engine's own reader with recover=false, exactly as sing-box does
// for a local rule set, so a truncated stub, an HTML error page and an
// unsupported format version are all rejected here instead of at engine start.
func ValidSRSFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	_, err = srs.Read(f, false)
	return err == nil
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

// Xray .dat sources. The sing-box .srs sources above are commit-pinned; these
// are tied to an immutable release tag and to the SHA-256 that release
// published, so the databases xray loads cannot change because upstream moved
// "latest". An operator who needs fresher data must ship a new pin with a new
// digest; there is deliberately no override that bypasses verification.
const (
	XrayGeoipURL      = "https://github.com/v2fly/geoip/releases/download/202611080027/geoip.dat"
	XrayGeoipSHA256   = "eedb24b3b9fcba27e06b92c0428dab90d9496083091ae4cf39e11387fd99d0e2"
	XrayGeositeURL    = "https://github.com/v2fly/domain-list-community/releases/download/20261115005626/dlc.dat"
	XrayGeositeSHA256 = "26e5f04c498ea651f62fa864f8e83ac5198ca311724e634d79f0ac02cdfe74fc"
)

// maxGeoDatSize bounds one .dat download. The pinned files are about 24 MB and
// 2.4 MB; anything far larger is not the asset this build expects.
const maxGeoDatSize = 128 << 20

// xrayGeoSource is one pinned database download.
type xrayGeoSource struct {
	url    string
	dest   string
	sha256 string
}

// DownloadXrayGeoFiles downloads the pinned geoip.dat and geosite.dat in
// xray/v2ray format. Each file must match the SHA-256 published with its
// immutable release, so a tampered or replaced asset is refused rather than
// widening DIRECT on the xray path.
func DownloadXrayGeoFiles(geoDir string, updateInterval time.Duration) error {
	return downloadXraySources([]xrayGeoSource{
		{url: XrayGeoipURL, dest: "geoip.dat", sha256: XrayGeoipSHA256},
		{url: XrayGeositeURL, dest: "geosite.dat", sha256: XrayGeositeSHA256},
	}, geoDir, updateInterval)
}

func downloadXraySources(sources []xrayGeoSource, geoDir string, updateInterval time.Duration) error {
	if err := os.MkdirAll(geoDir, 0755); err != nil {
		return fmt.Errorf("creating geo directory: %w", err)
	}

	var lastErr error
	for _, f := range sources {
		destPath := filepath.Join(geoDir, f.dest)
		if !needsUpdate(destPath, updateInterval) {
			log.Printf("  ✅ %s is up to date", f.dest)
			continue
		}

		_, existsErr := os.Stat(destPath)
		fileExists := existsErr == nil

		log.Printf("🌍 Downloading %s (xray format)...", f.dest)
		if err := downloadToFileChecked(f.url, destPath, f.sha256, maxGeoDatSize); err != nil {
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
	return downloadToFileChecked(url, destPath, "", 0)
}

// downloadToFileChecked is downloadToFile with an optional pinned digest and
// size cap. A mismatch is an error and leaves any existing asset untouched.
func downloadToFileChecked(url, destPath, expectedSHA256 string, maxSize int64) error {
	client := &http.Client{Timeout: downloadHTTPTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}
	if maxSize > 0 && resp.ContentLength > maxSize {
		return fmt.Errorf("asset is %d bytes, above the %d-byte cap", resp.ContentLength, maxSize)
	}

	dir := filepath.Dir(destPath)
	tmpFile, err := os.CreateTemp(dir, "geo-download-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanup := func() { _ = os.Remove(tmpPath) }

	body := io.Reader(resp.Body)
	if maxSize > 0 {
		// Read one byte past the cap so an oversized body is detected rather
		// than silently truncated.
		body = io.LimitReader(resp.Body, maxSize+1)
	}
	written, err := io.Copy(tmpFile, body)
	if err != nil {
		tmpFile.Close()
		cleanup()
		return fmt.Errorf("writing file: %w", err)
	}
	if maxSize > 0 && written > maxSize {
		tmpFile.Close()
		cleanup()
		return fmt.Errorf("asset exceeds the %d-byte cap", maxSize)
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

	if expectedSHA256 != "" {
		sum, _, err := hashFile(tmpPath)
		if err != nil {
			cleanup()
			return fmt.Errorf("hashing download: %w", err)
		}
		if !strings.EqualFold(sum, expectedSHA256) {
			cleanup()
			return fmt.Errorf("sha256 %s does not match the pinned %s", sum, expectedSHA256)
		}
	}

	if err := validateAsset(tmpPath, destPath); err != nil {
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
	// The asset is live; record where it came from. A sidecar failure is not a
	// download failure, but it must be visible: without it the bytes have no
	// provenance.
	if err := WriteProvenance(destPath, url); err != nil {
		log.Printf("⚠️  could not record provenance for %s: %v", filepath.Base(destPath), err)
	}
	return nil
}

// validateAsset rejects payloads the engines cannot load. Both checks are the
// engines' own: sing-box rule sets go through srs.Read with recover=false (the
// same call the engine makes), and xray .dat files are walked as a full
// GeoIPList/GeoSiteList. A header check is not enough — a truncated or
// unsupported-version file starts with "SRS" and would still be refused by the
// engine, and a captive-portal HTML page can begin with 0x0a.
func validateAsset(tmpPath, destPath string) error {
	switch {
	case strings.HasSuffix(destPath, ".srs"):
		if !ValidSRSFile(tmpPath) {
			return fmt.Errorf("downloaded rule set is not loadable by sing-box")
		}
	case strings.HasSuffix(destPath, ".dat"):
		if err := ValidateXrayDatFile(tmpPath); err != nil {
			return fmt.Errorf("downloaded geo database is not loadable by xray: %w", err)
		}
	}
	return nil
}
