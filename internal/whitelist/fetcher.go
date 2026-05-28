package whitelist

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

// Fetcher downloads country IP lists from public sources.
type Fetcher struct {
	dataDir string
	client  *http.Client
}

// NewFetcher creates a new IP list fetcher.
func NewFetcher(dataDir string) *Fetcher {
	return &Fetcher{
		dataDir: dataDir,
		client:  &http.Client{Timeout: 60 * time.Second},
	}
}

// FetchCountry downloads IPv4 and IPv6 CIDR lists for a country.
func (f *Fetcher) FetchCountry(countryCode string) error {
	countryCode = strings.ToLower(strings.TrimSpace(countryCode))
	if countryCode == "" {
		return fmt.Errorf("empty country code")
	}

	if err := os.MkdirAll(f.dataDir, 0755); err != nil {
		return fmt.Errorf("creating data dir: %w", err)
	}

	dateStr := time.Now().Format("2006-01-02")

	// IPv4
	ipv4URL := fmt.Sprintf("https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/%s.cidr", countryCode)
	ipv4File := filepath.Join(f.dataDir, fmt.Sprintf("ipv4_%s_%s.txt", countryCode, dateStr))

	log.Printf("  📥 Fetching IPv4 for %s...", countryCode)
	if err := f.downloadFile(ipv4URL, ipv4File); err != nil {
		// Try alternative source
		ipv4URL = fmt.Sprintf("https://stat.ripe.net/data/country-resource-list/data.json?resource=%s&v4_format=prefix", countryCode)
		log.Printf("  ⚠️  Primary source failed, trying alternative...")
		if err2 := f.downloadFile(ipv4URL, ipv4File); err2 != nil {
			return fmt.Errorf("fetching IPv4 for %s: %w (alt: %v)", countryCode, err, err2)
		}
	}

	// IPv6
	ipv6URL := fmt.Sprintf("https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv6/%s.cidr", countryCode)
	ipv6File := filepath.Join(f.dataDir, fmt.Sprintf("ipv6_%s_%s.txt", countryCode, dateStr))

	log.Printf("  📥 Fetching IPv6 for %s...", countryCode)
	if err := f.downloadFile(ipv6URL, ipv6File); err != nil {
		log.Printf("  ⚠️  IPv6 fetch failed for %s (non-critical): %v", countryCode, err)
	}

	return nil
}

// FetchAll downloads IP lists for all configured countries.
func (f *Fetcher) FetchAll(countries []string) error {
	var lastErr error
	for _, cc := range countries {
		if err := f.FetchCountry(cc); err != nil {
			log.Printf("  ⚠️  Failed to fetch %s: %v", cc, err)
			lastErr = err
		}
	}
	return lastErr
}

// CleanOld removes IP list files older than the given duration.
func (f *Fetcher) CleanOld(maxAge time.Duration) error {
	entries, err := os.ReadDir(f.dataDir)
	if err != nil {
		return err
	}

	cutoff := time.Now().Add(-maxAge)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(f.dataDir, entry.Name()))
		}
	}

	return nil
}

func (f *Fetcher) downloadFile(url, destPath string) error {
	resp, err := f.client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	written, err := io.Copy(out, resp.Body)
	if err != nil {
		os.Remove(destPath)
		return err
	}

	log.Printf("  ✅ Downloaded %s (%d bytes)", filepath.Base(destPath), written)
	return nil
}
