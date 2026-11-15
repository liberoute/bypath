// Package geo handles downloading and updating geoip/geosite rule set files.
package geo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Provenance records where an installed asset came from and what it contained.
// The default sources are pinned to immutable upstream commits, but an operator
// override is not, so the sidecar is the only way to tell later which bytes the
// engine actually loaded.
type Provenance struct {
	SourceURL string    `json:"source_url"`
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	FetchedAt time.Time `json:"fetched_at"`
}

// ProvenancePath is the sidecar location for an installed asset. The suffix is
// not .srs/.dat, so asset discovery and `geo status` file listing ignore it.
func ProvenancePath(assetPath string) string {
	return assetPath + ".provenance.json"
}

// WriteProvenance hashes the installed asset and writes its sidecar. It is
// called after the asset has been renamed into place, so the sidecar always
// describes the bytes that are live (or it does not exist).
func WriteProvenance(assetPath, sourceURL string) error {
	sum, size, err := hashFile(assetPath)
	if err != nil {
		return err
	}
	record := Provenance{
		SourceURL: sourceURL,
		SHA256:    sum,
		Size:      size,
		FetchedAt: time.Now().UTC(),
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(assetPath), "geo-provenance-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, ProvenancePath(assetPath)); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// ReadProvenance returns the sidecar for an installed asset, or an error when
// no sidecar was recorded (for example an asset copied in by hand).
func ReadProvenance(assetPath string) (Provenance, error) {
	var record Provenance
	data, err := os.ReadFile(ProvenancePath(assetPath))
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return record, fmt.Errorf("parsing provenance for %s: %w", assetPath, err)
	}
	return record, nil
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}
