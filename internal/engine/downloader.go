package engine

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// maxArtifactSize bounds engine archives so a malicious or broken response
// cannot fill the disk before the checksum is checked.
const maxArtifactSize = 512 << 20

var artifactClient = &http.Client{
	Timeout: 10 * time.Minute,
	Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
	},
}

// artifactAttempts bounds transport-level retries. Release downloads redirect
// to a CDN and a single TLS handshake failure should not make an install look
// like a missing artifact. HTTP status errors are returned immediately.
var artifactAttempts = 3

func getArtifact(url string) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt < artifactAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		resp, err := artifactClient.Get(url)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("after %d attempts: %w", artifactAttempts, lastErr)
}

// downloadVerified downloads url to dest and fails closed unless the content
// matches the pinned SHA-256 exactly. The file is removed on any mismatch.
func downloadVerified(url, dest, wantSHA256 string) error {
	want := strings.ToLower(strings.TrimSpace(wantSHA256))
	if len(want) != sha256.Size*2 {
		return fmt.Errorf("invalid pinned checksum for %s", filepath.Base(url))
	}

	resp, err := getArtifact(url)
	if err != nil {
		return fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(out, hash), io.LimitReader(resp.Body, maxArtifactSize+1))
	closeErr := out.Close()
	if copyErr != nil {
		os.Remove(dest)
		return copyErr
	}
	if closeErr != nil {
		os.Remove(dest)
		return closeErr
	}
	if n > maxArtifactSize {
		os.Remove(dest)
		return fmt.Errorf("%s is larger than the %d byte limit", filepath.Base(url), maxArtifactSize)
	}

	got := hex.EncodeToString(hash.Sum(nil))
	if got != want {
		os.Remove(dest)
		return fmt.Errorf("checksum mismatch for %s: got sha256:%s, want sha256:%s", filepath.Base(url), got, want)
	}
	return nil
}

// installArtifact extracts exactly one expected binary from a verified archive
// (or copies a verified raw binary) into destDir. Any other archive entry is
// ignored, so a release cannot install extra executables.
func installArtifact(src, artifactName, destDir, binaryName string) error {
	return installArtifactAs(src, artifactName, destDir, binaryName, binaryName)
}

// installArtifactAs is installArtifact for releases whose archive member name
// differs from the installed executable name (tun2socks zips carry a platform
// suffix).
func installArtifactAs(src, artifactName, destDir, binaryName, archiveName string) error {
	switch {
	case strings.HasSuffix(artifactName, ".tar.gz"), strings.HasSuffix(artifactName, ".tgz"):
		return extractTarGzFile(src, destDir, binaryName, archiveName)
	case strings.HasSuffix(artifactName, ".zip"):
		return extractZipFile(src, destDir, binaryName, archiveName)
	default:
		return copyArtifact(src, destDir, binaryName)
	}
}

func copyArtifact(src, destDir, binaryName string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return writeAtomic(destDir, binaryName, in, 0755)
}

func extractTarGzFile(src, destDir, binaryName, archiveName string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("opening archive: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	found := false
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading archive: %w", err)
		}
		if header.Typeflag != tar.TypeReg || filepath.Base(header.Name) != archiveName {
			continue
		}
		if found {
			return fmt.Errorf("archive contains more than one %q entry", archiveName)
		}
		if err := writeAtomic(destDir, binaryName, tr, 0755); err != nil {
			return err
		}
		found = true
	}
	if !found {
		return fmt.Errorf("archive does not contain %q", archiveName)
	}
	return nil
}

func extractZipFile(src, destDir, binaryName, archiveName string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("opening archive: %w", err)
	}
	defer zr.Close()

	found := false
	for _, entry := range zr.File {
		if entry.FileInfo().IsDir() || filepath.Base(entry.Name) != archiveName {
			continue
		}
		if found {
			return fmt.Errorf("archive contains more than one %q entry", archiveName)
		}
		if entry.UncompressedSize64 > maxArtifactSize {
			return fmt.Errorf("archive entry %q is larger than the %d byte limit", archiveName, maxArtifactSize)
		}
		rc, err := entry.Open()
		if err != nil {
			return err
		}
		writeErr := writeAtomic(destDir, binaryName, rc, 0755)
		rc.Close()
		if writeErr != nil {
			return writeErr
		}
		found = true
	}
	if !found {
		return fmt.Errorf("archive does not contain %q", archiveName)
	}
	return nil
}

// writeAtomic copies r into dir/name through a uniquely named temporary file so
// a failed extraction never replaces a working engine.
func writeAtomic(dir, name string, r io.Reader, mode os.FileMode) error {
	tmp, err := os.CreateTemp(dir, ".bypath-extract-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	n, err := io.Copy(tmp, io.LimitReader(r, maxArtifactSize+1))
	if err != nil {
		tmp.Close()
		return err
	}
	if n > maxArtifactSize {
		tmp.Close()
		return fmt.Errorf("extracted %q is larger than the %d byte limit", name, maxArtifactSize)
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filepath.Join(dir, name))
}
