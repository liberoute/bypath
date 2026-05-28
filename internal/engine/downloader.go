package engine

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// downloadFile downloads a file from url to destPath.
// If the file is an archive (.tar.gz, .zip), it extracts the binary.
func downloadFile(url, destPath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Determine if we need to extract
	if strings.HasSuffix(url, ".tar.gz") || strings.HasSuffix(url, ".tgz") {
		return extractTarGz(resp.Body, destPath)
	} else if strings.HasSuffix(url, ".zip") {
		return extractZip(resp.Body, destPath)
	}

	// Direct download
	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// extractTarGz extracts the main binary from a tar.gz archive.
func extractTarGz(reader io.Reader, destDir string) error {
	gzr, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	dir := filepath.Dir(destDir)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Only extract regular files that look like binaries
		if header.Typeflag != tar.TypeReg {
			continue
		}

		name := filepath.Base(header.Name)
		// Skip non-binary files
		if strings.HasSuffix(name, ".md") || strings.HasSuffix(name, ".txt") ||
			strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") {
			continue
		}

		// Extract to engines directory
		outPath := filepath.Join(dir, name)
		outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			return err
		}

		if _, err := io.Copy(outFile, tr); err != nil {
			outFile.Close()
			return err
		}
		outFile.Close()
	}

	return nil
}

// extractZip extracts the main binary from a zip archive.
func extractZip(reader io.Reader, destDir string) error {
	// We need to write to a temp file first since zip needs random access
	tmpFile, err := os.CreateTemp("", "liberoute-download-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := io.Copy(tmpFile, reader); err != nil {
		return err
	}

	// Open as zip
	zipReader, err := zip.OpenReader(tmpFile.Name())
	if err != nil {
		return err
	}
	defer zipReader.Close()

	dir := filepath.Dir(destDir)

	for _, f := range zipReader.File {
		if f.FileInfo().IsDir() {
			continue
		}

		name := filepath.Base(f.Name)
		// Skip non-binary files
		if strings.HasSuffix(name, ".md") || strings.HasSuffix(name, ".txt") ||
			strings.HasSuffix(name, ".json") || strings.HasPrefix(name, ".") ||
			strings.HasSuffix(name, ".dat") || strings.HasSuffix(name, ".sig") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		outPath := filepath.Join(dir, name)
		outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			rc.Close()
			return err
		}

		if _, err := io.Copy(outFile, rc); err != nil {
			outFile.Close()
			rc.Close()
			return err
		}

		outFile.Close()
		rc.Close()
	}

	return nil
}
