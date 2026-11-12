package layer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const manifestName = "MANIFEST.sha256"

// BackupProfiles copies every file under the profiles directory except the
// .layer sidecar into backupDir, then verifies the copy by re-hashing. It
// returns the backup directory and the manifest hash.
func BackupProfiles(profilesDir string) (string, string, error) {
	layerDir := filepath.Join(profilesDir, DirName)
	if err := checkFreeSpace(profilesDir, dirSize(profilesDir)); err != nil {
		return "", "", err
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	backupDir := filepath.Join(layerDir, BackupDir, "pre-v2-"+stamp)
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return "", "", err
	}
	var rels []string
	err := filepath.Walk(profilesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if filepath.Clean(path) == filepath.Clean(layerDir) {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(profilesDir, path)
		if err != nil {
			return err
		}
		rels = append(rels, rel)
		return nil
	})
	if err != nil {
		return "", "", fmt.Errorf("scanning profiles for backup: %w", err)
	}
	sort.Strings(rels)

	var lines []string
	for _, rel := range rels {
		src := filepath.Join(profilesDir, rel)
		dst := filepath.Join(backupDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			return "", "", err
		}
		if err := copyFile(src, dst); err != nil {
			return "", "", fmt.Errorf("backing up %s: %w", rel, err)
		}
		hash, size, err := fileHash(dst)
		if err != nil {
			return "", "", err
		}
		if srcHash, srcSize, err := fileHash(src); err != nil || srcHash != hash || srcSize != size {
			return "", "", fmt.Errorf("backup verification failed for %s", rel)
		}
		lines = append(lines, fmt.Sprintf("%s  %d  %s", hash, size, filepath.ToSlash(rel)))
	}
	manifest := strings.Join(lines, "\n") + "\n"
	manifestPath := filepath.Join(backupDir, manifestName)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0600); err != nil {
		return "", "", err
	}
	if err := syncDir(backupDir); err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(manifest))
	return backupDir, hex.EncodeToString(sum[:]), nil
}

// manifestEntry is one line of a backup manifest.
type manifestEntry struct {
	Hash string
	Size int64
	Rel  string
}

func readManifest(backupDir string) ([]manifestEntry, error) {
	data, err := os.ReadFile(filepath.Join(backupDir, manifestName))
	if err != nil {
		return nil, err
	}
	var out []manifestEntry
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "  ", 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("malformed manifest line %q", line)
		}
		var size int64
		if _, err := fmt.Sscanf(parts[1], "%d", &size); err != nil {
			return nil, err
		}
		out = append(out, manifestEntry{Hash: parts[0], Size: size, Rel: parts[2]})
	}
	return out, nil
}

// compareBackup reports manifest files whose content differs or is missing in
// the live profiles directory. Extra live files are not "changed": they were
// created after migration and a rollback leaves them alone.
func compareBackup(backupDir string) (changed, missing []string, err error) {
	entries, err := readManifest(backupDir)
	if err != nil {
		return nil, nil, err
	}
	// Manifest relative paths are rooted at the profiles directory, which is
	// two levels above backupDir (profiles/.layer/backup/<name>).
	profilesDir := filepath.Dir(filepath.Dir(filepath.Dir(backupDir)))
	for _, e := range entries {
		if _, ierr := os.Stat(filepath.Join(backupDir, e.Rel)); ierr != nil {
			missing = append(missing, e.Rel)
			continue
		}
		rel := filepath.FromSlash(e.Rel)
		live := filepath.Join(profilesDir, rel)
		hash, size, herr := fileHash(live)
		if herr != nil || hash != e.Hash || size != e.Size {
			changed = append(changed, e.Rel)
		}
	}
	sort.Strings(changed)
	sort.Strings(missing)
	return changed, missing, nil
}

func restoreChanged(backupDir string, changed []string) error {
	profilesDir := filepath.Dir(filepath.Dir(filepath.Dir(backupDir)))
	for _, relSlash := range changed {
		rel := filepath.FromSlash(relSlash)
		src := filepath.Join(backupDir, rel)
		dst := filepath.Join(profilesDir, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
		if err := copyFile(src, dst); err != nil {
			return err
		}
	}
	return nil
}

func fileHash(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func writeSnapshot(layerDir, prefix string, v interface{}) error {
	dir := filepath.Join(layerDir, BackupDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, fmt.Sprintf("%s-%s.json", prefix, timestampSlug()))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func timestampSlug() string { return time.Now().UTC().Format("20060102T150405Z") }

func dirSize(dir string) int64 {
	var total int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total * 2
}

func osRename(oldPath, newPath string) error { return os.Rename(oldPath, newPath) }

// ReadActivePair reads the legacy selection file. It never writes it.
func ReadActivePair(profilesDir string) (bucket, remark string, ok bool) {
	data, err := os.ReadFile(filepath.Join(profilesDir, ".active"))
	if err != nil {
		return "", "", false
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return "", "", false
	}
	bucket, remark = strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1])
	if bucket == "" || remark == "" {
		return "", "", false
	}
	return bucket, remark, true
}

// activeResolves reports whether .active names a connection that still exists
// in a bucket file.
func activeResolves(profilesDir string) bool {
	bucket, remark, ok := ReadActivePair(profilesDir)
	if !ok {
		return true // no selection is a valid state
	}
	data, err := os.ReadFile(filepath.Join(profilesDir, bucket+".json"))
	if err != nil {
		return false
	}
	var g struct {
		Links []struct {
			Remark string `json:"remark"`
		} `json:"links"`
	}
	if json.Unmarshal(data, &g) != nil {
		return false
	}
	for _, l := range g.Links {
		if strings.TrimSpace(l.Remark) == remark {
			return true
		}
	}
	return false
}
