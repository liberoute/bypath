package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResolveArtifactPath maps an artifact reference recorded in a profile onto the
// installation's profile directory.
//
// Links imported while bypath ran from a working directory store references
// such as "data/profiles/ovpn/office.ovpn". Once the group is used by an
// installed daemon those references no longer resolve from the daemon's
// working directory, which is what produced "reading OpenVPN profile: no such
// file or directory" for every profile in a migrated group.
//
// Resolution order: the absolute path as recorded, profileDir/<recorded>, then
// progressively shorter suffixes of <recorded>, then profileDir/ovpn/<base>.
// Relative candidates stay inside profileDir and must be regular files, so a
// tampered profile cannot point the root daemon at an unrelated file.
func ResolveArtifactPath(profileDir, recorded string) (string, error) {
	ref := strings.TrimSpace(recorded)
	if ref == "" {
		return "", errors.New("profile has no artifact reference")
	}
	ref = filepath.FromSlash(ref)
	if filepath.IsAbs(ref) && isRegularFile(ref) {
		return ref, nil
	}
	search := ref
	if vol := filepath.VolumeName(search); vol != "" {
		search = strings.TrimPrefix(search, vol)
	}

	root, err := filepath.Abs(profileDir)
	if err != nil {
		return "", fmt.Errorf("resolving profile directory: %w", err)
	}
	root = filepath.Clean(root)

	// An absolute reference that no longer exists is also searched by suffix:
	// moving an installation must not strand profiles recorded under the old
	// root. Suffix candidates still have to exist under the current root.
	parts := strings.Split(strings.TrimLeft(filepath.Clean(search), `/\`), string(filepath.Separator))
	var tried []string
	try := func(rel string) (string, bool) {
		candidate, ok := confineTo(root, rel)
		if !ok {
			return "", false
		}
		tried = append(tried, candidate)
		return candidate, isRegularFile(candidate)
	}

	for i := 0; i < len(parts); i++ {
		rel := filepath.Join(parts[i:]...)
		if candidate, ok := try(rel); ok {
			return candidate, nil
		}
	}
	// The managed artifact directory is the last resort: an import that only
	// kept the display name still resolves to its packaged file.
	base := filepath.Base(search)
	if base != "." && base != string(filepath.Separator) {
		if candidate, ok := try(filepath.Join("ovpn", base)); ok {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("artifact %q not found under %s (tried %s)", recorded, root, strings.Join(tried, ", "))
}

// confineTo joins rel under root and rejects anything that escapes it.
func confineTo(root, rel string) (string, bool) {
	if rel == "" || filepath.IsAbs(rel) {
		return "", false
	}
	candidate := filepath.Clean(filepath.Join(root, rel))
	if candidate != root && !strings.HasPrefix(candidate, root+string(filepath.Separator)) {
		return "", false
	}
	return candidate, true
}

func isRegularFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}
