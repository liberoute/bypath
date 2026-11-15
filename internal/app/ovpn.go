package app

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/securefile"
)

// sanitizeName keeps imported artifact filenames portable and unambiguous.
func sanitizeName(name string) string {
	name = strings.TrimSpace(name)
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), " ._")
	if out == "" || out == "." || out == ".." {
		return "profile"
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// writeArtifact stores bytes under the OpenVPN artifact directory with 0600
// permissions, allocating a free suffix when the name is taken. Each import gets
// its own file so deleting one link can never remove another link's secrets.
func (s *Local) writeArtifact(name string, data []byte) (string, error) {
	dir := filepath.Join(s.Config().Profiles.Directory, "ovpn")
	if err := securefile.MkdirAll(dir); err != nil {
		return "", fmt.Errorf("creating OpenVPN profile directory: %w", err)
	}
	// Record an absolute path: a working-directory-relative artifact becomes
	// unresolvable as soon as the daemon runs from another directory.
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	stem := strings.TrimSuffix(name, filepath.Ext(name))
	ext := filepath.Ext(name)
	for i := 1; i <= 100; i++ {
		candidate := filepath.Join(dir, name)
		if i > 1 {
			candidate = filepath.Join(dir, fmt.Sprintf("%s-%d%s", stem, i, ext))
		}
		err := securefile.WriteFileExclusive(candidate, data)
		if err == nil {
			return candidate, nil
		}
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return "", err
	}
	return "", fmt.Errorf("no free filename near %s", name)
}

// ovpnPath resolves an artifact reference recorded in a link. Empty references
// resolve to an error so callers never touch the daemon's working directory.
func (s *Local) ovpnPath(recorded string) (string, error) {
	if strings.TrimSpace(recorded) == "" {
		return "", errors.New("no artifact reference")
	}
	return profile.ResolveArtifactPath(s.Config().Profiles.Directory, recorded)
}

// cleanupOVPNArtifacts removes the packaged .ovpn and its legacy .auth file for
// a link being deleted. Every removal is confined to the artifact directory, so
// a tampered path cannot delete an unrelated host file.
func (s *Local) cleanupOVPNArtifacts(link *profile.Link) {
	if link == nil || link.Protocol != "openvpn" {
		return
	}
	base, err := filepath.Abs(filepath.Join(s.Config().Profiles.Directory, "ovpn"))
	if err != nil {
		return
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		return
	}
	defer root.Close()

	for _, recorded := range []string{link.OVPNPath, link.OVPNAuthUserPassFile} {
		p, err := s.ovpnPath(recorded)
		if err != nil {
			continue
		}
		rel, ok := confinedArtifactPath(base, p)
		if !ok {
			continue
		}
		if info, err := root.Lstat(rel); err != nil || info.IsDir() {
			continue
		}
		_ = root.Remove(rel)
	}
}

// confinedArtifactPath reports whether p is a child of base and returns the
// relative path used for a confined removal.
func confinedArtifactPath(base, p string) (string, bool) {
	if p == "" {
		return "", false
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(base, abs)
	if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) ||
		strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return rel, true
}
