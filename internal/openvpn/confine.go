package openvpn

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// maxProfileSize bounds the .ovpn text itself; the parser uses the same cap.
	maxProfileSize = 1 << 20
	// maxSecretSize bounds any referenced PEM or credential file.
	maxSecretSize = 4 << 20
	// maxCredentialsSize bounds a standalone username/password file.
	maxCredentialsSize = 64 << 10
)

// ConfinedResolver resolves file references relative to a profile directory and
// refuses anything that could read outside it: absolute paths, drive-letter and
// UNC paths, parent traversal, symlink escapes, non-regular files and oversized
// files. It is the only way profile-supplied paths are ever opened.
//
// The resolver holds an os.Root: every lookup is resolved by the kernel relative
// to a directory handle, and validation plus reading happen on the same opened
// file descriptor. Replacing a path with a symlink between validation and use
// therefore cannot redirect the read outside the profile directory.
type ConfinedResolver struct {
	dir     string
	root    *os.Root
	maxSize int64
}

func newConfinedResolver(dir string, maxSize int64) (*ConfinedResolver, error) {
	if dir == "" {
		return nil, fmt.Errorf("profile directory is empty")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolving profile directory: %w", err)
	}
	// Link targets are compared against the real directory because the root
	// handle resolves the directory to its physical location; a profile reached
	// through a symlinked parent would otherwise look like an escape.
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("resolving profile directory: %w", err)
	}
	root, err := os.OpenRoot(real)
	if err != nil {
		return nil, fmt.Errorf("opening profile directory: %w", err)
	}
	return &ConfinedResolver{dir: real, root: root, maxSize: maxSize}, nil
}

// Close releases the directory handle backing the confinement.
func (r *ConfinedResolver) Close() error {
	if r == nil || r.root == nil {
		return nil
	}
	err := r.root.Close()
	r.root = nil
	return err
}

// Resolve reads one referenced file and returns its contents.
func (r *ConfinedResolver) Resolve(ref string) (string, error) {
	if err := validateRelativeRef(ref); err != nil {
		return "", err
	}
	if r == nil || r.root == nil {
		return "", fmt.Errorf("referenced file %q: resolver is closed", ref)
	}
	// os.Root resolves every component inside the opened directory handle and
	// rejects symlinks that leave it, so there is no path-only validation step
	// that a concurrent rename could invalidate.
	f, err := r.openWithin(filepath.FromSlash(ref))
	if err != nil {
		return "", fmt.Errorf("referenced file %q: %w", ref, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("referenced file %q: %w", ref, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("referenced file %q is not a regular file", ref)
	}
	if info.Size() > r.maxSize {
		return "", fmt.Errorf("referenced file %q is larger than the %d byte limit", ref, r.maxSize)
	}
	b, err := readLimited(f, r.maxSize)
	if err != nil {
		return "", fmt.Errorf("referenced file %q: %w", ref, err)
	}
	return string(b), nil
}

// openWithin opens ref through the root handle. The kernel refuses an absolute
// symlink target even when it happens to resolve inside the profile directory,
// because it cannot prove containment for an absolute path. Such a link is
// rewritten to the equivalent relative path and retried; every attempt still
// goes through Root.Open, so swapping the link between Readlink and Open cannot
// make the read leave the directory.
func (r *ConfinedResolver) openWithin(rel string) (*os.File, error) {
	seen := make(map[string]bool, 4)
	for range 8 {
		f, err := r.root.Open(rel)
		if err == nil {
			return f, nil
		}
		next, ok := r.relativeLinkTarget(rel)
		if !ok || seen[next] {
			return nil, err
		}
		seen[rel] = true
		rel = next
	}
	return nil, fmt.Errorf("too many symlink levels")
}

// relativeLinkTarget reports the in-root relative path denoted by an absolute
// symlink at rel. Relative links are not handled here: Root.Open already follows
// them while keeping the resolution inside the root.
func (r *ConfinedResolver) relativeLinkTarget(rel string) (string, bool) {
	info, err := os.Lstat(filepath.Join(r.dir, rel))
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return "", false
	}
	target, err := os.Readlink(filepath.Join(r.dir, rel))
	if err != nil || !filepath.IsAbs(target) {
		return "", false
	}
	relTarget, err := filepath.Rel(r.dir, filepath.Clean(target))
	if err != nil || relTarget == "." || relTarget == ".." ||
		strings.HasPrefix(relTarget, ".."+string(filepath.Separator)) {
		return "", false
	}
	if err := validateRelativeRef(filepath.ToSlash(relTarget)); err != nil {
		return "", false
	}
	return relTarget, true
}

// validateRelativeRef rejects every form that could denote a location outside
// the profile directory before any filesystem access happens.
func validateRelativeRef(ref string) error {
	if strings.TrimSpace(ref) == "" {
		return fmt.Errorf("empty file reference")
	}
	if strings.ContainsRune(ref, 0) {
		return fmt.Errorf("file reference contains a NUL byte")
	}
	if filepath.IsAbs(ref) || strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, `\`) ||
		filepath.VolumeName(ref) != "" || isDriveLetterPath(ref) {
		return fmt.Errorf("absolute file reference %q is not allowed; place the file next to the profile", ref)
	}
	cleaned := filepath.Clean(filepath.FromSlash(ref))
	if cleaned == "." || cleaned == ".." ||
		strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) ||
		strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, `..\`) {
		return fmt.Errorf("file reference %q escapes the profile directory", ref)
	}
	for _, part := range strings.FieldsFunc(ref, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return fmt.Errorf("file reference %q escapes the profile directory", ref)
		}
	}
	return nil
}

// isDriveLetterPath catches Windows paths such as C:foo on non-Windows hosts,
// where filepath.VolumeName does not report them.
func isDriveLetterPath(ref string) bool {
	if len(ref) < 2 || ref[1] != ':' {
		return false
	}
	c := ref[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

var externalPEMDirectives = map[string]bool{
	"ca":        true,
	"cert":      true,
	"key":       true,
	"tls-auth":  true,
	"tls-crypt": true,
}

// PackageFile returns bytes for a self-contained .ovpn: every external PEM
// reference is inlined and `auth-user-pass <file>` becomes a bare directive, so
// the stored profile keeps working after the original folder is deleted.
// Credentials are still resolved by ParseFile and are stored separately by the
// caller. The exact bytes that are packaged are the bytes that were validated.
func PackageFile(path string) ([]byte, error) {
	pkg, _, err := LoadPackage(path)
	return pkg, err
}

// LoadPackage reads the profile exactly once and returns both the resolved
// profile and its self-contained packaged form. Parsing and packaging therefore
// share one snapshot: a file swapped between the two steps can no longer be
// validated as one profile and stored as another.
func LoadPackage(path string) ([]byte, *Profile, error) {
	data, err := readProfileFile(path)
	if err != nil {
		return nil, nil, err
	}
	profile, err := parseProfileFile(path, data)
	if err != nil {
		return nil, nil, err
	}
	resolver, err := newConfinedResolver(filepath.Dir(path), maxSecretSize)
	if err != nil {
		return nil, nil, err
	}
	defer resolver.Close()
	packaged, err := inlineExternalRefs(string(data), resolver)
	if err != nil {
		return nil, nil, err
	}
	return packaged, profile, nil
}

// readProfileFile reads the profile through one opened descriptor. The regular
// file and size checks apply to the same object that is read, so a path cannot
// be swapped for a different file between stat and read.
func readProfileFile(path string) ([]byte, error) {
	f, err := openProfileFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading OpenVPN profile: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("reading OpenVPN profile: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("OpenVPN profile is not a regular file")
	}
	if info.Size() > maxProfileSize {
		return nil, fmt.Errorf("OpenVPN profile is larger than the %d byte limit", maxProfileSize)
	}
	data, err := readLimited(f, maxProfileSize)
	if err != nil {
		return nil, fmt.Errorf("reading OpenVPN profile: %w", err)
	}
	return data, nil
}

// readLimited reads at most limit bytes and reports an error if the input is
// longer. The caller's stat may race with a growing file, so the read itself is
// bounded rather than trusting the earlier size.
func readLimited(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("file is larger than the %d byte limit", limit)
	}
	return b, nil
}

func inlineExternalRefs(content string, resolver *ConfinedResolver) ([]byte, error) {
	var out strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 64*1024), maxProfileSize)

	inBlock := ""
	skipBlock := ""
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)

		if inBlock != "" {
			// An inline <auth-user-pass> body is a credential pair. It must never
			// reach the packaged profile; the caller stores it in the per-link
			// .auth file instead.
			if skipBlock == "" {
				out.WriteString(raw)
				out.WriteByte('\n')
			}
			// Close only on the exact matching tag. The parser uses the same
			// rule, so a nested-looking or unrelated closing tag cannot end the
			// block early and leak credential lines into the packaged profile.
			if strings.EqualFold(line, "</"+inBlock+">") {
				inBlock, skipBlock = "", ""
			}
			continue
		}
		if strings.HasPrefix(line, "<") && strings.HasSuffix(line, ">") && !strings.HasPrefix(line, "</") {
			tag := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			inBlock = tag
			if tag == "auth-user-pass" {
				skipBlock = tag
				out.WriteString("auth-user-pass\n")
				continue
			}
			out.WriteString(raw)
			out.WriteByte('\n')
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			out.WriteString(raw)
			out.WriteByte('\n')
			continue
		}

		fields := strings.Fields(line)
		name := strings.ToLower(fields[0])
		if name == "auth-user-pass" && len(fields) > 1 {
			// Credentials move to the per-link .auth file, never into the
			// packaged profile.
			out.WriteString("auth-user-pass\n")
			continue
		}
		if externalPEMDirectives[name] {
			if len(fields) < 2 {
				return nil, fmt.Errorf("%s directive is missing a file path", name)
			}
			body, err := resolver.Resolve(fields[1])
			if err != nil {
				return nil, err
			}
			if err := validatePEM(body); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			out.WriteString("<" + name + ">\n")
			out.WriteString(strings.TrimSpace(body))
			out.WriteString("\n</" + name + ">\n")
			if (name == "tls-auth" || name == "tls-crypt") && len(fields) > 2 {
				out.WriteString("key-direction " + strings.ToLower(fields[2]) + "\n")
			}
			continue
		}
		out.WriteString(raw)
		out.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading OpenVPN profile: %w", err)
	}
	return []byte(out.String()), nil
}
