package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/liberoute/bypath/internal/openvpn"
	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/securefile"
)

// isOVPNPath reports whether arg is an existing .ovpn profile file.
func isOVPNPath(arg string) bool {
	if strings.HasPrefix(arg, "-") {
		return false
	}
	info, err := os.Stat(arg)
	if err != nil || info.IsDir() {
		return false
	}
	return strings.EqualFold(filepath.Ext(arg), ".ovpn")
}

// cmdAddOVPN imports an .ovpn profile into the selected group. The profile is
// copied with 0600 permissions; credentials travel in a sibling .auth file and
// are never written to the group JSON or printed.
func cmdAddOVPN(args []string) {
	group := "default"
	name := ""
	authFile := ""
	var src string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-g", "--group":
			if i+1 < len(args) {
				group = args[i+1]
				i++
			}
		case "--name":
			if i+1 < len(args) {
				name = args[i+1]
				i++
			}
		case "--auth-file":
			if i+1 < len(args) {
				authFile = args[i+1]
				i++
			}
		default:
			if !strings.HasPrefix(args[i], "-") {
				src = args[i]
			}
		}
	}

	if src == "" {
		fmt.Println("Usage: bypath add <profile.ovpn> [-g group] [--name NAME] [--auth-file userpass.txt]")
		os.Exit(1)
	}

	// One read produces both the parsed profile and the packaged bytes, so the
	// profile validated here is exactly the one that gets stored.
	data, prof, err := openvpn.LoadPackage(src)
	if err != nil {
		fmt.Printf("❌ Invalid OpenVPN profile: %v\n", err)
		os.Exit(1)
	}

	user, pass := prof.Username, prof.Password
	if authFile != "" {
		user, pass, err = openvpn.CredentialsFromFile(authFile)
		if err != nil {
			fmt.Printf("❌ %v\n", err)
			os.Exit(1)
		}
	}

	if name == "" {
		name = strings.TrimSuffix(filepath.Base(src), filepath.Ext(src))
	}
	safe := sanitizeOVPNName(name)

	ovpnDir := filepath.Join(profileDir(), "ovpn")
	if err := securefile.MkdirAll(ovpnDir); err != nil {
		fmt.Printf("❌ Creating profile directory: %v\n", err)
		os.Exit(1)
	}

	dest := filepath.Join(ovpnDir, safe+".ovpn")
	dest, created, err := copyProfile(data, dest)
	if err != nil {
		fmt.Printf("❌ Storing OpenVPN profile: %v\n", err)
		os.Exit(1)
	}

	authDest := ""
	createdAuth := false
	if user != "" {
		authDest = dest + ".auth"
		// Exclusive create: an import never overwrites credential material that
		// belongs to another link or a crashed previous import.
		if err := securefile.WriteFileExclusive(authDest, []byte(user+"\n"+pass+"\n")); err != nil {
			if created {
				os.Remove(dest)
			}
			fmt.Printf("❌ Storing OpenVPN credentials: %v\n", err)
			os.Exit(1)
		}
		createdAuth = true
	}

	// Import is atomic: if the link cannot be recorded, only artifacts created
	// by this invocation are removed. Other links may not lose their files.
	rollback := func() {
		if created {
			os.Remove(dest)
		}
		if createdAuth {
			os.Remove(authDest)
		}
	}

	r := prof.Remotes[0]
	link := &profile.Link{
		Protocol:             "openvpn",
		Remark:               name,
		Address:              r.Host,
		Port:                 r.Port,
		Network:              r.Network,
		RawURI:               fmt.Sprintf("openvpn://%s:%d", r.Host, r.Port),
		OVPNPath:             dest,
		OVPNAuthUserPassFile: authDest,
	}

	mgr, err := profile.NewManager(profileDir(), "default")
	if err != nil {
		rollback()
		fmt.Printf("❌ Profile error: %v\n", err)
		os.Exit(1)
	}
	if err := mgr.AddLink(group, link); err != nil {
		rollback()
		fmt.Printf("❌ Add failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Imported OpenVPN profile: %s\n", name)
	fmt.Printf("   Server:  %s:%d (%s)\n", r.Host, r.Port, r.Network)
	fmt.Printf("   Engine:  sing-box %s (openvpn-client endpoint)\n", "1.14+")
	fmt.Printf("   Group:   %s\n", group)
	if authDest != "" {
		fmt.Println("   Auth:    username/password stored in a 0600 file")
	}
	if len(prof.Warnings) > 0 {
		fmt.Printf("   Notes:   %d host/runtime directive(s) ignored (bypath routes internally)\n", len(prof.Warnings))
	}
	fmt.Println("   Host routes, DNS and interfaces are left untouched.")
}

// copyProfile stores the profile bytes under dest with 0600. Every import gets
// its own file: sharing an artifact between links would let deleting one link
// remove secrets still referenced by another. The bool reports whether this
// call created the file (so a failed import only rolls back its own artifacts).
//
// Name selection and creation are one exclusive-create operation, so two
// concurrent imports can never both claim the same path or overwrite each
// other's bytes.
func copyProfile(data []byte, dest string) (string, bool, error) {
	ext := filepath.Ext(dest)
	stem := strings.TrimSuffix(dest, ext)
	for i := 1; i <= 100; i++ {
		candidate := dest
		if i > 1 {
			candidate = fmt.Sprintf("%s-%d%s", stem, i, ext)
		}
		err := securefile.WriteFileExclusive(candidate, data)
		if err == nil {
			return candidate, true, nil
		}
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return "", false, err
	}
	return "", false, fmt.Errorf("no free OpenVPN profile filename near %s", filepath.Base(dest))
}

// sanitizeOVPNName keeps profile filenames portable and unambiguous.
func sanitizeOVPNName(name string) string {
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

// cleanupOVPNArtifacts removes the copied profile and its credential file for a
// link that is being deleted.
func cleanupOVPNArtifacts(link *profile.Link) {
	if link == nil || link.Protocol != "openvpn" {
		return
	}
	// profileDir() is relative in local mode, so both sides must be absolute:
	// comparing that prefix with an absolute link path would silently skip
	// deletion and leave secrets on disk.
	base, err := filepath.Abs(filepath.Join(profileDir(), "ovpn"))
	if err != nil {
		return
	}
	// OpenRoot confines every removal to the artifact directory: a path whose
	// parent component is a symlink out of the directory is rejected instead of
	// deleting an unrelated host file.
	root, err := os.OpenRoot(base)
	if err != nil {
		return
	}
	defer root.Close()

	for _, p := range []string{link.OVPNPath, link.OVPNAuthUserPassFile} {
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
