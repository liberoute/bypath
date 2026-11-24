package openvpn

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTestProfile(t *testing.T, dir, content string) string {
	t.Helper()
	return writeTestFile(t, dir, "profile.ovpn", "client\nremote vpn.example.net 1194\n"+content+"\n")
}

func TestParseFileRejectsAbsoluteReferences(t *testing.T) {
	dir := t.TempDir()
	for _, ref := range []string{
		"/etc/passwd",
		`\etc\passwd`,
		`C:\Windows\win.ini`,
		"C:/Windows/win.ini",
		`C:Windows\win.ini`,
		`\\server\share\key.pem`,
	} {
		profilePath := writeTestProfile(t, dir, "ca "+ref)
		if _, err := ParseFile(profilePath); err == nil {
			t.Errorf("absolute reference %q was accepted", ref)
		} else if !strings.Contains(err.Error(), "absolute") {
			t.Errorf("reference %q: error %v does not mention absolute path rejection", ref, err)
		}
	}
}

func TestParseFileRejectsTraversalReferences(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "profile")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, parent, "outside.pem", syntheticPEM("CERTIFICATE", "outside"))

	for _, ref := range []string{
		"../outside.pem",
		`..\outside.pem`,
		"sub/../../outside.pem",
		"./../outside.pem",
	} {
		profilePath := writeTestProfile(t, dir, "ca "+ref)
		if _, err := ParseFile(profilePath); err == nil {
			t.Errorf("traversal reference %q was accepted", ref)
		} else if !strings.Contains(err.Error(), "escapes") && !strings.Contains(err.Error(), "absolute") {
			t.Errorf("reference %q: unexpected error %v", ref, err)
		}
	}
}

func TestParseFileRejectsAuthUserPassTraversal(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "profile")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, parent, "creds.txt", "user\npass\n")

	profilePath := writeTestProfile(t, dir, "auth-user-pass ../creds.txt")
	if _, err := ParseFile(profilePath); err == nil {
		t.Fatal("auth-user-pass traversal was accepted")
	}
}

func TestParseFileRejectsSymlinkEscape(t *testing.T) {
	outsideDir := t.TempDir()
	outside := writeTestFile(t, outsideDir, "ca.pem", syntheticPEM("CERTIFICATE", "outside"))
	dir := t.TempDir()
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}

	profilePath := writeTestProfile(t, dir, "ca link.pem")
	if _, err := ParseFile(profilePath); err == nil {
		t.Fatal("symlink escaping the profile directory was accepted")
	} else if !strings.Contains(strings.ToLower(err.Error()), "escape") {
		t.Fatalf("unexpected error for symlink escape: %v", err)
	}
}

// TestResolveRejectsSymlinkSwappedAfterResolverOpen reproduces the TOCTOU shape:
// the resolver is trusted once, then the referenced name is atomically replaced
// with a link to an outside file. Because each Resolve opens through the root
// handle, the second call must still refuse the escape.
func TestResolveRejectsSymlinkSwappedAfterResolverOpen(t *testing.T) {
	outsideDir := t.TempDir()
	outside := writeTestFile(t, outsideDir, "secret.pem", syntheticPEM("CERTIFICATE", "outside"))
	dir := t.TempDir()
	ref := writeTestFile(t, dir, "ca.pem", syntheticPEM("CERTIFICATE", "inside"))

	resolver, err := newConfinedResolver(dir, maxSecretSize)
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	if _, err := resolver.Resolve("ca.pem"); err != nil {
		t.Fatalf("initial resolve: %v", err)
	}

	if err := os.Remove(ref); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, ref); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}
	if _, err := resolver.Resolve("ca.pem"); err == nil {
		t.Fatal("resolver followed a symlink swapped in after it was opened")
	}
}

func TestResolveRejectsSymlinkedParentDirectory(t *testing.T) {
	outsideDir := t.TempDir()
	writeTestFile(t, outsideDir, "secret.pem", syntheticPEM("CERTIFICATE", "outside"))
	dir := t.TempDir()
	if err := os.Symlink(outsideDir, filepath.Join(dir, "sub")); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}

	resolver, err := newConfinedResolver(dir, maxSecretSize)
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	if _, err := resolver.Resolve("sub/secret.pem"); err == nil {
		t.Fatal("resolver followed a parent-directory symlink out of the profile directory")
	}
}

func TestReadLimitedEnforcesLimit(t *testing.T) {
	if _, err := readLimited(strings.NewReader("abcdef"), 5); err == nil {
		t.Fatal("readLimited accepted input larger than the limit")
	}
	got, err := readLimited(strings.NewReader("abcde"), 5)
	if err != nil || string(got) != "abcde" {
		t.Fatalf("readLimited at the limit = %q, %v", got, err)
	}
}

func TestParseFileAllowsSymlinkInsideProfileDir(t *testing.T) {
	dir := t.TempDir()
	target := writeTestFile(t, dir, "real-ca.pem", syntheticPEM("CERTIFICATE", "inside"))
	link := filepath.Join(dir, "ca.pem")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable on this host: %v", err)
	}

	profilePath := writeTestProfile(t, dir, "ca ca.pem")
	p, err := ParseFile(profilePath)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(p.CACerts) != 1 || !strings.Contains(p.CACerts[0], pemBody("inside")) {
		t.Fatal("in-directory symlink was not resolved")
	}
}

func TestParseFileRejectsNonRegularReferences(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "ca-dir"), 0700); err != nil {
		t.Fatal(err)
	}
	profilePath := writeTestProfile(t, dir, "ca ca-dir")
	if _, err := ParseFile(profilePath); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory reference err = %v, want regular-file rejection", err)
	}
}

func TestParseFileRejectsOversizedReferences(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.pem")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxSecretSize + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	profilePath := writeTestProfile(t, dir, "ca big.pem")
	if _, err := ParseFile(profilePath); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized reference err = %v, want size-limit rejection", err)
	}
}

func TestPackageFileIsSelfContained(t *testing.T) {
	srcDir := t.TempDir()
	writeTestFile(t, srcDir, "ca.crt", syntheticPEM("CERTIFICATE", "ca-packaged"))
	writeTestFile(t, srcDir, "client.crt", syntheticPEM("CERTIFICATE", "cert-packaged"))
	writeTestFile(t, srcDir, "client.key", syntheticPEM("PRIVATE KEY", "key-packaged"))
	writeTestFile(t, srcDir, "ta.key", syntheticPEM("OpenVPN Static key V1", "ta-packaged"))
	writeTestFile(t, srcDir, "creds.txt", "pkg-user\npkg-pass\n")

	srcProfile := filepath.Join(srcDir, "sample.ovpn")
	ovpn := strings.Join([]string{
		"client",
		"dev tun",
		"remote vpn.example.net 443 tcp",
		"ca ca.crt",
		"cert client.crt",
		"key client.key",
		"tls-auth ta.key 1",
		"auth-user-pass creds.txt",
		"remote-cert-tls server",
	}, "\n")
	if err := os.WriteFile(srcProfile, []byte(ovpn), 0600); err != nil {
		t.Fatal(err)
	}

	packaged, err := PackageFile(srcProfile)
	if err != nil {
		t.Fatalf("PackageFile: %v", err)
	}
	text := string(packaged)
	for _, want := range []string{"<ca>", "<cert>", "<key>", "<tls-auth>", "key-direction 1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("packaged profile missing %q:\n%s", want, text)
		}
	}
	for _, forbidden := range []string{"ca ca.crt", "cert client.crt", "key client.key", "tls-auth ta.key", "creds.txt", "pkg-user", "pkg-pass"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("packaged profile still references %q", forbidden)
		}
	}

	// Simulate losing the original folder: the packaged copy must parse on its own.
	destDir := t.TempDir()
	dest := filepath.Join(destDir, "sample.ovpn")
	if err := os.WriteFile(dest, packaged, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(srcDir); err != nil {
		t.Fatal(err)
	}

	p, err := ParseFile(dest)
	if err != nil {
		t.Fatalf("ParseFile(packaged): %v", err)
	}
	if len(p.CACerts) != 1 || !strings.Contains(p.CACerts[0], pemBody("ca-packaged")) {
		t.Fatal("packaged CA not loaded")
	}
	if !strings.Contains(p.ClientCert, pemBody("cert-packaged")) || !strings.Contains(p.ClientKey, pemBody("key-packaged")) {
		t.Fatal("packaged client material not loaded")
	}
	if !strings.Contains(p.ControlWrapKey, pemBody("ta-packaged")) || p.ControlWrapDirection != "client" {
		t.Fatalf("packaged tls-auth not loaded: dir=%q", p.ControlWrapDirection)
	}
	if p.Username != "" || p.Password != "" {
		t.Fatal("packaged profile unexpectedly carries credentials; they belong in .auth")
	}
}

func TestPackageFileDropsInlineCredentials(t *testing.T) {
	dir := t.TempDir()
	content := strings.Join([]string{
		"client",
		"remote vpn.example.net 1194",
		"<auth-user-pass>",
		"inline-user",
		"inline-pass",
		"</auth-user-pass>",
	}, "\n")
	path := writeTestProfile(t, dir, content)

	packaged, prof, err := LoadPackage(path)
	if err != nil {
		t.Fatalf("LoadPackage: %v", err)
	}
	if prof.Username != "inline-user" || prof.Password != "inline-pass" {
		t.Fatalf("parsed credentials = %q/%q, want the inline pair", prof.Username, prof.Password)
	}
	text := string(packaged)
	if strings.Contains(text, "inline-user") || strings.Contains(text, "inline-pass") {
		t.Fatalf("packaged profile contains inline credentials:\n%s", text)
	}
	if !strings.Contains(text, "auth-user-pass\n") {
		t.Fatalf("packaged profile lost the auth-user-pass directive:\n%s", text)
	}

	// The packaged copy must parse without finding credentials: they belong in
	// the per-link .auth file written by the caller.
	destDir := t.TempDir()
	dest := writeTestFile(t, destDir, "packaged.ovpn", text)
	p, err := ParseFile(dest)
	if err != nil {
		t.Fatalf("ParseFile(packaged): %v", err)
	}
	if p.Username != "" || p.Password != "" {
		t.Fatal("packaged profile still carries credentials")
	}
}

func TestPackageFileRejectsUnsafeReference(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "profile")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, parent, "outside.pem", syntheticPEM("CERTIFICATE", "outside"))
	profilePath := writeTestProfile(t, dir, "ca ../outside.pem")
	if _, err := PackageFile(profilePath); err == nil {
		t.Fatal("PackageFile accepted a traversal reference")
	}
}

func TestValidateRelativeRef(t *testing.T) {
	bad := []string{"", " ", "/etc/passwd", `C:\x`, "../x", `..\x`, "a/../../x", `a\..\..\x`}
	for _, ref := range bad {
		if err := validateRelativeRef(ref); err == nil {
			t.Errorf("validateRelativeRef(%q) accepted", ref)
		}
	}
	good := []string{"ca.pem", "sub/ca.pem", `sub\ca.pem`, "./ca.pem"}
	for _, ref := range good {
		if err := validateRelativeRef(ref); err != nil {
			t.Errorf("validateRelativeRef(%q) = %v", ref, err)
		}
	}
}

// TestPackageFileInlineBlockClosesOnlyOnMatchingTag pins the boundary rule to
// the parser's: only the exact closing tag ends a block. Any other tag-shaped
// line is body content, so a nested-looking tag cannot end the credential block
// early and leak the remaining lines into the packaged profile.
func TestPackageFileInlineBlockClosesOnlyOnMatchingTag(t *testing.T) {
	dir := t.TempDir()
	const (
		fixtureUser = "fixture-inline-user"
		fixturePass = "fixture-inline-pass"
	)
	content := strings.Join([]string{
		"client",
		"remote vpn.example.net 1194",
		"<auth-user-pass>",
		fixtureUser,
		"</key>",
		fixturePass,
		"</AUTH-USER-PASS>",
		"verb 3",
	}, "\n")
	path := writeTestProfile(t, dir, content)

	packaged, prof, err := LoadPackage(path)
	if err != nil {
		t.Fatalf("LoadPackage: %v", err)
	}
	// The parser sees the same boundary: `</key>` is the password line, not the
	// end of the block.
	if prof.Username != fixtureUser || prof.Password != "</key>" {
		t.Fatalf("parser boundary mismatch: user=%q pass=%q", prof.Username, prof.Password)
	}
	text := string(packaged)
	for _, secret := range []string{fixtureUser, fixturePass, "</key>", "</AUTH-USER-PASS>"} {
		if strings.Contains(text, secret) {
			t.Fatalf("packaged profile leaked credential block content %q:\n%s", secret, text)
		}
	}
	if !strings.Contains(text, "auth-user-pass\n") {
		t.Fatalf("packaged profile lost the auth-user-pass directive:\n%s", text)
	}
	if !strings.Contains(text, "verb 3") {
		t.Fatalf("packaged profile lost directives after the credential block:\n%s", text)
	}
}

// TestPackageFileUnterminatedCredentialBlockDoesNotLeak proves an unclosed
// inline credential block never falls back to copying its body verbatim.
func TestPackageFileUnterminatedCredentialBlockDoesNotLeak(t *testing.T) {
	dir := t.TempDir()
	const (
		fixtureUser = "fixture-unterminated-user"
		fixturePass = "fixture-unterminated-pass"
	)
	content := strings.Join([]string{
		"client",
		"remote vpn.example.net 1194",
		"<auth-user-pass>",
		fixtureUser,
		fixturePass,
	}, "\n")
	path := writeTestProfile(t, dir, content)

	packaged, err := PackageFile(path)
	if err == nil {
		t.Fatalf("PackageFile accepted an unterminated credential block; output:\n%s", packaged)
	}
	if len(packaged) != 0 {
		t.Fatalf("PackageFile returned bytes with its error: %q", packaged)
	}
	if strings.Contains(err.Error(), fixtureUser) || strings.Contains(err.Error(), fixturePass) {
		t.Fatalf("error message leaked credential content: %v", err)
	}
}

// TestPackageFileInlineSecretBlocksStayIntact proves PEM blocks are packaged as
// written when they contain tag-shaped payload lines. The exact-match rule must
// not truncate a legitimate inline block either.
func TestPackageFileInlineSecretBlocksStayIntact(t *testing.T) {
	dir := t.TempDir()
	ca := syntheticPEM("CERTIFICATE", "ca-additive")
	content := strings.Join([]string{
		"client",
		"remote vpn.example.net 1194",
		"<ca>",
		ca,
		"</ca>",
		"remote-cert-tls server",
	}, "\n")
	path := writeTestProfile(t, dir, content)

	packaged, err := PackageFile(path)
	if err != nil {
		t.Fatalf("PackageFile: %v", err)
	}
	text := string(packaged)
	if !strings.Contains(text, pemBody("ca-additive")) {
		t.Fatalf("inline CA body was not preserved:\n%s", text)
	}
	if !strings.Contains(text, "remote-cert-tls server") {
		t.Fatalf("directive after the CA block was lost:\n%s", text)
	}
}
