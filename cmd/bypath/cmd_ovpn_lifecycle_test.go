package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/openvpn"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/securefile"
)

func lifecyclePEM(label, marker string) string {
	return "-----BEGIN " + label + "-----\n" +
		base64.StdEncoding.EncodeToString([]byte(marker)) + "\n" +
		"-----END " + label + "-----"
}

// TestOVPNImportRemoveLifecycle drives the real CLI handlers against an
// isolated working directory: import packages the profile, removal deletes
// only the artifacts that link owns, and nothing else in the directory moves.
func TestOVPNImportRemoveLifecycle(t *testing.T) {
	work := t.TempDir()
	src := filepath.Join(work, "src")
	if err := os.MkdirAll(src, 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"ca.crt":     lifecyclePEM("CERTIFICATE", "lifecycle-ca"),
		"client.crt": lifecyclePEM("CERTIFICATE", "lifecycle-cert"),
		"client.key": lifecyclePEM("PRIVATE KEY", "lifecycle-key"),
		"ta.key":     lifecyclePEM("OpenVPN Static key V1", "lifecycle-ta"),
		"creds.txt":  "fixture-user\nfixture-pass\n",
		"vpn.ovpn": strings.Join([]string{
			"client",
			"dev tun",
			"proto udp",
			"remote vpn.example.net 443",
			"ca ca.crt",
			"cert client.crt",
			"key client.key",
			"tls-auth ta.key 1",
			"auth-user-pass creds.txt",
			"remote-cert-tls server",
		}, "\n") + "\n",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	profileSrc := filepath.Join(src, "vpn.ovpn")

	t.Chdir(work)
	paths.Reset()
	t.Cleanup(paths.Reset)

	ovpnDir := filepath.Join(work, "data", "profiles", "ovpn")
	if err := os.MkdirAll(ovpnDir, 0700); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(ovpnDir, "keep.me")
	if err := os.WriteFile(unrelated, []byte("unrelated"), 0600); err != nil {
		t.Fatal(err)
	}

	cmdAddOVPN([]string{"--name", "fixture", profileSrc})

	entries, err := os.ReadDir(ovpnDir)
	if err != nil {
		t.Fatal(err)
	}
	var stored, auth string
	for _, e := range entries {
		switch {
		case strings.HasSuffix(e.Name(), ".ovpn"):
			stored = filepath.Join(ovpnDir, e.Name())
		case strings.HasSuffix(e.Name(), ".auth"):
			auth = filepath.Join(ovpnDir, e.Name())
		}
	}
	if stored == "" || auth == "" {
		t.Fatalf("import did not create profile and auth artifacts: %v", entries)
	}
	if !securefile.IsOwnerOnly(stored) || !securefile.IsOwnerOnly(auth) {
		t.Fatal("imported artifacts are readable by users other than their owner")
	}

	authBody, err := os.ReadFile(auth)
	if err != nil {
		t.Fatal(err)
	}
	if string(authBody) != "fixture-user\nfixture-pass\n" {
		t.Fatal("auth file does not contain the imported credentials")
	}
	storedBody, err := os.ReadFile(stored)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(storedBody), "fixture-pass") {
		t.Fatal("password was embedded in the stored profile")
	}
	if !strings.Contains(string(storedBody), "<ca>") || !strings.Contains(string(storedBody), "<tls-auth>") {
		t.Fatal("stored profile does not inline its certificate/ta material")
	}

	// Removing the source folder must not affect the imported profile.
	if err := os.RemoveAll(src); err != nil {
		t.Fatal(err)
	}
	if _, err := openvpn.ParseFile(stored); err != nil {
		t.Fatalf("stored profile no longer parses after source removal: %v", err)
	}
	if strings.Contains(strings.ToLower(string(storedBody)), "auth-user-pass creds") {
		t.Fatal("stored profile still references the credential file by path")
	}
	user, pass, err := openvpn.CredentialsFromFile(auth)
	if err != nil || user != "fixture-user" || pass != "fixture-pass" {
		t.Fatalf("stored credentials unusable after source removal: user=%q err=%v", user, err)
	}

	cmdRemove([]string{"fixture"})

	for _, p := range []string{stored, auth} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived link removal (err=%v)", p, err)
		}
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Errorf("removal deleted an unrelated file: %v", err)
	}
}
