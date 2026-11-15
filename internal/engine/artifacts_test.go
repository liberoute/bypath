package engine

import (
	"encoding/hex"
	"path"
	"strings"
	"testing"
)

func TestPinnedArtifactsAreWellFormed(t *testing.T) {
	for key, a := range pinnedArtifacts {
		if !strings.HasPrefix(a.URL, "https://github.com/") {
			t.Errorf("%v: URL %q is not an official https release", key, a.URL)
		}
		if got := path.Base(a.URL); got != a.Name {
			t.Errorf("%v: URL ends in %q, artifact name is %q", key, got, a.Name)
		}
		if len(a.SHA256) != 64 {
			t.Errorf("%v: checksum %q is not a sha256 hex digest", key, a.SHA256)
		}
		if _, err := hex.DecodeString(a.SHA256); err != nil {
			t.Errorf("%v: checksum is not hex: %v", key, err)
		}
		if a.SHA256 != strings.ToLower(a.SHA256) {
			t.Errorf("%v: checksum must be lowercase", key)
		}
	}
}

func TestArtifactForPicksExactPlatformAsset(t *testing.T) {
	cases := []struct {
		name, goos, goarch string
		wantName           string
	}{
		{"sing-box", "linux", "amd64", "sing-box-1.14.4-linux-amd64.tar.gz"},
		{"sing-box", "linux", "arm", "sing-box-1.14.4-linux-armv7.tar.gz"},
		{"sing-box", "linux", "mipsle", "sing-box-1.14.4-linux-mipsle.tar.gz"},
		{"sing-box", "windows", "amd64", "sing-box-1.14.4-windows-amd64.zip"},
		{"xray", "linux", "amd64", "Xray-linux-64.zip"},
		{"xray", "linux", "arm64", "Xray-linux-arm64-v8a.zip"},
		{"xray", "linux", "arm", "Xray-linux-arm32-v7a.zip"},
		{"xray", "windows", "amd64", "Xray-windows-64.zip"},
	}
	for _, tc := range cases {
		a, err := ArtifactFor(tc.name, tc.goos, tc.goarch)
		if err != nil {
			t.Errorf("ArtifactFor(%s, %s, %s): %v", tc.name, tc.goos, tc.goarch, err)
			continue
		}
		if a.Name != tc.wantName {
			t.Errorf("ArtifactFor(%s, %s, %s) = %q, want %q", tc.name, tc.goos, tc.goarch, a.Name, tc.wantName)
		}
	}
}

func TestArtifactForRejectsUnpinnedPlatform(t *testing.T) {
	cases := []struct{ name, goos, goarch string }{
		{"xray", "darwin", "amd64"},
		{"xray", "linux", "mipsle"},
		{"sing-box", "darwin", "arm64"},
		{"sing-box", "windows", "arm64"},
		{"openvpn", "linux", "amd64"},
		{"wireguard-go", "linux", "amd64"},
	}
	for _, tc := range cases {
		if a, err := ArtifactFor(tc.name, tc.goos, tc.goarch); err == nil {
			t.Errorf("ArtifactFor(%s, %s, %s) accepted %q instead of failing closed", tc.name, tc.goos, tc.goarch, a.Name)
		}
	}
}

func TestSupportedPlatformsOnlyListsPinnedEntries(t *testing.T) {
	got := strings.Join(supportedPlatforms("xray"), ",")
	want := "linux/amd64,linux/arm,linux/arm64,windows/amd64,windows/arm64"
	if got != want {
		t.Fatalf("supportedPlatforms(xray) = %q, want %q", got, want)
	}
}
