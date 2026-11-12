//go:build full && embed_tun2socks && linux && (amd64 || arm64 || (arm && arm.7))

package embedbin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestEmbeddedAssetMatchesManifestAndStagedFile(t *testing.T) {
	info, ok := EmbeddedTun2socksInfo()
	if !ok {
		t.Fatal("EmbeddedTun2socksInfo reports no asset with the embed tag")
	}
	if !HasEmbedded() {
		t.Fatal("HasEmbedded false with the embed tag")
	}
	if info.GOOS != runtime.GOOS || info.GOARCH != runtime.GOARCH {
		t.Fatalf("manifest %s/%s, process %s/%s", info.GOOS, info.GOARCH, runtime.GOOS, runtime.GOARCH)
	}

	want, err := os.ReadFile(filepath.Join("assets", info.File))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(want)
	if got := hex.EncodeToString(sum[:]); got != info.SHA256 {
		t.Fatalf("staged asset sha256 %s, manifest says %s", got, info.SHA256)
	}
	if !bytes.Equal(want, tun2socksData) {
		t.Fatalf("compiled-in bytes differ from %s", info.File)
	}
	if err := ValidateEmbedded(tun2socksData, info); err != nil {
		t.Fatalf("ValidateEmbedded: %v", err)
	}
}

func TestExtractWritesVerifiedExecutable(t *testing.T) {
	info, ok := EmbeddedTun2socksInfo()
	if !ok {
		t.Fatal("no embedded asset")
	}
	path, err := ExtractTun2socks()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, tun2socksData) {
		t.Fatal("extracted bytes differ from the embedded asset")
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v, want 0755", stat.Mode().Perm())
	}
	if err := VerifyAsset(path, info); err != nil {
		t.Fatalf("VerifyAsset on extracted file: %v", err)
	}
}

func TestValidateEmbeddedRejectsForeignArchitecture(t *testing.T) {
	info, ok := EmbeddedTun2socksInfo()
	if !ok {
		t.Fatal("no embedded asset")
	}
	for _, foreign := range StagedTun2socks {
		if foreign.GOARCH == info.GOARCH {
			continue
		}
		if err := ValidateEmbedded(tun2socksData, foreign); err == nil {
			t.Fatalf("embedded %s data accepted as %s", info.GOARCH, foreign.GOARCH)
		}
	}
}

func TestValidateEmbeddedRejectsCorruptPayload(t *testing.T) {
	info, ok := EmbeddedTun2socksInfo()
	if !ok {
		t.Fatal("no embedded asset")
	}
	truncated := tun2socksData[:len(tun2socksData)-1]
	if err := ValidateEmbedded(truncated, info); err == nil {
		t.Fatal("truncated payload accepted")
	}
	tampered := append([]byte(nil), tun2socksData...)
	tampered[len(tampered)/2] ^= 0xff
	if err := ValidateEmbedded(tampered, info); err == nil {
		t.Fatal("tampered payload accepted")
	}
}

// TestHasEmbeddedIsATagProperty covers C2-08: an empty payload inside an embed
// build is a packaging defect. It must select the embedded path (which then
// fails loudly through ExtractTun2socks), never a silent fallback.
func TestHasEmbeddedIsATagProperty(t *testing.T) {
	saved := tun2socksData
	tun2socksData = nil
	defer func() { tun2socksData = saved }()

	if !HasEmbedded() {
		t.Fatal("HasEmbedded reported no payload with the embed tag")
	}
	if _, err := ExtractTun2socks(); err == nil {
		t.Fatal("an empty embedded payload was extracted successfully")
	}
}
