package embedbin

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// elfHeader builds the smallest ELF header debug/elf accepts: correct magic,
// class, data encoding, version and machine, with no program or section
// headers. It is enough to exercise the architecture check without a payload.
func elfHeader(class byte, machine uint16) []byte {
	if class == 2 {
		b := make([]byte, 64)
		copy(b, "\x7fELF")
		b[4] = class
		b[5] = 1                                 // little endian
		b[6] = 1                                 // EV_CURRENT
		binary.LittleEndian.PutUint16(b[16:], 2) // ET_EXEC
		binary.LittleEndian.PutUint16(b[18:], machine)
		binary.LittleEndian.PutUint32(b[20:], 1)
		binary.LittleEndian.PutUint16(b[52:], 64) // e_ehsize
		return b
	}
	b := make([]byte, 52)
	copy(b, "\x7fELF")
	b[4] = class
	b[5] = 1
	b[6] = 1
	binary.LittleEndian.PutUint16(b[16:], 2)
	binary.LittleEndian.PutUint16(b[18:], machine)
	binary.LittleEndian.PutUint32(b[20:], 1)
	binary.LittleEndian.PutUint16(b[40:], 52)
	return b
}

func TestAssetForSelectsExactTargetOnly(t *testing.T) {
	cases := []struct {
		goos, goarch, goarm string
		want                bool
	}{
		{"linux", "amd64", "", true},
		{"linux", "arm64", "", true},
		{"linux", "arm", "7", true},
		{"linux", "arm", "6", false},
		{"linux", "arm", "", false},
		{"linux", "386", "", false},
		{"windows", "amd64", "", false},
		{"darwin", "arm64", "", false},
	}
	for _, c := range cases {
		a, ok := AssetFor(c.goos, c.goarch, c.goarm)
		if ok != c.want {
			t.Errorf("AssetFor(%s/%s/%s) ok=%v, want %v", c.goos, c.goarch, c.goarm, ok, c.want)
			continue
		}
		if ok && (a.GOOS != c.goos || a.GOARCH != c.goarch || a.GOARM != c.goarm) {
			t.Errorf("AssetFor(%s/%s/%s) returned %s/%s/%s", c.goos, c.goarch, c.goarm, a.GOOS, a.GOARCH, a.GOARM)
		}
		if ok && a.File == "" {
			t.Errorf("AssetFor(%s/%s/%s) has no staged file name", c.goos, c.goarch, c.goarm)
		}
	}
}

func TestMustAssetForPanicsOnUnsupportedTarget(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MustAssetFor did not panic for an unsupported target")
		}
	}()
	MustAssetFor("linux", "arm", "6")
}

func TestVerifyELFMatchesArchitecture(t *testing.T) {
	amd64 := elfHeader(2, 62)
	arm64 := elfHeader(2, 183)
	arm := elfHeader(1, 40)

	if err := VerifyELF(amd64, "amd64"); err != nil {
		t.Fatalf("amd64 header rejected: %v", err)
	}
	if err := VerifyELF(arm64, "arm64"); err != nil {
		t.Fatalf("arm64 header rejected: %v", err)
	}
	if err := VerifyELF(arm, "arm"); err != nil {
		t.Fatalf("arm header rejected: %v", err)
	}

	cross := []struct {
		data   []byte
		goarch string
	}{
		{amd64, "arm64"},
		{amd64, "arm"},
		{arm64, "amd64"},
		{arm, "amd64"},
		{arm, "arm64"},
	}
	for _, c := range cross {
		if err := VerifyELF(c.data, c.goarch); err == nil {
			t.Errorf("ELF for another architecture accepted as %s", c.goarch)
		}
	}
}

func TestVerifyELFRejectsNonELFAndUnknownArch(t *testing.T) {
	if err := VerifyELF([]byte("not an elf binary at all"), "amd64"); err == nil {
		t.Fatal("non-ELF data accepted")
	}
	if err := VerifyELF(elfHeader(2, 62), "386"); err == nil {
		t.Fatal("unknown GOARCH accepted")
	}
}

// requireStagedAssets makes a missing asset a failure instead of a skip. Release
// gates set BYPATH_REQUIRE_ASSETS=1 so an unstaged or partially staged tree can
// never produce a green run.
func requireStagedAssets() bool { return os.Getenv("BYPATH_REQUIRE_ASSETS") == "1" }

// TestStagedAssetsVerify pins the manifest to the staged files when they are
// present. The assets are gitignored build inputs, so a plain developer checkout
// skips this test; `make verify-tun2socks` performs the same check as a build
// gate, and release gates set BYPATH_REQUIRE_ASSETS=1.
func TestStagedAssetsVerify(t *testing.T) {
	for _, a := range StagedTun2socks {
		path := filepath.Join("assets", a.File)
		if _, err := os.Stat(path); err != nil {
			if requireStagedAssets() {
				t.Fatalf("%s is required by BYPATH_REQUIRE_ASSETS but not staged", path)
			}
			t.Logf("skipping %s: not staged", path)
			continue
		}
		if err := VerifyAsset(path, a); err != nil {
			t.Fatalf("VerifyAsset(%s): %v", a.File, err)
		}
	}
}

func TestVerifyAssetRejectsMismatches(t *testing.T) {
	for _, a := range StagedTun2socks {
		path := filepath.Join("assets", a.File)
		data, err := os.ReadFile(path)
		if err != nil {
			if requireStagedAssets() {
				t.Fatalf("%s is required by BYPATH_REQUIRE_ASSETS but not staged", path)
			}
			t.Logf("skipping %s: not staged", path)
			continue
		}
		dir := t.TempDir()

		tampered := append([]byte(nil), data...)
		tampered[len(tampered)/2] ^= 0xff
		tamperedPath := filepath.Join(dir, "tampered")
		if err := os.WriteFile(tamperedPath, tampered, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := VerifyAsset(tamperedPath, a); err == nil {
			t.Errorf("%s: corrupted asset accepted", a.File)
		}

		if a.GOARCH == "amd64" {
			continue
		}
		wrongArch := a
		wrongArch.GOARCH = "amd64"
		if err := VerifyAsset(path, wrongArch); err == nil {
			t.Errorf("%s: %s asset accepted as amd64", a.File, a.GOARCH)
		}
	}
}
