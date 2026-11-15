package embedbin

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// Tun2socksVersion is the pinned upstream release. The archive digests in the
// Makefile and the extracted-binary digests below come from the same release.
const Tun2socksVersion = "v2.5.2"

// Tun2socksCommit is the upstream commit v2.5.2 was built from. Every pinned
// binary embeds it as vcs.revision, so staging an asset built from another
// commit is detectable.
const Tun2socksCommit = "2b494a75170686ea6246ca36e784e7c8c447940f"

// Asset describes one staged tun2socks binary.
type Asset struct {
	GOOS    string
	GOARCH  string
	GOARM   string
	File    string // basename under internal/embedbin/assets
	SHA256  string // digest of the extracted binary
	Size    int64
	Version string
	Commit  string
}

// StagedTun2socks lists every supported staged asset. The digests are of the
// extracted binaries, not of the release archives (the Makefile verifies the
// archives first).
var StagedTun2socks = []Asset{
	{GOOS: "linux", GOARCH: "amd64", File: "tun2socks_linux_amd64", Size: 8622080,
		SHA256:  "baa6237fd5fbf5f5330f8f0e3578416ed47e85e34a7c973b248bb516fd0ed101",
		Version: Tun2socksVersion, Commit: Tun2socksCommit},
	{GOOS: "linux", GOARCH: "arm64", File: "tun2socks_linux_arm64", Size: 8257536,
		SHA256:  "a359b4a8a1ebde80b7a8164f8ab1e1de62f11187ce99a3e9065cdb1be53e87b2",
		Version: Tun2socksVersion, Commit: Tun2socksCommit},
	{GOOS: "linux", GOARCH: "arm", GOARM: "7", File: "tun2socks_linux_armv7", Size: 8192000,
		SHA256:  "5e255b6f932b3ac8428a94ec0725ae664f6526e0d588f72cc1e29b905128bc6c",
		Version: Tun2socksVersion, Commit: Tun2socksCommit},
}

// AssetFor returns the staged entry for a target triple.
func AssetFor(goos, goarch, goarm string) (Asset, bool) {
	for _, a := range StagedTun2socks {
		if a.GOOS == goos && a.GOARCH == goarch && a.GOARM == goarm {
			return a, true
		}
	}
	return Asset{}, false
}

// MustAssetFor is AssetFor for a target the build tags have already selected.
func MustAssetFor(goos, goarch, goarm string) Asset {
	a, ok := AssetFor(goos, goarch, goarm)
	if !ok {
		panic("embedbin: no staged tun2socks asset for " + goos + "/" + goarch + "/" + goarm)
	}
	return a
}

// elfTarget is the ELF header an asset for a Go architecture must carry.
type elfTarget struct {
	machine elf.Machine
	class   elf.Class
}

var elfTargets = map[string]elfTarget{
	"amd64": {machine: elf.EM_X86_64, class: elf.ELFCLASS64},
	"arm64": {machine: elf.EM_AARCH64, class: elf.ELFCLASS64},
	"arm":   {machine: elf.EM_ARM, class: elf.ELFCLASS32},
}

// VerifyELF rejects a binary whose ELF header does not describe goarch. This is
// the check that stops an amd64 tun2socks from being embedded into an arm64 or
// armv7 build, where it could only fail at runtime on the target device.
func VerifyELF(data []byte, goarch string) error {
	want, ok := elfTargets[goarch]
	if !ok {
		return fmt.Errorf("no ELF target is defined for GOARCH %q", goarch)
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("not an ELF binary: %w", err)
	}
	defer f.Close()
	if f.Class != want.class || f.Machine != want.machine {
		return fmt.Errorf("ELF header is %s/%s, want %s/%s for GOARCH %s",
			f.Machine, f.Class, want.machine, want.class, goarch)
	}
	return nil
}

// VerifyAsset checks a staged file end to end: size and digest against the
// pinned manifest, ELF architecture, and the upstream build information
// (GOOS/GOARCH/GOARM, module path and VCS revision). Any mismatch means the
// build would ship a binary that does not belong to its target.
func VerifyAsset(path string, a Asset) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if int64(len(data)) != a.Size {
		return fmt.Errorf("%s: size %d, want %d", path, len(data), a.Size)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != a.SHA256 {
		return fmt.Errorf("%s: sha256 %s, want %s", path, got, a.SHA256)
	}
	if err := VerifyELF(data, a.GOARCH); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	bi, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("%s: build info: %w", path, err)
	}
	if !strings.HasPrefix(bi.Main.Path, "github.com/xjasonlyu/tun2socks") {
		return fmt.Errorf("%s: module is %q, want tun2socks", path, bi.Main.Path)
	}
	settings := map[string]string{}
	for _, s := range bi.Settings {
		settings[s.Key] = s.Value
	}
	for key, want := range map[string]string{
		"GOOS": a.GOOS, "GOARCH": a.GOARCH, "GOARM": a.GOARM,
		"vcs.revision": a.Commit,
	} {
		if want != "" && settings[key] != want {
			return fmt.Errorf("%s: build setting %s=%q, want %q", path, key, settings[key], want)
		}
	}
	return nil
}
