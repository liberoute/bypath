// Command verify-embedded-binary checks a built Bypath binary against the
// staged tun2socks assets: the binary must target the requested architecture,
// carry the expected VCS revision, contain its own architecture's helper and
// contain no helper staged for another architecture.
package main

import (
	"bytes"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/liberoute/bypath/internal/embedbin"
)

func main() {
	binary := flag.String("binary", "", "built Bypath binary")
	assets := flag.String("assets-dir", "internal/embedbin/assets", "directory with staged tun2socks assets")
	goarch := flag.String("goarch", "", "expected GOARCH")
	goarm := flag.String("goarm", "", "expected GOARM (armv7 only)")
	commit := flag.String("expect-commit", "", "expected vcs.revision (short SHA accepted)")
	flag.Parse()
	if *binary == "" || *goarch == "" {
		fmt.Fprintln(os.Stderr, "verify-embedded-binary: -binary and -goarch are required")
		os.Exit(2)
	}
	if err := run(*binary, *assets, *goarch, *goarm, *commit); err != nil {
		fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", *binary, err)
		os.Exit(1)
	}
}

func run(binary, assetsDir, goarch, goarm, wantCommit string) error {
	data, err := os.ReadFile(binary)
	if err != nil {
		return err
	}
	if err := embedbin.VerifyELF(data, goarch); err != nil {
		return err
	}
	bi, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("build info: %w", err)
	}
	if bi.Main.Path != "github.com/liberoute/bypath" {
		return fmt.Errorf("main module is %q", bi.Main.Path)
	}
	settings := map[string]string{}
	for _, s := range bi.Settings {
		settings[s.Key] = s.Value
	}
	for key, want := range map[string]string{"GOOS": "linux", "GOARCH": goarch, "GOARM": goarm} {
		if want != "" && settings[key] != want {
			return fmt.Errorf("build setting %s=%q, want %q", key, settings[key], want)
		}
	}
	if wantCommit != "" && !binaryCarriesCommit(settings, wantCommit) {
		return fmt.Errorf("binary does not carry commit %q (vcs.revision=%q, -ldflags=%q)",
			wantCommit, settings["vcs.revision"], settings["-ldflags"])
	}

	var own embedbin.Asset
	for _, a := range embedbin.StagedTun2socks {
		payload, err := os.ReadFile(filepath.Join(assetsDir, a.File))
		if err != nil {
			return fmt.Errorf("reading staged %s: %w", a.File, err)
		}
		sum := sha256.Sum256(payload)
		if got := hex.EncodeToString(sum[:]); got != a.SHA256 {
			return fmt.Errorf("staged %s sha256 %s, manifest %s", a.File, got, a.SHA256)
		}
		present := bytes.Contains(data, payload)
		if a.GOARCH == goarch && (goarm == "" || a.GOARM == goarm) {
			own = a
			if !present {
				return fmt.Errorf("expected %s payload (%s) is not embedded", a.File, a.SHA256)
			}
			continue
		}
		if present {
			return fmt.Errorf("binary contains foreign %s/%s payload", a.GOARCH, a.GOARM)
		}
	}
	if own.File == "" {
		return fmt.Errorf("no staged asset matches linux/%s/%s", goarch, goarm)
	}
	fmt.Printf("PASS %s goarch=%s goarm=%q provenance=%s vcs.revision=%q go_version=%s payload=%s payload_sha256=%s binary_sha256=%s\n",
		filepath.Base(binary), goarch, goarm, provenance(settings, wantCommit), settings["vcs.revision"],
		bi.GoVersion, own.File, own.SHA256, sha256Hex(data))
	return nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// binaryCarriesCommit accepts either automatic VCS stamping or an explicit
// -X .../internal/build.Commit=... linker value. Linked worktrees are not
// stamped by the toolchain, so release builds always pass the commit through
// the linker (see the Makefile).
func binaryCarriesCommit(settings map[string]string, want string) bool {
	if strings.HasPrefix(settings["vcs.revision"], want) {
		return true
	}
	return ldflagsCommit(settings, want)
}

func ldflagsCommit(settings map[string]string, want string) bool {
	const key = "internal/build.Commit="
	for _, field := range strings.Fields(settings["-ldflags"]) {
		_, value, ok := strings.Cut(field, key)
		if !ok {
			continue
		}
		// A short -expect-commit must match a full linker value the same way it
		// matches vcs.revision.
		if value == want || (len(want) >= 7 && strings.HasPrefix(value, want)) {
			return true
		}
	}
	return false
}

func provenance(settings map[string]string, want string) string {
	if want == "" {
		return "unchecked"
	}
	if strings.HasPrefix(settings["vcs.revision"], want) {
		return "vcs"
	}
	if ldflagsCommit(settings, want) {
		return "ldflags"
	}
	return "none"
}
