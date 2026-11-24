//go:build full && embed_tun2socks && linux && (amd64 || arm64 || (arm && arm.7))

package embedbin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// ExtractTun2socks writes the embedded tun2socks binary to a temp file and
// returns its path. Permissions are set on the open handle before the bytes are
// written so the executable is never visible with different permissions than
// intended. The caller is responsible for deleting the file when done.
//
// The payload is validated before it is written: a binary staged for another
// architecture, or one that does not match the pinned digest and size, is
// rejected instead of being executed on the target device.
func ExtractTun2socks() (string, error) {
	if len(tun2socksData) == 0 {
		return "", fmt.Errorf("embedded tun2socks binary is empty")
	}
	if err := ValidateEmbedded(tun2socksData, embeddedTun2socks); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp("", "tun2socks-*")
	if err != nil {
		return "", err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if _, err := tmp.Write(tun2socksData); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return filepath.Clean(tmp.Name()), nil
}

// HasEmbedded reports that this build carries a tun2socks payload. It is true
// for every build with the embed tag, not only when the payload has bytes: an
// empty payload is a packaging defect that must fail the gateway instead of
// silently selecting a binary this build never verified.
func HasEmbedded() bool { return true }

// EmbeddedTun2socksInfo returns the manifest entry for the compiled-in asset.
func EmbeddedTun2socksInfo() (Asset, bool) {
	return embeddedTun2socks, len(tun2socksData) > 0
}

// ValidateEmbedded checks that data is the pinned binary for its target and
// that the target is the architecture this process was built for.
func ValidateEmbedded(data []byte, a Asset) error {
	if runtime.GOOS != a.GOOS || runtime.GOARCH != a.GOARCH {
		return fmt.Errorf("embedded tun2socks is for %s/%s but this build targets %s/%s; rebuild with the matching asset",
			a.GOOS, a.GOARCH, runtime.GOOS, runtime.GOARCH)
	}
	if int64(len(data)) != a.Size {
		return fmt.Errorf("embedded tun2socks is %d bytes, manifest says %d", len(data), a.Size)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != a.SHA256 {
		return fmt.Errorf("embedded tun2socks sha256 %s, manifest says %s", got, a.SHA256)
	}
	if err := VerifyELF(data, a.GOARCH); err != nil {
		return fmt.Errorf("embedded tun2socks: %w", err)
	}
	return nil
}
