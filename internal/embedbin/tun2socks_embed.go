//go:build full && embed_tun2socks

package embedbin

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed ../../../assets/embed/tun2socks
var tun2socksData []byte

// ExtractTun2socks writes the embedded tun2socks binary to a temp file and
// returns its path. The caller is responsible for deleting the file when done.
func ExtractTun2socks() (string, error) {
	if len(tun2socksData) == 0 {
		return "", fmt.Errorf("embedded tun2socks binary is empty")
	}
	tmp, err := os.CreateTemp("", "tun2socks-*")
	if err != nil {
		return "", err
	}
	if _, err := tmp.Write(tun2socksData); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return "", err
	}
	tmp.Close()
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return filepath.Clean(tmp.Name()), nil
}

// HasEmbedded reports whether a tun2socks binary is embedded.
func HasEmbedded() bool { return len(tun2socksData) > 0 }
