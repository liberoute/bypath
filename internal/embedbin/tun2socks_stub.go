//go:build !(full && embed_tun2socks)

package embedbin

import "fmt"

// ExtractTun2socks returns an error when tun2socks is not embedded.
func ExtractTun2socks() (string, error) {
	return "", fmt.Errorf("not available: build with -tags full,embed_tun2socks")
}

// HasEmbedded reports whether a tun2socks binary is embedded.
func HasEmbedded() bool { return false }
