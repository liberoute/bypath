//go:build full && embed_tun2socks

package build

func init() {
	EmbeddedTun2socks = true
}
