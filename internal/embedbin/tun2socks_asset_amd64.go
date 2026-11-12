//go:build full && embed_tun2socks && linux && amd64

package embedbin

import _ "embed"

//go:embed assets/tun2socks_linux_amd64
var tun2socksData []byte

var embeddedTun2socks = MustAssetFor("linux", "amd64", "")
