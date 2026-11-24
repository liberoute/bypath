//go:build full && embed_tun2socks && linux && arm64

package embedbin

import _ "embed"

//go:embed assets/tun2socks_linux_arm64
var tun2socksData []byte

var embeddedTun2socks = MustAssetFor("linux", "arm64", "")
