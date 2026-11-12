//go:build full && embed_tun2socks && linux && arm && arm.7

package embedbin

import _ "embed"

//go:embed assets/tun2socks_linux_armv7
var tun2socksData []byte

var embeddedTun2socks = MustAssetFor("linux", "arm", "7")
