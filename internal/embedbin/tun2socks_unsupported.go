//go:build full && embed_tun2socks && !(linux && (amd64 || arm64 || (arm && arm.7)))

package embedbin

// There is no staged tun2socks asset for this GOOS/GOARCH/GOARM. Referencing an
// undefined identifier turns "-tags full,embed_tun2socks" on an unsupported
// target into a compile error instead of a binary that silently carries a
// foreign-architecture helper.
var _ = tun2socks_embedding_is_only_supported_on_linux_amd64_arm64_and_armv7
