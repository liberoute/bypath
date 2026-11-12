//go:build full

package build

func init() {
	Variant = "full"
	RegisterEmbeddedEngine("sing-box")
	RegisterEmbeddedEngine("xray")
	RegisterEmbeddedEngine("wireguard-go")
}
