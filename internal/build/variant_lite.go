//go:build !full

package build

func init() {
	Variant = "lite"
}
