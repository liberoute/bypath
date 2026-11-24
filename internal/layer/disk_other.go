//go:build !unix

package layer

// checkFreeSpace is a no-op on platforms without a portable free-space query;
// the backup itself fails safely if the disk fills.
func checkFreeSpace(dir string, need int64) error { return nil }
