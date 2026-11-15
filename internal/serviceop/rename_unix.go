//go:build !windows

package serviceop

import "os"

func renameAtomic(old, new string) error { return os.Rename(old, new) }
