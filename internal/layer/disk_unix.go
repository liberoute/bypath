//go:build unix

package layer

import (
	"fmt"
	"syscall"
)

// checkFreeSpace refuses a migration that cannot fit a second copy of the
// profile directory. need is the size of the directory itself.
func checkFreeSpace(dir string, need int64) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return nil // best effort on filesystems that cannot report it
	}
	free := int64(st.Bavail) * int64(st.Bsize)
	if free < need {
		return fmt.Errorf("not enough free disk space for a profile backup: need %d bytes, have %d", need, free)
	}
	return nil
}
