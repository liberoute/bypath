//go:build !windows

package securefile

import (
	"os"
)

// WriteFile writes data with owner-only permissions (0600).
func WriteFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	return writeSecret(f, data)
}

// WriteFileExclusive creates a new file with owner-only permissions (0600) and
// fails with fs.ErrExist instead of reusing an existing path. Name allocation
// and creation are one atomic operation.
func WriteFileExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	return writeSecret(f, data)
}

// writeSecret tightens the mode on the opened descriptor before truncating or
// writing, so a pre-existing permissive file never contains the secret bytes
// under its old permissions.
func writeSecret(f *os.File, data []byte) error {
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// MkdirAll creates a directory with owner-only permissions (0700).
func MkdirAll(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	return os.Chmod(path, 0700)
}

// RestrictFile forces owner-only permissions on an existing file.
func RestrictFile(path string) error {
	return os.Chmod(path, 0600)
}

// RestrictDir forces owner-only permissions on an existing directory.
func RestrictDir(path string) error {
	return os.Chmod(path, 0700)
}

// IsOwnerOnly reports whether no group/other permission bits are set.
func IsOwnerOnly(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0077 == 0
}
