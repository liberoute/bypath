//go:build !linux

package serviceop

import (
	"context"
	"os"
	"path/filepath"
)

func platformBackend() Backend {
	return Backend{Authorize: func(context.Context, string) (int, string, error) { return 0, "", ErrUnsupported }, BootID: func() string { return "unsupported" }}
}
func workerAlive() bool { return false }
func securePath(path string, dir bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(path) || fi.Mode()&os.ModeSymlink != 0 || fi.IsDir() != dir {
		return ErrUnsupported
	}
	return nil
}
func syncDir(string) error     { return nil }
func privatePath(string) error { return nil }
func WorkerAllowed() error     { return ErrUnsupported }
func VerifyWorker() error      { return ErrUnsupported }
