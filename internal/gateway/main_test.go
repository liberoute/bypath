package gateway

import (
	"os"
	"testing"
)

// TestMain keeps runtime state (pidfile, ownership records, stop requests) out
// of the real installation directory, which local mode otherwise uses.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "bypath-gwtest-*")
	if err != nil {
		panic(err)
	}
	os.Setenv("BYPATH_RUNTIME_DIR", dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
