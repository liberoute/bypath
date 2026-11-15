//go:build !full

package engine

// This file is compiled in the "lite" build (default).
// No embedded engines — all engines are external binaries.

// EmbeddedFactory is a no-op in lite mode.
type EmbeddedFactory func(configFile string) (EmbeddedRunner, error)

// EmbeddedRunner is a no-op interface in lite mode.
type EmbeddedRunner interface {
	Start() error
	Stop() error
	IsRunning() bool
}

// GetEmbedded always returns false in lite mode.
func GetEmbedded(name string) (EmbeddedFactory, bool) {
	return nil, false
}
