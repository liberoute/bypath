//go:build !linux && !darwin

package main

// Windows and other platforms report a closed pipe as a write error instead
// of raising SIGPIPE, so there is nothing to ignore.
func ignoreSIGPIPE() {}
