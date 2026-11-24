package main

import "github.com/liberoute/bypath/internal/app"

// openService returns the shared application service for CLI commands. When a
// gateway process is alive, state belongs to it, so the CLI talks to its API
// instead of writing profile files behind its back. Otherwise the CLI acts on
// the same on-disk state through an in-process service.
func openService() (app.Contract, error) {
	return app.OpenDefault()
}
