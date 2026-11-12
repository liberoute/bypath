package main

import (
	"testing"

	"github.com/liberoute/bypath/internal/app"
)

// TestStatusExitCodeSignalsDaemonAbsence keeps `bypath status` usable as a
// probe: a stopped gateway must not look like success to a monitoring check.
func TestStatusExitCodeSignalsDaemonAbsence(t *testing.T) {
	cases := []struct {
		name    string
		running bool
		want    int
	}{
		{name: "daemon running", running: true, want: 0},
		{name: "daemon absent", running: false, want: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := statusExitCode(app.Status{Running: tc.running}); got != tc.want {
				t.Fatalf("statusExitCode(running=%v) = %d, want %d", tc.running, got, tc.want)
			}
		})
	}
}
