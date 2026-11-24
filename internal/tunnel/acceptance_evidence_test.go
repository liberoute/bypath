package tunnel

import (
	"os"
	"testing"

	"github.com/liberoute/bypath/internal/acceptance"
)

// recordAcceptanceEvidence publishes a live matrix result when the operator
// asked for an evidence directory. The full matrix is assembled and graded by
// internal/acceptance/matrix_test.go.
func recordAcceptanceEvidence(t *testing.T, r acceptance.Result) {
	t.Helper()
	dir := os.Getenv(acceptance.EvidenceDirEnv)
	if dir == "" {
		return
	}
	if err := acceptance.WriteEvidence(dir, r); err != nil {
		t.Errorf("writing acceptance evidence for %s: %v", r.Case, err)
	}
}
