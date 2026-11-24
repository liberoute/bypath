//go:build full && embed_tun2socks && linux && (amd64 || arm64 || (arm && arm.7))

package gateway

import "testing"

// TestEmbeddedBuildUsesOnlyItsOwnHelper covers C2-04: a full-embed build must
// never hand the gateway a managed download or a PATH binary, even when the
// embedded copy extracts but cannot run.
func TestEmbeddedBuildUsesOnlyItsOwnHelper(t *testing.T) {
	gw := newTestGateway(true, false)
	candidates, err := gw.tun2socksCandidates()
	if err != nil {
		t.Fatalf("resolving embedded candidates: %v", err)
	}
	if len(candidates) != 1 {
		names := make([]string, 0, len(candidates))
		for _, c := range candidates {
			names = append(names, c.source)
		}
		t.Fatalf("candidates = %v, want exactly the embedded helper", names)
	}
	if candidates[0].source != "embedded" || candidates[0].path == "" {
		t.Fatalf("candidate = %q %q, want an extracted embedded helper", candidates[0].source, candidates[0].path)
	}
	candidates[0].cleanup()
}
