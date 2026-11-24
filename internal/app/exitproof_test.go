package app

import (
	"strings"
	"testing"
)

// TestExitProofVerdict pins the activation rule. Blocked identity oracles do
// not disable a tunnel that carries traffic; a tunnel that carried nothing, or
// an exit equal to the direct uplink, still fails closed; and an unverified
// identity is never reported as verified.
func TestExitProofVerdict(t *testing.T) {
	cases := []struct {
		name         string
		proof        ExitProof
		wantAllowed  bool
		wantVerified bool
		wantDetail   string
	}{
		{
			name:         "reachable tunnel, distinct exit",
			proof:        ExitProof{Exits: []string{"203.0.113.7"}, Uplink: []string{"192.0.2.9"}, Oracles: 4},
			wantAllowed:  true,
			wantVerified: true,
		},
		{
			name:         "rotating exit with repeated samples",
			proof:        ExitProof{Exits: []string{"203.0.113.7", "203.0.113.7", "203.0.113.8"}, Uplink: []string{"192.0.2.9", "192.0.2.81"}, Oracles: 4},
			wantAllowed:  true,
			wantVerified: true,
		},
		{
			name:        "every identity oracle blocked, data path works",
			proof:       ExitProof{Uplink: []string{"192.0.2.9"}, Oracles: 4, DataPathOK: true},
			wantAllowed: true,
			wantDetail:  "UNVERIFIED",
		},
		{
			name:       "every identity oracle blocked and the data path failed",
			proof:      ExitProof{Oracles: 4, DataPathDetail: "http://www.gstatic.com/generate_204: timeout"},
			wantDetail: "no traffic reached the internet",
		},
		{
			name:       "actual tunnel failure with no direct sample",
			proof:      ExitProof{Oracles: 4},
			wantDetail: "no traffic reached the internet",
		},
		{
			name:       "exit equals the direct address",
			proof:      ExitProof{Exits: []string{"192.0.2.9"}, Uplink: []string{"192.0.2.9"}, Oracles: 4},
			wantDetail: "equals this host's direct address",
		},
		{
			name:       "inconsistent answers include the direct address",
			proof:      ExitProof{Exits: []string{"203.0.113.7", "192.0.2.9"}, Uplink: []string{"192.0.2.9"}, Oracles: 4},
			wantDetail: "equals this host's direct address",
		},
		{
			name:        "exit observed but the direct uplink is blocked",
			proof:       ExitProof{Exits: []string{"203.0.113.7"}, Oracles: 4},
			wantAllowed: true,
			wantDetail:  "UNVERIFIED",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.proof.Verdict()
			if got.Allowed != tc.wantAllowed {
				t.Fatalf("Allowed = %v (%q), want %v", got.Allowed, got.Detail, tc.wantAllowed)
			}
			if got.Verified != tc.wantVerified {
				t.Fatalf("Verified = %v, want %v", got.Verified, tc.wantVerified)
			}
			if got.Verified && !got.Allowed {
				t.Fatal("a verified proof must be allowed")
			}
			if tc.wantDetail != "" && !strings.Contains(got.Detail, tc.wantDetail) {
				t.Fatalf("detail %q does not contain %q", got.Detail, tc.wantDetail)
			}
			if got.Allowed && got.Detail == "" {
				t.Fatal("an allowed verdict must explain its evidence")
			}
		})
	}
}
