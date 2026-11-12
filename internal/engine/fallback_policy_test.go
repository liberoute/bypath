package engine

import (
	"testing"

	"github.com/liberoute/bypath/internal/profile"
)

func TestFallbackCompatible(t *testing.T) {
	selected := &profile.Link{Protocol: "vless", Encryption: "mlkem768x25519plus.native.0rtt.auth-a"}
	samePolicy := &profile.Link{Protocol: "vless", Encryption: "mlkem768x25519plus.native.0rtt.auth-b"}
	oneRTT := &profile.Link{Protocol: "vless", Encryption: "mlkem768x25519plus.native.1rtt.auth-a"}
	xorPub := &profile.Link{Protocol: "vless", Encryption: "mlkem768x25519plus.xorpub.1rtt.auth-a"}
	otherPadding := &profile.Link{Protocol: "vless", Encryption: "mlkem768x25519plus.native.0rtt.100-111-1111.auth-a"}
	plain := &profile.Link{Protocol: "vless"}

	cases := []struct {
		name      string
		selected  *profile.Link
		candidate *profile.Link
		want      bool
	}{
		{"encrypted->plain", selected, plain, false},
		{"encrypted->nil", selected, nil, false},
		{"encrypted->same-policy", selected, samePolicy, true},
		{"encrypted->other-resumption", selected, oneRTT, false},
		{"encrypted->other-appearance", selected, xorPub, false},
		{"encrypted->other-padding", selected, otherPadding, false},
		{"plain->plain", plain, plain, true},
		{"plain->encrypted", plain, oneRTT, true},
		{"no-selection", nil, plain, true},
	}
	for _, tc := range cases {
		if got := FallbackCompatible(tc.selected, tc.candidate); got != tc.want {
			t.Errorf("%s: FallbackCompatible = %v, want %v", tc.name, got, tc.want)
		}
	}
}
