package gateway

import (
	"testing"

	"github.com/liberoute/bypath/internal/profile"
)

func TestEligibleFallbackLinksHonorsEncryptionPolicy(t *testing.T) {
	encrypted := &profile.Link{
		Protocol:   "vless",
		Encryption: "mlkem768x25519plus.native.0rtt",
		Remark:     "encrypted",
		Address:    "vpn.example.net",
		Port:       443,
	}
	plain := &profile.Link{Protocol: "vless", Remark: "plain", Address: "plain.example.net", Port: 443}
	openvpn := &profile.Link{Protocol: "openvpn", Remark: "ovpn", Address: "ovpn.example.net", Port: 443}
	encrypted2 := &profile.Link{
		Protocol:   "vless",
		Encryption: "mlkem768x25519plus.native.0rtt",
		Remark:     "encrypted-2",
		Address:    "vpn2.example.net",
		Port:       443,
	}
	infoOnly := &profile.Link{Protocol: "vless", Remark: "info", Address: "0.0.0.0", Port: 1}

	got := eligibleFallbackLinks(encrypted, []*profile.Link{encrypted, plain, openvpn, encrypted2, infoOnly})
	if len(got) != 1 || got[0].Remark != "encrypted-2" {
		t.Fatalf("encrypted selection fell back to %+v, want only encrypted-2", got)
	}

	got = eligibleFallbackLinks(plain, []*profile.Link{plain, encrypted, openvpn})
	if len(got) != 2 {
		t.Fatalf("plain selection candidates = %+v, want the encrypted and OpenVPN links", got)
	}
}
