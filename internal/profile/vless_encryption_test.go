package profile

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Synthetic credentials only. Real subscription keys must never be committed.
const (
	testEncKey   = "TESTKEY_do-not-use-0123456789"
	testUUID     = "11111111-2222-3333-4444-555555555555"
	testVLESSUri = "vless://" + testUUID + "@198.51.100.10:443" +
		"?type=tcp&security=reality&pbk=TESTPBK_public&sid=abcd&sni=www.example.com" +
		"&fp=chrome&flow=xtls-rprx-vision&support-x25519mlkem768=true" +
		"&encryption=mlkem768x25519plus.native.0rtt.100-111-1111." + testEncKey +
		"#Test%20Node"
)

func TestParseVlessEncryptionPreserved(t *testing.T) {
	link, err := ParseURI(testVLESSUri)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}

	wantEnc := "mlkem768x25519plus.native.0rtt.100-111-1111." + testEncKey
	if link.Encryption != wantEnc {
		t.Fatalf("encryption not preserved verbatim:\n got %q\nwant %q", link.Encryption, wantEnc)
	}
	if !link.EncryptedVLESS() {
		t.Fatal("EncryptedVLESS() = false, want true")
	}
	if got := link.EncryptionScheme(); got != "mlkem768x25519plus.native.0rtt" {
		t.Fatalf("EncryptionScheme() = %q", got)
	}
	if !link.SupportX25519MLKEM768 {
		t.Fatal("support-x25519mlkem768 hint not recorded")
	}

	// REALITY / Vision parameters must survive alongside encryption.
	checks := map[string]string{
		"pbk":  link.RealityPublicKey,
		"sid":  link.RealityShortID,
		"sni":  link.SNI,
		"fp":   link.Fingerprint,
		"flow": link.Flow,
	}
	wants := map[string]string{
		"pbk":  "TESTPBK_public",
		"sid":  "abcd",
		"sni":  "www.example.com",
		"fp":   "chrome",
		"flow": "xtls-rprx-vision",
	}
	for k, got := range checks {
		if got != wants[k] {
			t.Errorf("%s = %q, want %q", k, got, wants[k])
		}
	}
	if link.RawURI != testVLESSUri {
		t.Error("RawURI was rewritten")
	}
}

func TestEncryptionParametersExcludeAuth(t *testing.T) {
	link, err := ParseURI(testVLESSUri)
	if err != nil {
		t.Fatalf("ParseURI: %v", err)
	}
	want := "mlkem768x25519plus.native.0rtt.100-111-1111"
	if got := link.EncryptionParameters(); got != want {
		t.Fatalf("EncryptionParameters() = %q, want %q", got, want)
	}
	if strings.Contains(link.EncryptionParameters(), testEncKey) {
		t.Fatal("EncryptionParameters leaked the authentication segment")
	}

	other := &Link{Protocol: "vless", Encryption: "mlkem768x25519plus.native.0rtt.200-222-2222.different-auth"}
	if link.EncryptionParameters() == other.EncryptionParameters() {
		t.Fatal("padding differences were treated as the same policy")
	}

	plain := &Link{Protocol: "vless"}
	if plain.EncryptionParameters() != "" {
		t.Fatal("unencrypted link reported encryption parameters")
	}
}

func TestParseVlessEncryptionLegacyAndNone(t *testing.T) {
	base := "vless://" + testUUID + "@198.51.100.10:443?security=tls&sni=example.com&type=ws&path=%2Fws#Legacy"

	link, err := ParseURI(base)
	if err != nil {
		t.Fatalf("legacy VLESS without encryption: %v", err)
	}
	if link.Encryption != "" {
		t.Fatalf("Encryption = %q, want empty", link.Encryption)
	}
	if link.EncryptedVLESS() {
		t.Fatal("legacy VLESS must not be treated as encrypted")
	}

	linkNone, err := ParseURI(base + "&encryption=none")
	if err != nil {
		t.Fatalf("encryption=none: %v", err)
	}
	if linkNone.EncryptedVLESS() {
		t.Fatal("encryption=none must not require xray encryption support")
	}
}

func TestParseVlessEncryptionUnsupported(t *testing.T) {
	cases := map[string]string{
		"too few segments":   "mlkem768x25519plus.native." + testEncKey,
		"unknown handshake":  "aes256gcm.native.0rtt." + testEncKey,
		"unknown appearance": "mlkem768x25519plus.weird.0rtt." + testEncKey,
		"unknown resumption": "mlkem768x25519plus.native.2rtt." + testEncKey,
		"bad padding":        "mlkem768x25519plus.native.0rtt.1-2." + testEncKey,
		"missing auth":       "mlkem768x25519plus.native.0rtt.",
	}

	for name, enc := range cases {
		t.Run(name, func(t *testing.T) {
			uri := "vless://" + testUUID + "@198.51.100.10:443?security=reality&encryption=" + enc + "#Bad"
			_, err := ParseURI(uri)
			if err == nil {
				t.Fatal("expected a parse error")
			}
			msg := err.Error()
			if strings.Contains(msg, testEncKey) || strings.Contains(msg, testUUID) {
				t.Fatalf("error leaked secret material: %v", err)
			}
		})
	}
}

func TestRedactURIHidesCredentials(t *testing.T) {
	red := RedactURI(testVLESSUri)
	if strings.Contains(red, testUUID) || strings.Contains(red, testEncKey) || strings.Contains(red, "TESTPBK") {
		t.Fatalf("RedactURI leaked credentials: %s", red)
	}
	if !strings.Contains(red, "198.51.100.10:443") {
		t.Fatalf("RedactURI dropped host:port: %s", red)
	}

	// Unsupported schemes must also be redacted in errors.
	_, err := ParseURI("quic://" + testUUID + "@host.example:443?key=" + testEncKey)
	if err == nil {
		t.Fatal("expected unsupported protocol error")
	}
	if strings.Contains(err.Error(), testUUID) || strings.Contains(err.Error(), testEncKey) {
		t.Fatalf("unsupported-protocol error leaked credentials: %v", err)
	}
}

func TestVMessAndXHTTPRegression(t *testing.T) {
	vmessJSON := `{"v":"2","ps":"node","add":"203.0.113.7","port":"443","id":"` + testUUID + `","aid":"0","scy":"auto","net":"xhttp","type":"none","host":"cdn.example.com","path":"/x","tls":"tls","sni":"cdn.example.com"}`
	uri := "vmess://" + base64Std(vmessJSON)

	link, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("vmess xhttp: %v", err)
	}
	if link.Network != "xhttp" || link.Host != "cdn.example.com" || link.Path != "/x" {
		t.Fatalf("xhttp transport fields lost: %+v", link)
	}
	if link.Encryption != "" {
		t.Fatalf("vmess picked up encryption %q", link.Encryption)
	}
}

func base64Std(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
