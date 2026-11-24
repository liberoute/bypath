package tunnel

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
)

const (
	cfgTestEncKey = "TESTKEY_do-not-use-abcdef"
	cfgTestEnc    = "mlkem768x25519plus.native.0rtt.100-111-1111." + cfgTestEncKey
)

func encryptedTestLink() *profile.Link {
	return &profile.Link{
		Protocol:              "vless",
		Address:               "198.51.100.10",
		Port:                  443,
		UUID:                  "11111111-2222-3333-4444-555555555555",
		Security:              "reality",
		TLS:                   true,
		SNI:                   "www.example.com",
		Flow:                  "xtls-rprx-vision",
		Fingerprint:           "chrome",
		RealityPublicKey:      "TESTPBK_public",
		RealityShortID:        "abcd",
		Encryption:            cfgTestEnc,
		SupportX25519MLKEM768: true,
		Network:               "tcp",
	}
}

// firstXrayVlessUser returns outbounds[0].settings.vnext[0].users[0].
func firstXrayVlessUser(t *testing.T, cfg map[string]interface{}) map[string]interface{} {
	t.Helper()
	outbounds, ok := cfg["outbounds"].([]interface{})
	if !ok || len(outbounds) == 0 {
		t.Fatalf("missing outbounds")
	}
	ob, ok := outbounds[0].(map[string]interface{})
	if !ok || ob["protocol"] != "vless" {
		t.Fatalf("first outbound is not vless: %v", ob["protocol"])
	}
	settings := ob["settings"].(map[string]interface{})
	vnext := settings["vnext"].([]interface{})
	user := vnext[0].(map[string]interface{})["users"].([]interface{})[0].(map[string]interface{})
	return user
}

func TestXrayPreservesVLESSEncryptionVerbatim(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	link := encryptedTestLink()

	configFile, err := cg.Generate(&engine.Engine{Name: "xray"}, link)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cfg := loadJSON(t, configFile)
	user := firstXrayVlessUser(t, cfg)

	if got := user["encryption"]; got != cfgTestEnc {
		t.Fatalf("encryption altered:\n got %q\nwant %q", got, cfgTestEnc)
	}
	if got := user["flow"]; got != "xtls-rprx-vision" {
		t.Fatalf("flow lost: %v", got)
	}
	if got := user["id"]; got != link.UUID {
		t.Fatalf("uuid changed: %v", got)
	}

	// The REALITY ML-KEM hint is informational and must not become a JSON property.
	stream := cfg["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})
	reality := stream["realitySettings"].(map[string]interface{})
	if reality["publicKey"] != "TESTPBK_public" || reality["shortId"] != "abcd" || reality["fingerprint"] != "chrome" {
		t.Fatalf("reality settings altered: %v", reality)
	}
	serialized := mustJSONString(t, cfg)
	if strings.Contains(serialized, "support-x25519mlkem768") || strings.Contains(serialized, "support_x25519mlkem768") {
		t.Fatal("support-x25519mlkem768 hint was injected into the xray config")
	}
}

func TestSingBoxRejectsEncryptedVLESS(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	_, err := cg.Generate(&engine.Engine{Name: "sing-box"}, encryptedTestLink())
	if err == nil {
		t.Fatal("sing-box accepted VLESS Encryption; it would silently discard it")
	}
	if !strings.Contains(err.Error(), "xray") {
		t.Fatalf("error does not name the required engine: %v", err)
	}
	if strings.Contains(err.Error(), cfgTestEncKey) {
		t.Fatalf("error leaked the encryption key: %v", err)
	}
}

func TestXrayLegacyVLESSGetsEncryptionNone(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	link := &profile.Link{
		Protocol: "vless",
		Address:  "server.com",
		Port:     443,
		UUID:     "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		TLS:      true,
		SNI:      "server.com",
	}
	configFile, err := cg.Generate(&engine.Engine{Name: "xray"}, link)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	user := firstXrayVlessUser(t, loadJSON(t, configFile))
	if user["encryption"] != "none" {
		t.Fatalf("legacy VLESS encryption = %v, want none", user["encryption"])
	}
}

func TestXrayWSTransportRegression(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	link := &profile.Link{
		Protocol: "vless",
		Address:  "server.com",
		Port:     443,
		UUID:     "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		Network:  "ws",
		Path:     "/ws",
		Host:     "cdn.example.com",
		TLS:      true,
		SNI:      "cdn.example.com",
	}
	configFile, err := cg.Generate(&engine.Engine{Name: "xray"}, link)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cfg := loadJSON(t, configFile)
	stream := cfg["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})
	if stream["network"] != "ws" {
		t.Fatalf("network = %v", stream["network"])
	}
	ws := stream["wsSettings"].(map[string]interface{})
	if ws["path"] != "/ws" || ws["host"] != "cdn.example.com" {
		t.Fatalf("ws settings altered: %v", ws)
	}
}

func TestXrayXHTTPTransportRegression(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	link := &profile.Link{
		Protocol:      "vless",
		Address:       "server.com",
		Port:          443,
		UUID:          "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		Network:       "xhttp",
		Path:          "/x",
		Host:          "cdn.example.com",
		TLS:           true,
		SNI:           "cdn.example.com",
		TransportMode: "stream-one",
	}
	configFile, err := cg.Generate(&engine.Engine{Name: "xray"}, link)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cfg := loadJSON(t, configFile)
	stream := cfg["outbounds"].([]interface{})[0].(map[string]interface{})["streamSettings"].(map[string]interface{})
	if stream["network"] != "xhttp" {
		t.Fatalf("network = %v", stream["network"])
	}
	xh := stream["xhttpSettings"].(map[string]interface{})
	if xh["path"] != "/x" || xh["host"] != "cdn.example.com" || xh["mode"] != "stream-one" {
		t.Fatalf("xhttp settings altered: %v", xh)
	}
}

func mustJSONString(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
