package tunnel

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
)

func TestGenerateSingBoxVmess(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)

	eng := &engine.Engine{Name: "sing-box"}
	link := &profile.Link{
		Protocol: "vmess",
		Address:  "1.2.3.4",
		Port:     443,
		UUID:     "test-uuid",
		Security: "auto",
		Network:  "ws",
		Path:     "/ws",
		Host:     "example.com",
		TLS:      true,
		SNI:      "example.com",
	}

	configFile, err := cg.Generate(eng, link)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Read and validate JSON
	data, err := os.ReadFile(configFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("Invalid JSON: %v", err)
	}

	// Check structure
	if _, ok := cfg["inbounds"]; !ok {
		t.Error("missing inbounds")
	}
	if _, ok := cfg["outbounds"]; !ok {
		t.Error("missing outbounds")
	}

	outbounds := cfg["outbounds"].([]interface{})
	if len(outbounds) < 1 {
		t.Fatal("no outbounds")
	}

	proxy := outbounds[0].(map[string]interface{})
	if proxy["type"] != "vmess" {
		t.Errorf("outbound type: got %v", proxy["type"])
	}
	if proxy["server"] != "1.2.3.4" {
		t.Errorf("server: got %v", proxy["server"])
	}
}

func TestGenerateXrayVless(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)

	eng := &engine.Engine{Name: "xray"}
	link := &profile.Link{
		Protocol: "vless",
		Address:  "server.com",
		Port:     443,
		UUID:     "vless-uuid",
		Network:  "tcp",
		TLS:      true,
		SNI:      "server.com",
	}

	configFile, err := cg.Generate(eng, link)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	data, _ := os.ReadFile(configFile)
	var cfg map[string]interface{}
	json.Unmarshal(data, &cfg)

	outbounds := cfg["outbounds"].([]interface{})
	proxy := outbounds[0].(map[string]interface{})
	if proxy["protocol"] != "vless" {
		t.Errorf("protocol: got %v", proxy["protocol"])
	}
}

func TestGenerateWireGuard(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)

	eng := &engine.Engine{Name: "wireguard-go"}
	link := &profile.Link{
		Protocol:   "wireguard",
		Address:    "wg.server.com",
		Port:       51820,
		PrivateKey: "privkey123",
		PublicKey:  "pubkey456",
		Remark:     "wg-test",
	}

	configFile, err := cg.Generate(eng, link)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	data, _ := os.ReadFile(configFile)
	content := string(data)

	if !strings.Contains(content, "PrivateKey = privkey123") {
		t.Error("missing PrivateKey")
	}
	if !strings.Contains(content, "PublicKey = pubkey456") {
		t.Error("missing PublicKey")
	}
	if !strings.Contains(content, "Endpoint = wg.server.com:51820") {
		t.Error("missing Endpoint")
	}
}

func TestGenerateUnsupported(t *testing.T) {
	tmpDir := t.TempDir()
	cg := NewConfigGenerator(tmpDir)

	eng := &engine.Engine{Name: "unknown-engine"}
	link := &profile.Link{Protocol: "vmess"}

	_, err := cg.Generate(eng, link)
	if err == nil {
		t.Error("expected error for unsupported engine")
	}
}
