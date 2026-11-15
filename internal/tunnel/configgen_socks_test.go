package tunnel

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
)

func vlessTestLink() *profile.Link {
	return &profile.Link{
		Protocol: "vless",
		Address:  "server.example.com",
		Port:     443,
		UUID:     "11111111-2222-3333-4444-555555555555",
		Network:  "tcp",
		TLS:      true,
		SNI:      "server.example.com",
	}
}

// TestSingboxInboundBindsLoopbackByDefault is the regression guard for the
// unauthenticated LAN-wide SOCKS listener.
func TestSingboxInboundBindsLoopbackByDefault(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	inbounds := cg.singboxInbounds(vlessTestLink())
	if len(inbounds) != 1 {
		t.Fatalf("inbounds = %d, want 1", len(inbounds))
	}
	if got := inbounds[0]["listen"]; got != "127.0.0.1" {
		t.Fatalf("listen = %v, want 127.0.0.1", got)
	}
	if _, ok := inbounds[0]["users"]; ok {
		t.Fatal("an unauthenticated inbound emitted users")
	}
}

func TestSingboxInboundLANOptInWithAuth(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.SOCKSListen = "0.0.0.0"
	cg.SOCKSUsername = "operator"
	cg.SOCKSPassword = "s3cret"

	inbounds := cg.singboxInbounds(vlessTestLink())
	if got := inbounds[0]["listen"]; got != "0.0.0.0" {
		t.Fatalf("listen = %v, want 0.0.0.0", got)
	}
	users, ok := inbounds[0]["users"].([]map[string]interface{})
	if !ok || len(users) != 1 {
		t.Fatalf("users = %v, want one entry", inbounds[0]["users"])
	}
	if users[0]["username"] != "operator" || users[0]["password"] != "s3cret" {
		t.Fatalf("unexpected credentials in inbound: %v", users[0])
	}
}

func TestChainInboundBindsLoopbackByDefault(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	file, err := cg.GenerateChainConfig("chain-a", []*profile.Link{vlessTestLink(), vlessTestLink()})
	if err != nil {
		t.Fatalf("GenerateChainConfig: %v", err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	inbounds := cfg["inbounds"].([]interface{})
	inbound := inbounds[0].(map[string]interface{})
	if got := inbound["listen"]; got != "127.0.0.1" {
		t.Fatalf("chain inbound listen = %v, want 127.0.0.1", got)
	}
}

func TestXrayInboundBindsLoopbackByDefault(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	file, err := cg.Generate(&engine.Engine{Name: "xray"}, vlessTestLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	inbound := readFirstInbound(t, file)
	if got := inbound["listen"]; got != "127.0.0.1" {
		t.Fatalf("xray listen = %v, want 127.0.0.1", got)
	}
	settings := inbound["settings"].(map[string]interface{})
	if settings["auth"] != "noauth" {
		t.Fatalf("xray auth = %v, want noauth", settings["auth"])
	}
}

func TestXrayInboundEmitsSOCKSCredentials(t *testing.T) {
	cg := NewConfigGenerator(t.TempDir())
	cg.SOCKSListen = "0.0.0.0"
	cg.SOCKSUsername = "operator"
	cg.SOCKSPassword = "s3cret"

	file, err := cg.Generate(&engine.Engine{Name: "xray"}, vlessTestLink())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	inbound := readFirstInbound(t, file)
	settings := inbound["settings"].(map[string]interface{})
	if settings["auth"] != "password" {
		t.Fatalf("xray auth = %v, want password", settings["auth"])
	}
	accounts := settings["accounts"].([]interface{})
	account := accounts[0].(map[string]interface{})
	if account["user"] != "operator" || account["pass"] != "s3cret" {
		t.Fatalf("unexpected xray account: %v", account)
	}
}

func readFirstInbound(t *testing.T, file string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	inbounds, ok := cfg["inbounds"].([]interface{})
	if !ok || len(inbounds) == 0 {
		t.Fatalf("no inbounds in %s", file)
	}
	return inbounds[0].(map[string]interface{})
}
