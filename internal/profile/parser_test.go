package profile

import (
	"testing"
)

func TestParseVmess(t *testing.T) {
	// Standard vmess base64 JSON
	uri := "vmess://eyJ2IjoiMiIsInBzIjoidGVzdC1zZXJ2ZXIiLCJhZGQiOiIxLjIuMy40IiwicG9ydCI6NDQzLCJpZCI6IjEyMzQ1Njc4LTEyMzQtMTIzNC0xMjM0LTEyMzQ1Njc4OTBhYiIsImFpZCI6MCwic2N5IjoiYXV0byIsIm5ldCI6IndzIiwiaG9zdCI6ImV4YW1wbGUuY29tIiwicGF0aCI6Ii93cyIsInRscyI6InRscyIsInNuaSI6ImV4YW1wbGUuY29tIn0="

	link, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI failed: %v", err)
	}

	if link.Protocol != "vmess" {
		t.Errorf("protocol: got %s", link.Protocol)
	}
	if link.Address != "1.2.3.4" {
		t.Errorf("address: got %s", link.Address)
	}
	if link.Port != 443 {
		t.Errorf("port: got %d", link.Port)
	}
	if link.UUID != "12345678-1234-1234-1234-1234567890ab" {
		t.Errorf("uuid: got %s", link.UUID)
	}
	if link.Network != "ws" {
		t.Errorf("network: got %s", link.Network)
	}
	if link.TLS != true {
		t.Error("tls should be true")
	}
	if link.SNI != "example.com" {
		t.Errorf("sni: got %s", link.SNI)
	}
	if link.Path != "/ws" {
		t.Errorf("path: got %s", link.Path)
	}
	if link.Remark != "test-server" {
		t.Errorf("remark: got %s", link.Remark)
	}
}

func TestParseVless(t *testing.T) {
	uri := "vless://uuid-1234@example.com:443?type=ws&security=tls&sni=example.com&path=/vless#my-vless"

	link, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI failed: %v", err)
	}

	if link.Protocol != "vless" {
		t.Errorf("protocol: got %s", link.Protocol)
	}
	if link.Address != "example.com" {
		t.Errorf("address: got %s", link.Address)
	}
	if link.Port != 443 {
		t.Errorf("port: got %d", link.Port)
	}
	if link.UUID != "uuid-1234" {
		t.Errorf("uuid: got %s", link.UUID)
	}
	if link.Network != "ws" {
		t.Errorf("network: got %s", link.Network)
	}
	if link.TLS != true {
		t.Error("tls should be true")
	}
	if link.Remark != "my-vless" {
		t.Errorf("remark: got %s", link.Remark)
	}
}

func TestParseTrojan(t *testing.T) {
	uri := "trojan://mypassword@server.com:8443?type=grpc&sni=server.com#trojan-server"

	link, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI failed: %v", err)
	}

	if link.Protocol != "trojan" {
		t.Errorf("protocol: got %s", link.Protocol)
	}
	if link.Address != "server.com" {
		t.Errorf("address: got %s", link.Address)
	}
	if link.Port != 8443 {
		t.Errorf("port: got %d", link.Port)
	}
	if link.UUID != "mypassword" {
		t.Errorf("password: got %s", link.UUID)
	}
	if link.TLS != true {
		t.Error("trojan should always have TLS")
	}
}

func TestParseShadowsocks(t *testing.T) {
	// ss://base64(method:password)@host:port#remark
	uri := "ss://YWVzLTI1Ni1nY206bXlwYXNz@1.2.3.4:8388#ss-test"

	link, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI failed: %v", err)
	}

	if link.Protocol != "shadowsocks" {
		t.Errorf("protocol: got %s", link.Protocol)
	}
	if link.Address != "1.2.3.4" {
		t.Errorf("address: got %s", link.Address)
	}
	if link.Port != 8388 {
		t.Errorf("port: got %d", link.Port)
	}
	if link.Security != "aes-256-gcm" {
		t.Errorf("method: got %s", link.Security)
	}
}

func TestParseWireguard(t *testing.T) {
	uri := "wireguard://privatekey123@wg.server.com:51820?publickey=pubkey456#wg-test"

	link, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI failed: %v", err)
	}

	if link.Protocol != "wireguard" {
		t.Errorf("protocol: got %s", link.Protocol)
	}
	if link.Address != "wg.server.com" {
		t.Errorf("address: got %s", link.Address)
	}
	if link.Port != 51820 {
		t.Errorf("port: got %d", link.Port)
	}
	if link.PrivateKey != "privatekey123" {
		t.Errorf("private_key: got %s", link.PrivateKey)
	}
	if link.PublicKey != "pubkey456" {
		t.Errorf("public_key: got %s", link.PublicKey)
	}
}

func TestParseUnsupported(t *testing.T) {
	_, err := ParseURI("http://not-a-proxy.com")
	if err == nil {
		t.Error("expected error for unsupported protocol")
	}
}

func TestParseEmpty(t *testing.T) {
	_, err := ParseURI("")
	if err == nil {
		t.Error("expected error for empty URI")
	}
}
