package profile

import (
	"encoding/json"
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

func TestParseSSH(t *testing.T) {
	t.Run("key-based", func(t *testing.T) {
		uri := "ssh://root@myserver.com:22?key=/etc/bypath/keys/id_rsa#my-ssh-server"

		link, err := ParseURI(uri)
		if err != nil {
			t.Fatalf("ParseURI failed: %v", err)
		}

		if link.Protocol != "ssh" {
			t.Errorf("protocol: got %s, want ssh", link.Protocol)
		}
		if link.Address != "myserver.com" {
			t.Errorf("address: got %s, want myserver.com", link.Address)
		}
		if link.Port != 22 {
			t.Errorf("port: got %d, want 22", link.Port)
		}
		if link.SSHUser != "root" {
			t.Errorf("ssh_user: got %s, want root", link.SSHUser)
		}
		if link.SSHPassword != "" {
			t.Errorf("ssh_password: got %s, want empty", link.SSHPassword)
		}
		if link.SSHKeyPath != "/etc/bypath/keys/id_rsa" {
			t.Errorf("ssh_key_path: got %s, want /etc/bypath/keys/id_rsa", link.SSHKeyPath)
		}
		if link.Remark != "my-ssh-server" {
			t.Errorf("remark: got %s, want my-ssh-server", link.Remark)
		}
	})

	t.Run("password-based", func(t *testing.T) {
		uri := "ssh://user:password123@10.0.0.1:2222#office-relay"

		link, err := ParseURI(uri)
		if err != nil {
			t.Fatalf("ParseURI failed: %v", err)
		}

		if link.Protocol != "ssh" {
			t.Errorf("protocol: got %s, want ssh", link.Protocol)
		}
		if link.Address != "10.0.0.1" {
			t.Errorf("address: got %s, want 10.0.0.1", link.Address)
		}
		if link.Port != 2222 {
			t.Errorf("port: got %d, want 2222", link.Port)
		}
		if link.SSHUser != "user" {
			t.Errorf("ssh_user: got %s, want user", link.SSHUser)
		}
		if link.SSHPassword != "password123" {
			t.Errorf("ssh_password: got %s, want password123", link.SSHPassword)
		}
		if link.SSHKeyPath != "" {
			t.Errorf("ssh_key_path: got %s, want empty", link.SSHKeyPath)
		}
		if link.Remark != "office-relay" {
			t.Errorf("remark: got %s, want office-relay", link.Remark)
		}
	})

	t.Run("minimal-defaults-port", func(t *testing.T) {
		uri := "ssh://admin@192.168.1.1#home-router"

		link, err := ParseURI(uri)
		if err != nil {
			t.Fatalf("ParseURI failed: %v", err)
		}

		if link.Protocol != "ssh" {
			t.Errorf("protocol: got %s, want ssh", link.Protocol)
		}
		if link.Address != "192.168.1.1" {
			t.Errorf("address: got %s, want 192.168.1.1", link.Address)
		}
		if link.Port != 22 {
			t.Errorf("port: got %d, want 22 (default)", link.Port)
		}
		if link.SSHUser != "admin" {
			t.Errorf("ssh_user: got %s, want admin", link.SSHUser)
		}
		if link.SSHPassword != "" {
			t.Errorf("ssh_password: got %s, want empty", link.SSHPassword)
		}
		if link.SSHKeyPath != "" {
			t.Errorf("ssh_key_path: got %s, want empty", link.SSHKeyPath)
		}
		if link.Remark != "home-router" {
			t.Errorf("remark: got %s, want home-router", link.Remark)
		}
	})

	t.Run("no-user-defaults-to-root", func(t *testing.T) {
		uri := "ssh://host.com:22#test"

		link, err := ParseURI(uri)
		if err != nil {
			t.Fatalf("ParseURI failed: %v", err)
		}

		if link.Protocol != "ssh" {
			t.Errorf("protocol: got %s, want ssh", link.Protocol)
		}
		if link.Address != "host.com" {
			t.Errorf("address: got %s, want host.com", link.Address)
		}
		if link.Port != 22 {
			t.Errorf("port: got %d, want 22", link.Port)
		}
		if link.SSHUser != "root" {
			t.Errorf("ssh_user: got %s, want root (default)", link.SSHUser)
		}
		if link.SSHPassword != "" {
			t.Errorf("ssh_password: got %s, want empty", link.SSHPassword)
		}
		if link.SSHKeyPath != "" {
			t.Errorf("ssh_key_path: got %s, want empty", link.SSHKeyPath)
		}
		if link.Remark != "test" {
			t.Errorf("remark: got %s, want test", link.Remark)
		}
	})
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

func TestParseSSH_RoundTrip(t *testing.T) {
	// Parse an SSH URI, serialize to JSON, deserialize back, and verify all fields are preserved.
	uri := "ssh://admin:s3cret@bastion.example.com:2222?key=/home/user/.ssh/id_ed25519#bastion-server"

	original, err := ParseURI(uri)
	if err != nil {
		t.Fatalf("ParseURI failed: %v", err)
	}

	// Serialize to JSON
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	// Deserialize back
	var restored Link
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	// Verify all SSH-specific fields survived the round-trip
	if restored.Protocol != "ssh" {
		t.Errorf("protocol: got %q, want %q", restored.Protocol, "ssh")
	}
	if restored.Address != "bastion.example.com" {
		t.Errorf("address: got %q, want %q", restored.Address, "bastion.example.com")
	}
	if restored.Port != 2222 {
		t.Errorf("port: got %d, want %d", restored.Port, 2222)
	}
	if restored.SSHUser != "admin" {
		t.Errorf("ssh_user: got %q, want %q", restored.SSHUser, "admin")
	}
	if restored.SSHPassword != "s3cret" {
		t.Errorf("ssh_password: got %q, want %q", restored.SSHPassword, "s3cret")
	}
	if restored.SSHKeyPath != "/home/user/.ssh/id_ed25519" {
		t.Errorf("ssh_key_path: got %q, want %q", restored.SSHKeyPath, "/home/user/.ssh/id_ed25519")
	}
	if restored.Remark != "bastion-server" {
		t.Errorf("remark: got %q, want %q", restored.Remark, "bastion-server")
	}
	if restored.RawURI != uri {
		t.Errorf("raw_uri: got %q, want %q", restored.RawURI, uri)
	}
}
