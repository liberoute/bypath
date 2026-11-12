package profile

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestP5SyntheticURIFixtures(t *testing.T) {
	vmess := `{"v":"2","ps":"synthetic","add":"192.0.2.10","port":"443","id":"11111111-1111-1111-1111-111111111111","aid":0,"scy":"auto","network":"h2","host":"front.example.invalid","path":"/fixture","tls":"tls","peer":"tls.example.invalid","fingerprint":"chrome","alpn":["h2","http/1.1"]}`
	fixtures := []struct {
		name, uri, protocol, network string
		tls                          bool
	}{
		{"vmess JSON", "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(vmess)), "vmess", "h2", true},
		{"vmess userinfo", "vmess://auto:11111111-1111-1111-1111-111111111111@192.0.2.10:443?network=ws&security=tls&peer=tls.example.invalid&fingerprint=chrome&alpn=h2,http%2F1.1&path=%2Ffixture&host=front.example.invalid", "vmess", "ws", true},
		{"vless ws aliases", "vless://11111111-1111-1111-1111-111111111111@192.0.2.10:443?network=websocket&security=tls&peer=tls.example.invalid&fingerprint=chrome&alpn=h2,http%2F1.1&path=%2Ffixture&host=front.example.invalid", "vless", "ws", true},
		{"trojan grpc aliases", "trojan://synthetic-password@192.0.2.10:443?network=grpc&peer=tls.example.invalid&fingerprint=chrome&alpn=h2,http%2F1.1&serviceName=fixture", "trojan", "grpc", true},
		{"vless h2", "vless://11111111-1111-1111-1111-111111111111@192.0.2.10:443?type=http2&security=tls&path=%2Ffixture&host=front.example.invalid", "vless", "h2", true},
		{"reality", "vless://11111111-1111-1111-1111-111111111111@192.0.2.10:443?network=grpc&security=reality&serviceName=fixture&pbk=synthetic-public-key&sid=abcd&fp=chrome&sni=tls.example.invalid&spx=%2Ffixture", "vless", "grpc", true},
		{"xhttp", "vless://11111111-1111-1111-1111-111111111111@[2001:db8::10]:443?network=splithttp&security=tls&mode=stream-up&extra=%7B%22xPaddingBytes%22%3A%22100-200%22%7D&path=%2Ffixture", "vless", "xhttp", true},
		{"SS userinfo", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:synthetic-password")) + "@192.0.2.10:8388", "shadowsocks", "tcp", false},
		{"SS legacy", "ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:synthetic-password@[2001:db8::10]:8388")), "shadowsocks", "tcp", false},
		{"SS plaintext", "ss://aes-128-gcm:synthetic-password@192.0.2.10:8388", "shadowsocks", "tcp", false},
		{"https auth", "https://synthetic-user:synthetic-password@192.0.2.10:443?peer=tls.example.invalid&fingerprint=chrome&alpn=h2,http%2F1.1", "http", "tcp", true},
		{"SOCKS auth", "socks5://synthetic-user:synthetic-password@[2001:db8::10]:1080", "socks5", "tcp", false},
	}
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			link, err := ParseURI(f.uri)
			if err != nil {
				t.Fatal(err)
			}
			if link.Protocol != f.protocol || link.Network != f.network || link.TLS != f.tls || link.Insecure || link.Port <= 0 {
				t.Fatalf("fixture fields lost: %+v", link)
			}
			if strings.Contains(f.uri, "fingerprint=") || f.name == "vmess JSON" {
				if link.SNI != "tls.example.invalid" || link.Fingerprint != "chrome" || !reflect.DeepEqual(link.ALPN, []string{"h2", "http/1.1"}) {
					t.Fatal("TLS aliases/ALPN dropped")
				}
			}
			if f.network == "grpc" && link.GRPCServiceName != "fixture" {
				t.Fatal("gRPC serviceName dropped")
			}
			if f.network == "xhttp" && (link.TransportMode != "stream-up" || link.ExtraJSON == "") {
				t.Fatal("XHTTP options dropped")
			}
			data, err := json.Marshal(link)
			if err != nil {
				t.Fatal(err)
			}
			var restored Link
			if json.Unmarshal(data, &restored) != nil || !reflect.DeepEqual(*link, restored) {
				t.Fatal("model round-trip lost parameters")
			}
		})
	}
}

func TestP5CertificateDefaultsAndExplicitFlag(t *testing.T) {
	for _, scheme := range []string{"vless", "trojan", "vmess", "https"} {
		prefix := scheme + "://synthetic-user@192.0.2.10:443?security=tls"
		for _, flag := range []string{"", "&insecure=0", "&allowInsecure=false", "&insecure=true", "&allowInsecure=1"} {
			link, err := ParseURI(prefix + flag)
			if err != nil {
				t.Fatal(err)
			}
			want := flag == "&insecure=true" || flag == "&allowInsecure=1"
			if link.Insecure != want {
				t.Fatalf("%s flag %q got insecure=%v", scheme, flag, link.Insecure)
			}
		}
	}
}

func TestP5DetailedDiagnosticsAreSanitizedAndComplete(t *testing.T) {
	content := "# synthetic\n" + "vless://fixture@192.0.2.10:443?security=tls\n" +
		"vless://synthetic-secret@192.0.2.10:65536?security=tls\n" +
		"trojan://synthetic-secret@192.0.2.10:443?network=kcp&plugin=synthetic-secret\n" +
		"vmess://not-json-synthetic-secret\n" +
		"unknown://synthetic-secret@192.0.2.10:443\n" +
		"ss://aes-128-gcm:synthetic-secret@192.0.2.10:8388?plugin=synthetic-secret\n" +
		"vless://synthetic-secret@192.0.2.10:443?network=xhttp&extra=synthetic-secret\n"
	for _, body := range []string{content, base64.RawURLEncoding.EncodeToString([]byte(content))} {
		links, diagnostics, err := ParseSubscriptionDetailed(body)
		if err != nil || len(links) != 1 || len(diagnostics) != 6 {
			t.Fatalf("accepted=%d rejected=%d err=%v", len(links), len(diagnostics), err)
		}
		for i, d := range diagnostics {
			if d.Line != i+3 || strings.Contains(d.Message, "synthetic-secret") || d.Message == "" {
				t.Fatalf("unsafe or incomplete diagnostic %+v", d)
			}
		}
		data, _ := json.Marshal(diagnostics)
		if strings.Contains(string(data), "synthetic-secret") || strings.Contains(string(data), "192.0.2") {
			t.Fatal("diagnostics exposed input")
		}
	}
	for _, uri := range []string{"vless://@192.0.2.10:443", "trojan://fixture@:443", "https://fixture@192.0.2.10:0", "vless://fixture@[invalid-ip]:443", "vless://fixture@192.0.2.10:443?security=tls&insecure=garbage", "vless://fixture@192.0.2.10:443?type=grpc&serviceName=fixture&unknown=synthetic-secret"} {
		if _, err := ParseURI(uri); err == nil {
			t.Fatal("malformed/unmapped URI accepted")
		} else if strings.Contains(err.Error(), "synthetic-secret") {
			t.Fatal("error leaked query")
		}
	}
}
