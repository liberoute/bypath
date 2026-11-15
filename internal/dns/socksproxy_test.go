package dns

import (
	"testing"
)

func TestParseHostPort(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort int
	}{
		{"1.1.1.1:53", "1.1.1.1", 53},
		{"8.8.8.8:5353", "8.8.8.8", 5353},
		{"example.com:53", "example.com", 53},
		{"1.1.1.1", "1.1.1.1", 53}, // no port defaults to 53
	}

	for _, tt := range tests {
		host, port, _ := parseHostPort(tt.input)
		if host != tt.wantHost {
			t.Errorf("parseHostPort(%s) host = %s, want %s", tt.input, host, tt.wantHost)
		}
		if port != tt.wantPort {
			t.Errorf("parseHostPort(%s) port = %d, want %d", tt.input, port, tt.wantPort)
		}
	}
}

func TestNewSOCKSProxy(t *testing.T) {
	p := NewSOCKSProxy("127.0.0.1:15353", "127.0.0.1:1080", "1.1.1.1:53")

	if p.listenAddr != "127.0.0.1:15353" {
		t.Errorf("listenAddr: got %s", p.listenAddr)
	}
	if p.socksAddr != "127.0.0.1:1080" {
		t.Errorf("socksAddr: got %s", p.socksAddr)
	}
	if p.upstream != "1.1.1.1:53" {
		t.Errorf("upstream: got %s", p.upstream)
	}
}
