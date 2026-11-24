//go:build full

package engine

import (
	"os"
	"path/filepath"
	"testing"
)

// A uTLS fingerprint makes sing-box compile its uTLS client, which is gated
// behind the with_utls build tag. Release builds that omit the tag fail here
// with "uTLS is not included in this build" and silently fall back to
// downloading an engine, so the tag set must be exercised instead of assumed.
func TestEmbeddedSingBoxStartsUTLSOutbound(t *testing.T) {
	config := `{
  "log": {"level": "error", "disabled": true},
  "outbounds": [
    {
      "type": "vless",
      "tag": "proxy",
      "server": "192.0.2.10",
      "server_port": 443,
      "uuid": "00000000-0000-4000-8000-000000000000",
      "tls": {
        "enabled": true,
        "server_name": "example.com",
        "alpn": ["http/1.1"],
        "utls": {"enabled": true, "fingerprint": "chrome"}
      },
      "transport": {
        "type": "ws",
        "path": "/download",
        "headers": {"Host": "example.com"}
      }
    }
  ]
}`
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	runner, err := newEmbeddedSingBox(path)
	if err != nil {
		t.Fatalf("newEmbeddedSingBox: %v", err)
	}
	// Start constructs the outbound and the TUN-less router without dialing,
	// so success proves the uTLS code was compiled in. If it was not, this
	// fails with "uTLS is not included in this build".
	if err := runner.Start(); err != nil {
		t.Fatalf("embedded sing-box rejected a uTLS outbound: %v", err)
	}
	if !runner.IsRunning() {
		t.Fatal("embedded sing-box reported not running after a successful start")
	}
	if err := runner.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if runner.IsRunning() {
		t.Fatal("embedded sing-box still running after stop")
	}
}
