//go:build !windows

package api

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/config"
)

// TestWebSocketServesThePanel pins the reverse-proxy contract: the panel is
// reachable over a Unix socket with owner/group-only permissions, so a host
// proxy can cross the gateway's network namespace without a TCP port.
func TestWebSocketServesThePanel(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "run", "web.sock")
	_, _, server := newTestServerWith(t, "", func(cfg *config.Config) {
		cfg.Server.Web = config.WebConfig{
			Enabled: true,
			Listen:  "127.0.0.1",
			Port:    18080,
			Socket:  socket,
		}
	})
	go server.serveWebSocket(socket)

	var info os.FileInfo
	deadline := time.Now().Add(5 * time.Second)
	for {
		var err error
		info, err = os.Stat(socket)
		if err == nil && info.Mode()&os.ModeSocket != 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("socket %s was not created: %v", socket, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	if perm := info.Mode().Perm(); perm != 0660 {
		t.Fatalf("socket permissions = %o, want 660", perm)
	}
	dirInfo, err := os.Stat(filepath.Dir(socket))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Fatalf("socket directory permissions = %o, want 700", perm)
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)
	resp, err := client.Get("http://127.0.0.1/api/v1/web/health")
	if err != nil {
		t.Fatalf("health over socket: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, body %s", resp.StatusCode, body)
	}
	if strings.TrimSpace(string(body)) != `{"status":"ok"}` {
		t.Fatalf("health body = %s", body)
	}
}
