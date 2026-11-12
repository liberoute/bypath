//go:build !windows

package api

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/control"
)

func TestControlSocketServesAppWithoutToken(t *testing.T) {
	_, _, server := newTestServerWith(t, "tok", nil)
	path := filepath.Join(t.TempDir(), "control.sock")

	ln, err := control.Listen(path, "")
	if err != nil {
		t.Fatalf("control.Listen: %v", err)
	}
	srv := &http.Server{Handler: server.localRouter}
	go srv.Serve(ln)
	defer srv.Close()

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
		Timeout: 3 * time.Second,
	}
	resp, err := client.Get("http://bypath.local/api/v1/app/status")
	if err != nil {
		t.Fatalf("GET over control socket: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %s, body: %s", resp.Status, body)
	}
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if out["state"] == "" {
		t.Fatalf("status response missing state: %+v", out)
	}
}
