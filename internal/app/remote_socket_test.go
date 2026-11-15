//go:build !windows

package app

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/control"
)

func TestRemoteOverControlSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	ln, err := control.Listen(path, "")
	if err != nil {
		t.Fatalf("control.Listen: %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/app/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("socket client sent an API token")
		}
		json.NewEncoder(w).Encode(Status{State: "CONNECTED", ActiveLink: "node-a"})
	})
	srv := &http.Server{Handler: mux}
	go func() { srv.Serve(ln) }()
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	st, err := NewRemoteSocket(path).Status(ctx)
	if err != nil {
		t.Fatalf("status over socket: %v", err)
	}
	if st.State != "CONNECTED" || st.ActiveLink != "node-a" {
		t.Fatalf("unexpected status: %+v", st)
	}
}

func TestOpenControlSocketDiscovery(t *testing.T) {
	if svc, ok, err := openControlSocket(""); svc != nil || ok || err != nil {
		t.Fatalf("empty path = (%v, %v, %v), want (nil, false, nil)", svc, ok, err)
	}

	// No daemon: discovery declines quietly so config-based discovery can run.
	missing := filepath.Join(t.TempDir(), "missing.sock")
	if svc, ok, err := openControlSocket(missing); svc != nil || ok || err != nil {
		t.Fatalf("missing socket = (%v, %v, %v), want (nil, false, nil)", svc, ok, err)
	}

	path := filepath.Join(t.TempDir(), "live.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	// The file exists but nothing answers it: still a fallback, not an error.
	if svc, ok, err := openControlSocket(path); svc != nil || ok || err != nil {
		t.Fatalf("stale socket = (%v, %v, %v), want (nil, false, nil)", svc, ok, err)
	}
}

func TestOpenControlSocketPermissionError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses filesystem permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "control.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := os.Chmod(path, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(path, 0600)

	_, _, err = openControlSocket(path)
	if err == nil {
		t.Fatal("permission-denied socket was not reported")
	}
	if CodeOf(err) != CodeUnauthorized {
		t.Fatalf("code = %q, want %q (err: %v)", CodeOf(err), CodeUnauthorized, err)
	}
	if !strings.Contains(err.Error(), control.GroupName) {
		t.Fatalf("error does not name the granting group: %v", err)
	}
}
