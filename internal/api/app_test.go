package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
)

const apiTestVLESS = "vless://33333333-3333-3333-3333-333333333333@example.net:443?security=tls&type=ws#api-node"

func newTestServer(t *testing.T, token string) (*httptest.Server, *app.Local) {
	t.Helper()
	srv, svc, _ := newTestServerWith(t, token, nil)
	return srv, svc
}

func newTestServerWith(t *testing.T, token string, mutate func(*config.Config)) (*httptest.Server, *app.Local, *Server) {
	t.Helper()
	dir := t.TempDir()
	p := &paths.Resolved{
		Mode:       paths.ModeLocal,
		ConfigFile: filepath.Join(dir, "config.yaml"),
		ProfileDir: filepath.Join(dir, "profiles"),
		TmpDir:     filepath.Join(dir, "tmp"),
	}
	for _, d := range []string{p.ProfileDir, p.TmpDir} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{}
	cfg.Server.Listen = "127.0.0.1"
	cfg.Server.APIPort = 8080
	cfg.Server.APIToken = token
	cfg.Profiles.Directory = p.ProfileDir
	cfg.Profiles.ActiveGroup = "default"
	if mutate != nil {
		mutate(cfg)
	}

	mgr, err := profile.NewManager(p.ProfileDir, "default")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := app.NewLocal(app.Options{Paths: p, Config: cfg, ConfigPath: p.ConfigFile, Profiles: mgr})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(cfg, nil, nil, svc)
	if server.privileged {
		// These tests assert the unprivileged contract (loopback trust without a
		// token). A root test runner gets the privileged refusal by design; that
		// behavior is covered directly in auth_test.go.
		server.privileged = false
		server.router = server.buildRouter(true)
	}
	return httptest.NewServer(server.router), svc, server
}

func TestAppAPIRequiresToken(t *testing.T) {
	srv, _ := newTestServer(t, "tok")
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/v1/app/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/app/status", nil)
	req.Header.Set("Authorization", "Bearer tok")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with token, got %d", resp.StatusCode)
	}
	var st app.Status
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.APIPort != 8080 || st.Running {
		t.Fatalf("unexpected status payload: %+v", st)
	}
}

func TestAppAPIErrorContract(t *testing.T) {
	srv, _ := newTestServer(t, "")
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/v1/app/connections/delete",
		"application/json", strings.NewReader(`{"id":"default:missing"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
	var body map[string]string
	json.NewDecoder(resp.Body).Decode(&body)
	if body["code"] != app.CodeNotFound || body["message"] == "" {
		t.Fatalf("unexpected error body: %+v", body)
	}
}

func TestAppAPIEmptyListsAreArrays(t *testing.T) {
	srv, _ := newTestServer(t, "")
	defer srv.Close()

	for _, path := range []string{
		"/api/v1/app/connections?search=zzz-no-match",
		"/api/v1/app/subscriptions",
	} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]json.RawMessage
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		for key, value := range out {
			if string(value) != "[]" {
				t.Fatalf("%s: %s = %s, want []", path, key, value)
			}
		}
	}
}

func TestAppAPISubscriptionPreview(t *testing.T) {
	srv, svc := newTestServer(t, "")
	defer srv.Close()

	uri := "vless://44444444-4444-4444-4444-444444444444@preview.example.net:443?security=tls&type=ws#preview-node"
	resp, err := http.Post(srv.URL+"/api/v1/app/subscriptions/preview-text",
		"application/json", strings.NewReader(`{"text":"`+uri+`\n"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("preview-text status = %d", resp.StatusCode)
	}
	var preview app.SubscriptionPreview
	if err := json.NewDecoder(resp.Body).Decode(&preview); err != nil {
		t.Fatal(err)
	}
	if preview.Total != 1 || len(preview.Links) != 1 || preview.Links[0].Remark != "preview-node" {
		t.Fatalf("unexpected preview: %+v", preview)
	}
	if subs, _ := svc.ListSubscriptions(context.Background()); len(subs) != 0 {
		t.Fatalf("preview stored a subscription: %+v", subs)
	}

	// The URL endpoint must reject non-http schemes before any fetch is tried.
	resp2, err := http.Post(srv.URL+"/api/v1/app/subscriptions/preview",
		"application/json", strings.NewReader(`{"url":"file:///etc/passwd"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("file:// preview status = %d, want 400", resp2.StatusCode)
	}
	var body map[string]string
	json.NewDecoder(resp2.Body).Decode(&body)
	if body["code"] != app.CodeInvalid {
		t.Fatalf("error code = %q", body["code"])
	}
}

func TestAppAPIImportAndList(t *testing.T) {
	srv, _ := newTestServer(t, "")
	defer srv.Close()

	payload := `{"group":"default","uri":"` + apiTestVLESS + `"}`
	resp, err := http.Post(srv.URL+"/api/v1/app/connections/import",
		"application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d", resp.StatusCode)
	}

	resp, err = http.Get(srv.URL + "/api/v1/app/connections")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Connections []app.Connection `json:"connections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Connections) != 1 || out.Connections[0].Remark != "api-node" {
		t.Fatalf("unexpected connections: %+v", out.Connections)
	}
	if strings.Contains(out.Connections[0].Address, "33333333") {
		t.Fatal("API exposed URI material")
	}

	resp, err = http.Get(srv.URL + "/api/v1/app/connection?id=default%3Aapi-node")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected detail 200, got %d", resp.StatusCode)
	}
}

func TestOpenVPNSourceRejectsServerPaths(t *testing.T) {
	for _, path := range []string{
		"/api/v1/app/connections/ovpn/preview",
		"/api/v1/app/connections/ovpn/import",
	} {
		srv, _ := newTestServer(t, "")
		resp, err := http.Post(srv.URL+path, "application/json",
			strings.NewReader(`{"path":"/etc/shadow","name":"probe"}`))
		if err != nil {
			t.Fatal(err)
		}
		var payload map[string]string
		json.NewDecoder(resp.Body).Decode(&payload)
		resp.Body.Close()
		srv.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("%s: expected 400 for a server-side path, got %d (%+v)", path, resp.StatusCode, payload)
		}
		if !strings.Contains(payload["message"], "paths are not accepted") {
			t.Fatalf("%s: unexpected message %q", path, payload["message"])
		}
	}
}

func TestCreateGroupRejectsTraversalName(t *testing.T) {
	srv, svc, _ := newTestServerWith(t, "", nil)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/v1/profiles/groups", "application/json",
		strings.NewReader(`{"name":"../escape","type":"basic"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for a traversal group name, got %d", resp.StatusCode)
	}
	escaped := filepath.Join(filepath.Dir(svc.Config().Profiles.Directory), "escape.json")
	if _, err := os.Stat(escaped); err == nil {
		t.Fatalf("group file was written outside the profile directory: %s", escaped)
	}
}

// TestAppAPILifecycleRoutesExist guards the two distinct lifecycle endpoints:
// disconnect tears down the tunnel, shutdown stops the daemon. Neither may be a
// missing route that the panel would silently fail to use.
func TestAppAPILifecycleRoutesExist(t *testing.T) {
	srv, _ := newTestServer(t, "")
	defer srv.Close()

	for _, path := range []string{"/api/v1/app/disconnect", "/api/v1/app/shutdown"} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		// Router wording differs between mux configurations (404 vs 405); what
		// matters is that a read request never triggers a lifecycle action.
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("%s: GET was accepted", path)
		}

		resp, err = http.Post(srv.URL+path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		var res app.ActionResult
		decodeErr := json.NewDecoder(resp.Body).Decode(&res)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: POST status = %d, want 200", path, resp.StatusCode)
		}
		if decodeErr != nil {
			t.Fatalf("%s: %v", path, decodeErr)
		}
		if res.Applied {
			t.Fatalf("%s: reported applied without a runtime: %+v", path, res)
		}
	}
}

func TestAppAPIBenchRoute(t *testing.T) {
	srv, _ := newTestServer(t, "")
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/api/v1/app/bench", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("empty profile status = %d, want 404", resp.StatusCode)
	}
	var out struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Code != app.CodeNotFound {
		t.Fatalf("code = %q, want %q", out.Code, app.CodeNotFound)
	}
	if !strings.Contains(out.Message, "no groups") {
		t.Fatalf("message = %q, want the reason", out.Message)
	}
}
