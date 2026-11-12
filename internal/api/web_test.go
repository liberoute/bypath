package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/config"
)

const (
	webTestUser = "admin"
	webTestPass = "correct horse battery"
)

func newWebTest(t *testing.T) (*httptest.Server, *webAPI) {
	t.Helper()
	return newWebTestOpts(t, config.WebConfig{})
}

func newWebTestOpts(t *testing.T, web config.WebConfig) (*httptest.Server, *webAPI) {
	t.Helper()
	web.Enabled = true
	if web.Listen == "" {
		web.Listen = "127.0.0.1"
	}
	if web.Port == 0 {
		web.Port = 18080
	}
	srv, _, server := newTestServerWith(t, "", func(cfg *config.Config) {
		cfg.Server.Web = web
	})
	srv.Close()
	if server.web == nil {
		t.Fatalf("web API did not initialize: %v", server.webErr)
	}
	// The shared helper exercises the unprivileged setup path so results do not
	// depend on whether the test runner is root. The privileged path has its own
	// test below.
	server.web.privileged = false
	server.web.setupCode = ""
	webSrv := httptest.NewServer(server.web.router)
	t.Cleanup(webSrv.Close)
	return webSrv, server.web
}

func newWebClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

// webDo performs one JSON request and decodes an object body. The response is
// returned so tests can inspect cookies and headers.
func webDo(t *testing.T, client *http.Client, method, url string, payload interface{}, headers map[string]string, mutate func(*http.Request)) (int, map[string]interface{}, *http.Response) {
	t.Helper()
	var reader io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if mutate != nil {
		mutate(req)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]interface{}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("%s %s: non-object body %q: %v", method, url, raw, err)
		}
	}
	return resp.StatusCode, body, resp
}

func wantCode(t *testing.T, body map[string]interface{}, code string) {
	t.Helper()
	if got, _ := body["code"].(string); got != code {
		t.Fatalf("error code = %q, want %q (body %v)", got, code, body)
	}
}

func sessionCookieOf(resp *http.Response) string {
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookieName {
			return c.Value
		}
	}
	return ""
}

func webSetup(t *testing.T, client *http.Client, base string) (csrf, cookie string) {
	t.Helper()
	status, body, resp := webDo(t, client, http.MethodPost, base+"/api/v1/web/setup",
		map[string]string{"username": webTestUser, "password": webTestPass}, nil, nil)
	if status != http.StatusCreated {
		t.Fatalf("setup status = %d, want 201 (body %v)", status, body)
	}
	csrf, _ = body["csrf"].(string)
	cookie = sessionCookieOf(resp)
	if csrf == "" || cookie == "" {
		t.Fatalf("setup did not return a CSRF token and session cookie: %v", body)
	}
	return csrf, cookie
}

// A root daemon must not let any local account claim the administrator account.
// The setup code (root-only file) or the API token is required, and the code is
// consumed by the successful setup.
func TestPrivilegedSetupRequiresCode(t *testing.T) {
	srv, web := newWebTest(t)
	web.privileged = true
	web.setupCode = "TEST-CODE-123456"
	codePath := filepath.Join(t.TempDir(), "setup-code")
	if err := os.WriteFile(codePath, []byte(web.setupCode), 0600); err != nil {
		t.Fatal(err)
	}
	web.setupCodePath = codePath
	base := srv.URL
	client := newWebClient(t)

	status, body, _ := webDo(t, client, http.MethodGet, base+"/api/v1/web/session", nil, nil, nil)
	if status != http.StatusOK || body["setup_code_required"] != true {
		t.Fatalf("session info did not advertise the setup code: %d %v", status, body)
	}

	status, body, _ = webDo(t, client, http.MethodPost, base+"/api/v1/web/setup",
		map[string]string{"username": webTestUser, "password": webTestPass}, nil, nil)
	if status != http.StatusForbidden {
		t.Fatalf("setup without code = %d, want 403 (body %v)", status, body)
	}
	wantCode(t, body, "setup_forbidden")

	status, body, _ = webDo(t, client, http.MethodPost, base+"/api/v1/web/setup",
		map[string]string{"username": webTestUser, "password": webTestPass, "setup_code": "WRONG-CODE-999"}, nil, nil)
	if status != http.StatusForbidden {
		t.Fatalf("setup with wrong code = %d, want 403 (body %v)", status, body)
	}

	status, body, resp := webDo(t, client, http.MethodPost, base+"/api/v1/web/setup",
		map[string]string{"username": webTestUser, "password": webTestPass, "setup_code": web.setupCode}, nil, nil)
	if status != http.StatusCreated {
		t.Fatalf("setup with code = %d, want 201 (body %v)", status, body)
	}
	if csrf, _ := body["csrf"].(string); csrf == "" || sessionCookieOf(resp) == "" {
		t.Fatalf("setup with code did not create a session: %v", body)
	}
	if _, err := os.Stat(codePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("setup code file still exists after setup: %v", err)
	}
}

func pemBlock(label, marker string) string {
	return "-----BEGIN " + label + "-----\n" +
		base64.StdEncoding.EncodeToString([]byte(marker)) + "\n" +
		"-----END " + label + "-----"
}

func TestWebSetupLoginFlow(t *testing.T) {
	srv, _ := newWebTest(t)
	base := srv.URL
	client := newWebClient(t)

	status, body, resp := webDo(t, client, http.MethodGet, base+"/api/v1/web/session", nil, nil, nil)
	if status != http.StatusOK || body["authenticated"] != false || body["setup_required"] != true {
		t.Fatalf("fresh session info = %d %v", status, body)
	}
	if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q", got)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Fatalf("missing CSP header: %q", csp)
	}

	status, body, _ = webDo(t, client, http.MethodPost, base+"/api/v1/web/setup",
		map[string]string{"username": webTestUser, "password": "short"}, nil, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("short password status = %d, want 400", status)
	}
	wantCode(t, body, "invalid")

	csrf, cookie := webSetup(t, client, base)

	status, body, _ = webDo(t, client, http.MethodPost, base+"/api/v1/web/setup",
		map[string]string{"username": webTestUser, "password": webTestPass}, nil, nil)
	if status != http.StatusConflict {
		t.Fatalf("second setup status = %d, want 409", status)
	}
	wantCode(t, body, "already_configured")

	status, body, _ = webDo(t, newWebClient(t), http.MethodGet, base+"/api/v1/app/status", nil, nil, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("status without session = %d, want 401", status)
	}
	wantCode(t, body, "unauthenticated")

	importBody := map[string]string{"group": "default", "uri": apiTestVLESS}
	status, body, _ = webDo(t, client, http.MethodPost, base+"/api/v1/app/connections/import", importBody, nil, nil)
	if status != http.StatusForbidden {
		t.Fatalf("import without CSRF = %d, want 403", status)
	}
	wantCode(t, body, "csrf")

	status, body, _ = webDo(t, client, http.MethodPost, base+"/api/v1/app/connections/import", importBody,
		map[string]string{"X-CSRF-Token": csrf}, nil)
	if status != http.StatusCreated {
		t.Fatalf("import with CSRF = %d, want 201 (body %v)", status, body)
	}

	status, body, _ = webDo(t, newWebClient(t), http.MethodPost, base+"/api/v1/web/login",
		map[string]string{"username": webTestUser, "password": "wrong password"}, nil, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong login = %d, want 401", status)
	}
	wantCode(t, body, "invalid_credentials")

	status, body, _ = webDo(t, newWebClient(t), http.MethodPost, base+"/api/v1/web/login",
		map[string]string{"username": webTestUser, "password": webTestPass}, nil, nil)
	loginCSRF, _ := body["csrf"].(string)
	if status != http.StatusOK || loginCSRF == "" || loginCSRF == csrf {
		t.Fatalf("login = %d %v", status, body)
	}

	status, _, _ = webDo(t, client, http.MethodPost, base+"/api/v1/web/logout", nil,
		map[string]string{"X-CSRF-Token": csrf}, nil)
	if status != http.StatusNoContent {
		t.Fatalf("logout = %d, want 204", status)
	}

	status, _, _ = webDo(t, newWebClient(t), http.MethodGet, base+"/api/v1/app/status", nil,
		map[string]string{"Cookie": sessionCookieName + "=" + cookie}, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("logged-out cookie = %d, want 401", status)
	}
}

func TestWebLoginThrottle(t *testing.T) {
	srv, web := newWebTest(t)
	base := srv.URL
	webSetup(t, newWebClient(t), base)

	clock := time.Now()
	web.now = func() time.Time { return clock }

	bad := map[string]string{"username": webTestUser, "password": "not the password"}
	for i := 1; i <= 5; i++ {
		status, _, _ := webDo(t, newWebClient(t), http.MethodPost, base+"/api/v1/web/login", bad, nil, nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("failed attempt %d = %d, want 401", i, status)
		}
	}

	good := map[string]string{"username": webTestUser, "password": webTestPass}
	status, body, resp := webDo(t, newWebClient(t), http.MethodPost, base+"/api/v1/web/login", good, nil, nil)
	if status != http.StatusTooManyRequests {
		t.Fatalf("blocked login = %d, want 429 (body %v)", status, body)
	}
	if retry := resp.Header.Get("Retry-After"); retry == "" {
		t.Fatal("429 response is missing Retry-After")
	}

	clock = clock.Add(31 * time.Second)
	status, body, _ = webDo(t, newWebClient(t), http.MethodPost, base+"/api/v1/web/login", good, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("login after cooldown = %d, want 200 (body %v)", status, body)
	}
}

func TestWebHostAndOriginGuards(t *testing.T) {
	srv, _ := newWebTest(t)
	base := srv.URL
	authed := newWebClient(t)
	csrf, _ := webSetup(t, authed, base)
	creds := map[string]string{"username": webTestUser, "password": webTestPass}

	status, body, _ := webDo(t, newWebClient(t), http.MethodPost, base+"/api/v1/web/login", creds,
		map[string]string{"Origin": "https://evil.example"}, nil)
	if status != http.StatusForbidden {
		t.Fatalf("cross-origin login = %d, want 403", status)
	}
	wantCode(t, body, "origin_not_allowed")

	status, body, _ = webDo(t, newWebClient(t), http.MethodPost, base+"/api/v1/web/login", creds,
		map[string]string{"Sec-Fetch-Site": "cross-site"}, nil)
	if status != http.StatusForbidden {
		t.Fatalf("cross-site login = %d, want 403", status)
	}
	wantCode(t, body, "origin_not_allowed")

	status, body, _ = webDo(t, newWebClient(t), http.MethodGet, base+"/api/v1/web/health", nil, nil,
		func(r *http.Request) { r.Host = "evil.example" })
	if status != http.StatusForbidden {
		t.Fatalf("rebinding host = %d, want 403", status)
	}
	wantCode(t, body, "host_not_allowed")

	// Same-origin writes are accepted, here a logout carrying the session.
	status, _, _ = webDo(t, authed, http.MethodPost, base+"/api/v1/web/logout", nil,
		map[string]string{"X-CSRF-Token": csrf, "Origin": base}, nil)
	if status != http.StatusNoContent {
		t.Fatalf("same-origin logout = %d, want 204", status)
	}
}

func TestWebAllowedOriginsForReverseProxy(t *testing.T) {
	srv, _ := newWebTestOpts(t, config.WebConfig{
		AllowedOrigins: []string{"https://panel.example.net"},
	})
	base := srv.URL

	status, body, _ := webDo(t, newWebClient(t), http.MethodGet, base+"/api/v1/web/session", nil, nil,
		func(r *http.Request) { r.Host = "panel.example.net" })
	if status != http.StatusOK {
		t.Fatalf("configured host = %d, want 200 (body %v)", status, body)
	}

	status, body, _ = webDo(t, newWebClient(t), http.MethodPost, base+"/api/v1/web/logout", nil,
		map[string]string{"Origin": "https://panel.example.net"}, nil)
	if status != http.StatusNoContent {
		t.Fatalf("allowlisted origin logout = %d, want 204 (body %v)", status, body)
	}
}

func TestWebSessionExpiry(t *testing.T) {
	srv, web := newWebTest(t)
	base := srv.URL
	client := newWebClient(t)
	webSetup(t, client, base)

	clock := time.Now()
	web.now = func() time.Time { return clock }
	clock = clock.Add(13 * time.Hour)

	status, body, _ := webDo(t, client, http.MethodGet, base+"/api/v1/app/status", nil, nil, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("expired session = %d, want 401 (body %v)", status, body)
	}
	wantCode(t, body, "unauthenticated")
}

func TestWebPasswordChangeRotatesSessions(t *testing.T) {
	srv, _ := newWebTest(t)
	base := srv.URL
	client := newWebClient(t)
	csrf, oldCookie := webSetup(t, client, base)
	const newPass = "an even longer passphrase"

	status, body, _ := webDo(t, client, http.MethodPost, base+"/api/v1/web/password",
		map[string]string{"current_password": webTestPass, "new_password": newPass},
		map[string]string{"X-CSRF-Token": csrf}, nil)
	if status != http.StatusOK {
		t.Fatalf("password change = %d, want 200 (body %v)", status, body)
	}
	freshCSRF, _ := body["csrf"].(string)
	if freshCSRF == "" || freshCSRF == csrf {
		t.Fatalf("password change did not rotate the CSRF token: %v", body)
	}

	status, _, _ = webDo(t, newWebClient(t), http.MethodGet, base+"/api/v1/app/status", nil,
		map[string]string{"Cookie": sessionCookieName + "=" + oldCookie}, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("pre-change cookie = %d, want 401", status)
	}

	status, body, _ = webDo(t, newWebClient(t), http.MethodPost, base+"/api/v1/web/login",
		map[string]string{"username": webTestUser, "password": webTestPass}, nil, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("old password login = %d, want 401", status)
	}

	status, body, _ = webDo(t, newWebClient(t), http.MethodPost, base+"/api/v1/web/login",
		map[string]string{"username": webTestUser, "password": newPass}, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("new password login = %d, want 200 (body %v)", status, body)
	}
}

func TestWebOVPNUploads(t *testing.T) {
	srv, _ := newWebTest(t)
	base := srv.URL
	client := newWebClient(t)
	csrf, _ := webSetup(t, client, base)
	headers := map[string]string{"X-CSRF-Token": csrf}

	profileText := strings.Join([]string{
		"client",
		"dev tun",
		"proto udp",
		"remote vpn.upload.example 1194",
		"ca ca.crt",
		"cert client.crt",
		"key client.key",
	}, "\n")
	refs := []map[string]string{
		{"name": "ca.crt", "content": pemBlock("CERTIFICATE", "ca-marker")},
		{"name": "client.crt", "content": pemBlock("CERTIFICATE", "cert-marker")},
		{"name": "client.key", "content": pemBlock("PRIVATE KEY", "key-marker-secret")},
	}

	status, body, _ := webDo(t, client, http.MethodPost, base+"/api/v1/app/connections/ovpn/preview",
		map[string]interface{}{"path": "/etc/passwd", "text": profileText}, headers, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("server path preview = %d, want 400 (body %v)", status, body)
	}
	wantCode(t, body, app.CodeInvalid)
	if msg, _ := body["message"].(string); !strings.Contains(msg, "file paths are not accepted") {
		t.Fatalf("server path message = %q", msg)
	}

	status, body, _ = webDo(t, client, http.MethodPost, base+"/api/v1/app/connections/ovpn/preview",
		map[string]interface{}{
			"text": profileText,
			"refs": []map[string]string{{"name": "../evil.crt", "content": pemBlock("CERTIFICATE", "x")}},
		}, headers, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("traversal ref preview = %d, want 400 (body %v)", status, body)
	}
	wantCode(t, body, app.CodeInvalid)

	status, body, _ = webDo(t, client, http.MethodPost, base+"/api/v1/app/connections/ovpn/preview",
		map[string]interface{}{"text": profileText, "refs": refs}, headers, nil)
	if status != http.StatusOK {
		t.Fatalf("upload preview = %d, want 200 (body %v)", status, body)
	}
	if body["host"] != "vpn.upload.example" {
		t.Fatalf("preview host = %v", body["host"])
	}
	certFiles, _ := body["cert_files"].([]interface{})
	if len(certFiles) != 3 {
		t.Fatalf("preview cert_files = %v", body["cert_files"])
	}

	status, body, _ = webDo(t, client, http.MethodPost, base+"/api/v1/app/connections/ovpn/import",
		map[string]interface{}{
			"group": "default",
			"name":  "web-upload",
			"text":  profileText,
			"refs":  refs,
		}, headers, nil)
	if status != http.StatusCreated {
		t.Fatalf("upload import = %d, want 201 (body %v)", status, body)
	}
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), "key-marker-secret") {
		t.Fatal("import response leaked private key material")
	}

	status, body, _ = webDo(t, client, http.MethodGet, base+"/api/v1/app/connections", nil, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("list connections = %d, want 200", status)
	}
	list, _ := body["connections"].([]interface{})
	if len(list) != 1 {
		t.Fatalf("connections = %v", body["connections"])
	}
	conn, _ := list[0].(map[string]interface{})
	if conn["protocol"] != "openvpn" || conn["remark"] != "web-upload" || conn["address"] != "vpn.upload.example" {
		t.Fatalf("imported connection = %v", conn)
	}
}

func TestWebPanelServesEmbeddedUI(t *testing.T) {
	srv, _ := newWebTest(t)
	base := srv.URL

	get := func(path string, mutate func(*http.Request)) (*http.Response, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, base+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if mutate != nil {
			mutate(req)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp, string(body)
	}

	resp, page := get("/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("index = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("index content type = %q", ct)
	}
	for _, needle := range []string{"/app.css", "/app.js", "BYPATH", `id="auth-login"`} {
		if !strings.Contains(page, needle) {
			t.Fatalf("index is missing %q", needle)
		}
	}
	if strings.Contains(page, "<script>") {
		t.Fatal("index uses an inline script, which the CSP forbids")
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("CSP still allows inline content: %q", csp)
	}

	resp, script := get("/app.js", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "javascript") {
		t.Fatalf("app.js = %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(script, "/api/v1/web/session") {
		t.Fatal("app.js does not boot from the session endpoint")
	}
	if strings.Contains(script, "localStorage") {
		t.Fatal("the panel must not store data in localStorage")
	}
	// The only cross-reload state is the opaque supervised-operation id, which
	// survives the panel vanishing during a restart and carries no credentials.
	for _, line := range strings.Split(script, "\n") {
		if strings.Contains(line, "sessionStorage") && !strings.Contains(line, "operationKey") {
			t.Fatalf("web storage used for something other than the operation id: %q", strings.TrimSpace(line))
		}
	}

	resp, css := get("/app.css", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Header.Get("Content-Type"), "text/css") {
		t.Fatalf("app.css = %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	// The panel toggles the hidden attribute on sections that also carry an
	// author display rule, so the stylesheet itself has to honor it.
	if !strings.Contains(css, "[hidden] { display: none !important; }") {
		t.Fatal("app.css does not let the hidden attribute win over author display rules")
	}

	// A reload of a hash route hits an unknown path and must still boot.
	resp, page = get("/connections", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "BYPATH") {
		t.Fatalf("document fallback = %d", resp.StatusCode)
	}

	resp, body := get("/api/v1/web/does-not-exist", nil)
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, `"not_found"`) {
		t.Fatalf("unknown API path = %d %s", resp.StatusCode, body)
	}

	resp, _ = get("/", func(r *http.Request) { r.Host = "evil.example" })
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("panel with rebinding host = %d, want 403", resp.StatusCode)
	}

	// Writes to the document path are not a thing.
	req, _ := http.NewRequest(http.MethodPost, base+"/", strings.NewReader(""))
	respPost, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer respPost.Body.Close()
	if respPost.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST / = %d, want 405", respPost.StatusCode)
	}
}

func TestAuthMiddlewareRequiresLoopbackWithoutToken(t *testing.T) {
	handler := NewAuthMiddleware("").Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:4444"
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("remote request without token = %d, want 401", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:4444"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("loopback request without token = %d, want 200", rec.Code)
	}

	tokenHandler := NewAuthMiddleware("tok").Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.5:4444"
	req.Header.Set("Authorization", "Bearer tok")
	rec = httptest.NewRecorder()
	tokenHandler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("remote request with token = %d, want 200", rec.Code)
	}
}

func TestValidateWebExposurePolicy(t *testing.T) {
	cases := []struct {
		name    string
		web     config.WebConfig
		wantErr bool
	}{
		{"loopback", config.WebConfig{Listen: "127.0.0.1", Port: 18080}, false},
		{"localhost", config.WebConfig{Listen: "localhost", Port: 18080}, false},
		{"lan without opt-in", config.WebConfig{Listen: "0.0.0.0", Port: 18080}, true},
		{"lan with opt-in", config.WebConfig{Listen: "0.0.0.0", Port: 18080, AllowLAN: true}, false},
		{"port out of range", config.WebConfig{Listen: "127.0.0.1", Port: 0}, true},
		{"origin without scheme", config.WebConfig{Listen: "127.0.0.1", Port: 18080, AllowedOrigins: []string{"panel.example.net"}}, true},
		{"origin with path", config.WebConfig{Listen: "127.0.0.1", Port: 18080, AllowedOrigins: []string{"https://panel.example.net/app"}}, true},
		{"valid origin", config.WebConfig{Listen: "127.0.0.1", Port: 18080, AllowedOrigins: []string{"https://panel.example.net"}}, false},
		{"valid proxy socket", config.WebConfig{Listen: "127.0.0.1", Port: 18080, Socket: "/run/bypath/web.sock"}, false},
		{"relative proxy socket", config.WebConfig{Listen: "127.0.0.1", Port: 18080, Socket: "run/web.sock"}, true},
		{"unclean proxy socket", config.WebConfig{Listen: "127.0.0.1", Port: 18080, Socket: "/run/bypath/../web.sock"}, true},
		{"socket is a directory", config.WebConfig{Listen: "127.0.0.1", Port: 18080, Socket: os.TempDir()}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := config.ValidateWeb(tc.web)
			if tc.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNewServerDisablesInvalidWebConfig(t *testing.T) {
	srv, _, server := newTestServerWith(t, "", func(cfg *config.Config) {
		cfg.Server.Web = config.WebConfig{Enabled: true, Listen: "0.0.0.0", Port: 18080}
	})
	defer srv.Close()
	if server.web != nil {
		t.Fatal("web panel should not start when the exposure policy is violated")
	}
	if server.webErr == nil {
		t.Fatal("expected the configuration error to be recorded")
	}
}
