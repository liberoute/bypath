package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serveThroughHost(t *testing.T, mw func(http.Handler) http.Handler, remote, host string, header map[string]string) int {
	t.Helper()
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/app/status", nil)
	req.RemoteAddr = remote
	req.Host = host
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

func serveThrough(t *testing.T, mw func(http.Handler) http.Handler, remote string, header map[string]string) int {
	t.Helper()
	return serveThroughHost(t, mw, remote, "127.0.0.1:8080", header)
}

func serveMutation(t *testing.T, mw func(http.Handler) http.Handler, contentType, body string) int {
	t.Helper()
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	var req *http.Request
	if reader == nil {
		req = httptest.NewRequest(http.MethodPost, "/api/v1/app/connections/delete", nil)
	} else {
		req = httptest.NewRequest(http.MethodPost, "/api/v1/app/connections/delete", reader)
		req.Header.Set("Content-Type", contentType)
	}
	req.Host = "127.0.0.1:8080"
	req.Header.Set("Authorization", "Bearer tok")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

func TestAuthMiddlewarePrivilegedRefusesTokenlessTCP(t *testing.T) {
	mw := NewAuthMiddlewareFor("", true).Middleware
	if code := serveThrough(t, mw, "127.0.0.1:40000", nil); code != http.StatusUnauthorized {
		t.Fatalf("privileged tokenless loopback = %d, want 401", code)
	}
	if code := serveThrough(t, mw, "192.0.2.10:40000", nil); code != http.StatusUnauthorized {
		t.Fatalf("privileged tokenless remote = %d, want 401", code)
	}
}

func TestAuthMiddlewarePrivilegedAcceptsConfiguredToken(t *testing.T) {
	mw := NewAuthMiddlewareFor("tok", true).Middleware
	if code := serveThrough(t, mw, "127.0.0.1:40000", map[string]string{"Authorization": "Bearer tok"}); code != http.StatusOK {
		t.Fatalf("privileged token request = %d, want 200", code)
	}
	if code := serveThrough(t, mw, "127.0.0.1:40000", map[string]string{"Authorization": "Bearer wrong"}); code != http.StatusUnauthorized {
		t.Fatalf("privileged wrong token = %d, want 401", code)
	}
}

// R2-09/P3: a tokenless management API is not supported on Unix. Loopback is
// not an authentication boundary, so both loopback and remote callers are
// refused and the daemon must be configured with server.api_token.
func TestAuthMiddlewareRefusesTokenlessLoopback(t *testing.T) {
	mw := NewAuthMiddleware("").Middleware
	if code := serveThrough(t, mw, "127.0.0.1:40000", nil); code != http.StatusUnauthorized {
		t.Fatalf("tokenless loopback = %d, want 401", code)
	}
	if code := serveThrough(t, mw, "192.0.2.10:40000", nil); code != http.StatusUnauthorized {
		t.Fatalf("tokenless remote = %d, want 401", code)
	}
}

func TestAuthMiddlewareRefusesTokenlessForeignHost(t *testing.T) {
	mw := NewAuthMiddleware("").Middleware
	// A DNS-rebinding page reaches loopback but keeps the attacker's hostname.
	if code := serveThroughHost(t, mw, "127.0.0.1:40000", "attacker.example", nil); code != http.StatusForbidden {
		t.Fatalf("tokenless foreign Host = %d, want 403", code)
	}
}

func TestAuthMiddlewareRejectsCrossSiteOrigin(t *testing.T) {
	mw := NewAuthMiddlewareFor("tok", false).Middleware
	for _, origin := range []string{"https://evil.example", "null", "http://attacker.example:8080"} {
		header := map[string]string{"Origin": origin, "Authorization": "Bearer tok"}
		if code := serveThrough(t, mw, "127.0.0.1:40000", header); code != http.StatusForbidden {
			t.Fatalf("origin %q = %d, want 403", origin, code)
		}
	}
	header := map[string]string{"Origin": "http://127.0.0.1:18080", "Authorization": "Bearer tok"}
	if code := serveThrough(t, mw, "127.0.0.1:40000", header); code != http.StatusOK {
		t.Fatalf("loopback origin with token = %d, want 200", code)
	}
}

func TestAuthMiddlewareRequiresJSONForMutationBody(t *testing.T) {
	mw := NewAuthMiddlewareFor("tok", false).Middleware
	if code := serveMutation(t, mw, "application/x-www-form-urlencoded", `id=default:missing`); code != http.StatusUnsupportedMediaType {
		t.Fatalf("urlencoded mutation = %d, want 415", code)
	}
	if code := serveMutation(t, mw, "text/plain", `{"id":"default:missing"}`); code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain mutation = %d, want 415", code)
	}
	if code := serveMutation(t, mw, "application/json", `{"id":"default:missing"}`); code != http.StatusOK {
		t.Fatalf("JSON mutation = %d, want 200", code)
	}
	if code := serveMutation(t, mw, "", ""); code != http.StatusOK {
		t.Fatalf("bodyless mutation = %d, want 200", code)
	}
}

// Windows has no control socket, so its loopback API stays the local channel.
// The carve-out still demands a loopback Host and refuses cross-site origins.
func TestAuthMiddlewareLocalTrustStillChecksRequestShape(t *testing.T) {
	mw := newAuthMiddlewareLocalTrust("", false).Middleware
	if code := serveThrough(t, mw, "127.0.0.1:40000", nil); code != http.StatusOK {
		t.Fatalf("local trust loopback = %d, want 200", code)
	}
	if code := serveThroughHost(t, mw, "127.0.0.1:40000", "attacker.example", nil); code != http.StatusForbidden {
		t.Fatalf("local trust foreign Host = %d, want 403", code)
	}
	if code := serveThrough(t, mw, "127.0.0.1:40000", map[string]string{"Origin": "https://evil.example"}); code != http.StatusForbidden {
		t.Fatalf("local trust cross-site origin = %d, want 403", code)
	}
}

func TestTokenlessTCPListenerPolicy(t *testing.T) {
	cases := []struct {
		name          string
		token         string
		controlSocket string
		want          bool
	}{
		{"unix tokenless is refused", "", "/run/bypath/control.sock", false},
		{"unix with token", "tok", "/run/bypath/control.sock", true},
		{"windows has no control socket", "", "", true},
		{"windows with token", "tok", "", true},
	}
	for _, tc := range cases {
		if got := tokenlessTCPAllowed(tc.token, tc.controlSocket); got != tc.want {
			t.Fatalf("%s: tokenlessTCPAllowed(%q, %q) = %v, want %v", tc.name, tc.token, tc.controlSocket, got, tc.want)
		}
	}
}
