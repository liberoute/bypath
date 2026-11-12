package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func serveThrough(t *testing.T, mw func(http.Handler) http.Handler, remote string, header map[string]string) int {
	t.Helper()
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/app/status", nil)
	req.RemoteAddr = remote
	for k, v := range header {
		req.Header.Set(k, v)
	}
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

func TestAuthMiddlewareUnprivilegedStillTrustsLoopback(t *testing.T) {
	mw := NewAuthMiddleware("").Middleware
	if code := serveThrough(t, mw, "127.0.0.1:40000", nil); code != http.StatusOK {
		t.Fatalf("unprivileged loopback = %d, want 200", code)
	}
	if code := serveThrough(t, mw, "192.0.2.10:40000", nil); code != http.StatusUnauthorized {
		t.Fatalf("unprivileged remote = %d, want 401", code)
	}
}
