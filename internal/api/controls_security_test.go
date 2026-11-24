package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/config"
)

func TestControlOperationsRequireSessionAndCSRF(t *testing.T) {
	srv, _, server := newTestServerWith(t, "", func(cfg *config.Config) {
		cfg.Server.SOCKSPort = 2801
		cfg.Server.Web = config.WebConfig{Enabled: true, Listen: "127.0.0.1", Port: 8081}
	})
	srv.Close()
	if server.web == nil {
		t.Fatal(server.webErr)
	}
	token, session := server.web.newSession("fixture-operator")
	for _, endpoint := range []string{"/api/v1/app/service/restart", "/api/v1/app/proxy/apply"} {
		for _, tc := range []struct {
			name   string
			cookie string
			csrf   string
			status int
		}{
			{"unauthenticated", "", "", http.StatusUnauthorized},
			{"missing_csrf", token, "", http.StatusForbidden},
			{"invalid_csrf", token, "not-the-session-token", http.StatusForbidden},
		} {
			t.Run(endpoint+"/"+tc.name, func(t *testing.T) {
				r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8081"+endpoint, strings.NewReader(`{"confirm":true}`))
				r.Header.Set("Content-Type", "application/json")
				if tc.cookie != "" {
					r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tc.cookie})
				}
				r.Header.Set("X-CSRF-Token", tc.csrf)
				w := httptest.NewRecorder()
				server.web.router.ServeHTTP(w, r)
				if w.Code != tc.status {
					t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
				}
			})
		}
	}
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8081/api/v1/app/service/restart", strings.NewReader(`{"confirm":true,"command":"reboot","unit":"sshd.service"}`))
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", session.csrf)
	w := httptest.NewRecorder()
	server.web.router.ServeHTTP(w, r)
	if w.Code >= 200 && w.Code < 300 {
		t.Fatalf("local unsupported service accepted caller-controlled operation: %d %s", w.Code, w.Body.String())
	}
}

func TestWebSurfaceDoesNotPublishRawManagementAPI(t *testing.T) {
	srv, _, server := newTestServerWith(t, "", func(cfg *config.Config) {
		cfg.Server.SOCKSPort = 2801
		cfg.Server.Web = config.WebConfig{Enabled: true, Listen: "127.0.0.1", Port: 8081}
	})
	srv.Close()
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8081/api/v1/status", nil)
	w := httptest.NewRecorder()
	server.web.router.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("raw management API leaked onto panel surface: %d", w.Code)
	}
}
