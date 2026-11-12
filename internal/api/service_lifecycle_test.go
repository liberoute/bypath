package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServiceLifecycleAuthenticationAndCSRF(t *testing.T) {
	srv, client, csrf := newRoutingWebTest(t, nil)
	for _, path := range []string{"/service/restart", "/proxy/apply"} {
		status, _, _ := webDo(t, client, http.MethodPost, srv.URL+"/api/v1/app"+path, map[string]interface{}{"confirm": true}, nil, nil)
		if status != http.StatusForbidden {
			t.Fatalf("%s without CSRF = %d", path, status)
		}
	}
	status, body, _ := webDo(t, client, http.MethodPost, srv.URL+"/api/v1/app/service/restart", map[string]bool{"confirm": true}, csrfHeaders(csrf), nil)
	if status != http.StatusNotImplemented {
		t.Fatalf("local restart = %d: %v", status, body)
	}
	wantCode(t, body, "unsupported")
	anonymous := newWebClient(t)
	status, _, _ = webDo(t, anonymous, http.MethodGet, srv.URL+"/api/v1/app/service/operation?id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil, nil, nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated operation poll = %d", status)
	}
}
func TestLifecycleStrictStructuredRequests(t *testing.T) {
	for _, body := range []string{`{"confirm":true,"unit":"ssh.service"}`, `{"confirm":true} {}`, `{"socks_port":1080,"executable":"/bin/sh"}`, `null`, `[]`} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		var req struct {
			Confirm bool `json:"confirm"`
		}
		if decodeLifecycle(w, r, &req, 1024) {
			t.Fatalf("unsafe body accepted: %s", body)
		}
	}
}
func TestGenericSettingsRejectSOCKSPatch(t *testing.T) {
	srv, client, csrf := newRoutingWebTest(t, nil)
	for _, field := range []string{"socks_port", "socks_listen", "socks_allow_lan"} {
		status, _, _ := webDo(t, client, http.MethodPatch, srv.URL+"/api/v1/app/settings", map[string]interface{}{field: 1080}, csrfHeaders(csrf), nil)
		if status != http.StatusBadRequest {
			t.Fatalf("generic %s patch = %d", field, status)
		}
	}
}
