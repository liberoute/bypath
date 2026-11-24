package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/liberoute/bypath/internal/config"
)

func routingAPIRules() []config.RoutingRule {
	return []config.RoutingRule{
		{Match: "geoip:de", Outbound: "direct"},
		{Match: "domain_suffix:de", Outbound: "direct"},
		{Match: "default", Outbound: "proxy"},
	}
}

// newRoutingWebTest builds the browser-facing server (session + CSRF) with a
// routing.rules policy, which is the surface the panel actually calls.
func newRoutingWebTest(t *testing.T, rules []config.RoutingRule) (*httptest.Server, *http.Client, string) {
	t.Helper()
	web := config.WebConfig{Enabled: true, Listen: "127.0.0.1", Port: 18080}
	srv, _, server := newTestServerWith(t, "", func(cfg *config.Config) {
		cfg.Server.Web = web
		cfg.Routing.Rules = rules
	})
	srv.Close()
	if server.web == nil {
		t.Fatalf("web API did not initialize: %v", server.webErr)
	}
	server.web.privileged = false
	server.web.setupCode = ""
	webSrv := httptest.NewServer(server.web.router)
	t.Cleanup(webSrv.Close)
	client := newWebClient(t)
	csrf, _ := webSetup(t, client, webSrv.URL)
	return webSrv, client, csrf
}

func csrfHeaders(csrf string) map[string]string {
	return map[string]string{"X-CSRF-Token": csrf}
}

func TestRoutingAPIOverviewAndExplain(t *testing.T) {
	srv, client, _ := newRoutingWebTest(t, routingAPIRules())

	status, body, _ := webDo(t, client, http.MethodGet, srv.URL+"/api/v1/app/routing", nil, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("overview status %d: %v", status, body)
	}
	if body["mode"] != "rules" || body["can_edit"] != true {
		t.Fatalf("overview not editable: %v", body)
	}
	if body["default_outbound"] != "proxy" {
		t.Fatalf("default outbound %v", body["default_outbound"])
	}
	if revision, _ := body["revision"].(string); len(revision) != 16 {
		t.Fatalf("revision missing from overview: %v", body["revision"])
	}

	target := url.QueryEscape("https://example.com/path")
	status, body, _ = webDo(t, client, http.MethodGet, srv.URL+"/api/v1/app/routing/explain?target="+target, nil, nil, nil)
	if status != http.StatusOK {
		t.Fatalf("explain status %d: %v", status, body)
	}
	if body["target"] != "example.com" || body["outcome"] != "PROXY" {
		t.Fatalf("unexpected explanation: %v", body)
	}

	status, body, _ = webDo(t, client, http.MethodGet, srv.URL+"/api/v1/app/routing/explain", nil, nil, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("explain without target = %d, want 400 (body %v)", status, body)
	}
	wantCode(t, body, "invalid_argument")
}

func TestRoutingAPIApplyRequiresConfirmationAndRevision(t *testing.T) {
	srv, client, csrf := newRoutingWebTest(t, routingAPIRules())
	headers := csrfHeaders(csrf)

	edit := map[string]interface{}{
		"force":  []map[string]string{{"match": "domain:blocked.example", "outbound": "block"}},
		"direct": []map[string]string{},
	}
	status, preview, _ := webDo(t, client, http.MethodPost, srv.URL+"/api/v1/app/routing/preview",
		map[string]interface{}{"edit": edit}, headers, nil)
	if status != http.StatusOK {
		t.Fatalf("preview status %d: %v", status, preview)
	}
	revision, _ := preview["revision"].(string)
	if revision == "" {
		t.Fatalf("preview returned no revision: %v", preview)
	}
	if rules, _ := preview["rules"].([]interface{}); len(rules) == 0 {
		t.Fatalf("preview returned no rules: %v", preview)
	}

	status, body, _ := webDo(t, client, http.MethodPost, srv.URL+"/api/v1/app/routing/apply",
		map[string]interface{}{"edit": edit, "revision": revision}, headers, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("apply without confirmation = %d, want 400 (body %v)", status, body)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "confirmed") {
		t.Fatalf("confirmation error message %q", msg)
	}

	status, body, _ = webDo(t, client, http.MethodPost, srv.URL+"/api/v1/app/routing/apply",
		map[string]interface{}{"edit": edit, "confirmed": true}, headers, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("apply without a revision = %d, want 400 (body %v)", status, body)
	}

	status, body, _ = webDo(t, client, http.MethodPost, srv.URL+"/api/v1/app/routing/apply",
		map[string]interface{}{"edit": edit, "revision": "deadbeefdeadbeef", "confirmed": true}, headers, nil)
	if status != http.StatusConflict {
		t.Fatalf("stale revision = %d, want 409 (body %v)", status, body)
	}
	wantCode(t, body, "conflict")

	status, change, _ := webDo(t, client, http.MethodPost, srv.URL+"/api/v1/app/routing/apply",
		map[string]interface{}{"edit": edit, "revision": revision, "note": "api test", "confirmed": true}, headers, nil)
	if status != http.StatusOK {
		t.Fatalf("apply status %d: %v", status, change)
	}
	if change["applied"] != true || change["snapshot"] == "" {
		t.Fatalf("apply did not persist with a snapshot: %v", change)
	}

	status, body, _ = webDo(t, client, http.MethodPost, srv.URL+"/api/v1/app/routing/rollback",
		map[string]interface{}{"snapshot": change["snapshot"], "confirmed": true}, headers, nil)
	if status != http.StatusOK || body["applied"] != true {
		t.Fatalf("rollback status %d: %v", status, body)
	}
}

func TestRoutingAPIRejectsMissingCSRF(t *testing.T) {
	srv, client, _ := newRoutingWebTest(t, routingAPIRules())
	status, body, _ := webDo(t, client, http.MethodPost, srv.URL+"/api/v1/app/routing/preview",
		map[string]interface{}{"edit": map[string]interface{}{}}, nil, nil)
	if status != http.StatusForbidden {
		t.Fatalf("preview without CSRF = %d, want 403 (body %v)", status, body)
	}
	wantCode(t, body, "csrf")
}

func TestRoutingAPILegacyPolicyIsReadOnly(t *testing.T) {
	srv, client, csrf := newRoutingWebTest(t, nil)

	status, overview, _ := webDo(t, client, http.MethodGet, srv.URL+"/api/v1/app/routing", nil, nil, nil)
	if status != http.StatusOK || overview["mode"] != "legacy" || overview["can_edit"] != false {
		t.Fatalf("legacy overview = %d %v", status, overview)
	}

	status, body, _ := webDo(t, client, http.MethodPost, srv.URL+"/api/v1/app/routing/preview",
		map[string]interface{}{"edit": map[string]interface{}{}}, csrfHeaders(csrf), nil)
	if status != http.StatusBadRequest {
		t.Fatalf("legacy preview = %d, want 400 (body %v)", status, body)
	}
	wantCode(t, body, "invalid_argument")
}

func TestRoutingAPITestRouteBlockedNeedsNoTunnel(t *testing.T) {
	rules := []config.RoutingRule{
		{Match: "ip_cidr:203.0.113.0/24", Outbound: "deny"},
		{Match: "default", Outbound: "proxy"},
	}
	srv, client, csrf := newRoutingWebTest(t, rules)

	status, body, _ := webDo(t, client, http.MethodPost, srv.URL+"/api/v1/app/routing/test",
		map[string]interface{}{"target": "203.0.113.8", "port": 443}, csrfHeaders(csrf), nil)
	if status != http.StatusOK {
		t.Fatalf("test route status %d: %v", status, body)
	}
	if body["verdict"] != "blocked_by_rule" {
		t.Fatalf("verdict %v (%v)", body["verdict"], body["verdict_text"])
	}
	if body["verdict_text"] == "" {
		t.Fatal("verdict has no explanation")
	}
}
