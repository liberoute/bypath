package api

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/config"
)

// TestPanelPreviewHarness serves the real management panel on a local port with
// an authenticated session, so the UI can be reviewed in a browser without a
// tunnel, root privileges or a login. It is inert unless BYPATH_PANEL_PREVIEW is
// set, and it never leaves the loopback interface.
//
//	BYPATH_PANEL_PREVIEW=1 go test ./internal/api -run TestPanelPreviewHarness -v
//
// The session cookie and CSRF token are injected by a loopback reverse proxy;
// everything behind it is the production router, embedded assets and handlers.
func TestPanelPreviewHarness(t *testing.T) {
	if os.Getenv("BYPATH_PANEL_PREVIEW") == "" {
		t.Skip("set BYPATH_PANEL_PREVIEW=1 to serve the panel for manual review")
	}
	web := config.WebConfig{Enabled: true, Listen: "127.0.0.1", Port: 18080}
	srv, _, server := newTestServerWith(t, "", func(cfg *config.Config) {
		cfg.Server.Web = web
		cfg.Engines.PreferredEngine = "xray"
		cfg.Gateway.LocalDNS = []config.LocalDNSEntry{{Server: "192.0.2.53", Domains: []string{"home"}}}
		// Mirrors a typical shape: one country direct, named exceptions,
		// everything else through the tunnel.
		cfg.Routing.Rules = []config.RoutingRule{
			{Match: "domain_suffix:de", Outbound: "direct"},
			{Match: "domain_suffix:example.com", Outbound: "direct"},
			{Match: "domain:blocked.example", Outbound: "block"},
			{Match: "default", Outbound: "proxy"},
		}
	})
	srv.Close()
	if server.web == nil {
		t.Fatalf("web API did not initialize: %v", server.webErr)
	}
	server.web.privileged = false
	server.web.setupCode = ""

	token, sess := server.web.newSession("preview")
	upstream := httptest.NewServer(server.web.router)
	defer upstream.Close()
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	director := proxy.Director
	proxy.Director = func(r *http.Request) {
		host := r.Host
		director(r)
		// Keep the browser's Host so the panel's rebinding and origin guards
		// evaluate the request exactly as they would in production.
		r.Host = host
		r.Header.Set("Cookie", sessionCookieName+"="+token)
		if isWriteMethod(r.Method) {
			r.Header.Set("X-CSRF-Token", sess.csrf)
		}
	}

	seconds := 600
	if raw := os.Getenv("BYPATH_PANEL_PREVIEW_SECONDS"); raw != "" {
		if value, err := strconv.Atoi(raw); err == nil && value > 0 && value <= 3600 {
			seconds = value
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:18091")
	if err != nil {
		t.Fatalf("preview port unavailable: %v", err)
	}
	defer ln.Close()
	go func() { _ = http.Serve(ln, proxy) }()
	t.Logf("panel preview: http://127.0.0.1:18091/ (running for %ds)", seconds)

	deadline := time.Now().Add(time.Duration(seconds) * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
	}
}
