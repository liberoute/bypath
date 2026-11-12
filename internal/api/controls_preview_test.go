package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/liberoute/bypath/internal/config"
)

func TestControlsPreviewHarness(t *testing.T) {
	if os.Getenv("BYPATH_CONTROLS_PREVIEW") == "" {
		t.Skip("set BYPATH_CONTROLS_PREVIEW for isolated browser acceptance")
	}
	fixture := "vless://33333333-3333-3333-3333-333333333333@192.0.2.10:443?security=tls&type=ws&host=fixture.example&path=%2Fsocket#Fixture-WS\n"
	sub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(fixture))
	}))
	defer sub.Close()
	srv, svc, server := newTestServerWith(t, "", func(cfg *config.Config) {
		cfg.Server.SOCKSPort = 2801
		cfg.Server.DNSPort = 53
		cfg.Server.Web = config.WebConfig{Enabled: true, Listen: "127.0.0.1", Port: 18125}
	})
	srv.Close()
	if _, err := svc.ImportURI(context.Background(), "manual", "vless://44444444-4444-4444-4444-444444444444@192.0.2.11:443?security=tls&type=tcp#Manual-TLS"); err != nil {
		t.Fatal(err)
	}
	server.web.privileged = false
	server.web.setupCode = ""
	token, session := server.web.newSession("fixture-operator")
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
		r.Host = host
		r.Header.Set("Cookie", sessionCookieName+"="+token)
		if isWriteMethod(r.Method) {
			r.Header.Set("X-CSRF-Token", session.csrf)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:18125")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/fixture-url", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(sub.URL + "#Fixture-News"))
	})
	mux.Handle("/", proxy)
	go func() { _ = http.Serve(ln, mux) }()
	t.Log("controls preview: http://127.0.0.1:18125/ (real embedded router; synthetic session only)")
	<-time.After(20 * time.Minute)
}
