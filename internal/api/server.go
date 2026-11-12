package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/control"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/gateway"
	_ "github.com/liberoute/bypath/internal/metrics" // register metrics
	"github.com/liberoute/bypath/internal/paths"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server is the REST API server for managing Bypath. Every handler is a thin
// adapter over the shared application service; the server owns no business
// logic and no second copy of profile state.
type Server struct {
	config      *config.Config
	gateway     *gateway.Gateway
	engineMgr   *engine.Manager
	svc         *app.Local
	router      *mux.Router
	localRouter *mux.Router
	web         *webAPI
	webErr      error
	// privileged mirrors the effective uid: a root daemon must never trust an
	// unauthenticated loopback TCP client.
	privileged bool
}

// NewServer creates a new API server.
func NewServer(cfg *config.Config, gw *gateway.Gateway, engineMgr *engine.Manager, svc *app.Local) *Server {
	s := &Server{
		config:     cfg,
		gateway:    gw,
		engineMgr:  engineMgr,
		svc:        svc,
		privileged: os.Geteuid() == 0,
	}

	// The TCP API keeps token auth. The Unix socket carries its own access
	// control in the filesystem, so an unprivileged operator never needs the
	// token or the root-owned config to use the same handlers.
	s.router = s.buildRouter(true)
	s.localRouter = s.buildRouter(false)

	if cfg.Server.Web.Enabled && svc != nil {
		web, err := newWebAPI(cfg, svc)
		if err != nil {
			s.webErr = err
			log.Printf("⚠️  Web panel disabled: %v", err)
		} else {
			s.web = web
		}
	}

	return s
}

func (s *Server) buildRouter(requireToken bool) *mux.Router {
	r := mux.NewRouter()
	s.registerRoutesOn(r)
	s.registerAppRoutesOn(r.PathPrefix("/api/v1/app").Subrouter())
	if requireToken {
		r.Use(NewAuthMiddlewareFor(s.config.Server.APIToken, s.privileged).Middleware)
	}
	return r
}

// Start begins listening for API requests. The web panel, when enabled, runs on
// its own loopback-by-default listener so enabling it never widens the
// management API's exposure.
func (s *Server) Start() error {
	if s.web != nil {
		go s.serveWeb()
	}
	if path := paths.Get().ControlSocket; path != "" {
		if ln, err := control.Listen(path, paths.Get().RuntimeRoot); err != nil {
			log.Printf("⚠️  Local control socket unavailable: %v", err)
		} else {
			log.Printf("🔌 Local control socket: %s", path)
			go s.serveControl(ln)
		}
	}
	return s.serve(s.config.Server.Listen, s.config.Server.APIPort, s.router, "API")
}

// serveControl serves the same handlers without the TCP token middleware:
// connecting at all required the kernel to grant access to the socket.
func (s *Server) serveControl(ln net.Listener) {
	srv := &http.Server{
		Handler:           s.localRouter,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		// Lifecycle calls carry a 10-minute budget above the 5-minute gateway
		// startup bound. A shorter write deadline would cut the response of a
		// slow fallback start while the gateway itself is still coming up.
		WriteTimeout:   11 * time.Minute,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 1 << 20,
	}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("❌ Local control socket stopped: %v", err)
	}
}

func (s *Server) serveWeb() {
	addr := net.JoinHostPort(s.config.Server.Web.Listen, strconv.Itoa(s.config.Server.Web.Port))
	scheme := "http"
	log.Printf("🖥️  Web panel: %s://%s (session login required)", scheme, addr)
	if config.IsLoopbackHost(s.config.Server.Web.Listen) {
		log.Printf("   Loopback only. Set server.web.allow_lan: true to serve it on the LAN.")
	}
	if s.config.Server.Web.Socket != "" {
		go s.serveWebSocket(s.config.Server.Web.Socket)
	}
	if s.web.adminMissing() {
		if s.web.privileged && s.web.setupCodePath != "" {
			log.Printf("   No administrator yet: the setup code is in %s (root-only; read it as root)", s.web.setupCodePath)
		} else {
			log.Printf("   No administrator yet: open the panel locally to finish setup.")
		}
	}
	if err := s.serve(s.config.Server.Web.Listen, s.config.Server.Web.Port, s.web.router, "web panel"); err != nil {
		log.Printf("❌ Web panel listener on %s failed: %v", addr, err)
	}
}

// serveWebSocket publishes the panel on a Unix socket for a host-local reverse
// proxy. The gateway's network namespace keeps its loopback private, so a
// proxy on the host can reach the panel only through the shared filesystem.
// The socket is owner/group readable, never world accessible, and no TCP port
// is opened beyond the existing loopback listener.
func (s *Server) serveWebSocket(path string) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		log.Printf("❌ Web panel socket directory failed: %v", err)
		return
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			log.Printf("❌ Web panel socket %s exists and is not a socket", path)
			return
		}
		if err := os.Remove(path); err != nil {
			log.Printf("❌ Web panel socket cleanup failed: %v", err)
			return
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		log.Printf("❌ Web panel socket listen failed: %v", err)
		return
	}
	if err := os.Chmod(path, 0660); err != nil {
		log.Printf("⚠️  Web panel socket permissions: %v", err)
	}
	log.Printf("🖥️  Web panel socket: %s (reverse proxy only)", path)
	srv := &http.Server{
		Handler:           s.web.router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      11 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("❌ Web panel socket stopped: %v", err)
	}
}

func (s *Server) serve(host string, port int, handler http.Handler, label string) error {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	log.Printf("🌐 %s server starting on %s", label, addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		// Must outlast the 10-minute lifecycle budget; see serveControl.
		WriteTimeout:   11 * time.Minute,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 1 << 20,
	}
	err := srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return fmt.Errorf("%s listener: %w", label, err)
}

func (s *Server) registerRoutesOn(router *mux.Router) {
	api := router.PathPrefix("/api/v1").Subrouter()

	// Status
	api.HandleFunc("/status", s.handleStatus).Methods("GET")

	// Profiles
	api.HandleFunc("/profiles/groups", s.handleListGroups).Methods("GET")
	api.HandleFunc("/profiles/groups/{name}", s.handleGetGroup).Methods("GET")
	api.HandleFunc("/profiles/groups", s.handleCreateGroup).Methods("POST")
	api.HandleFunc("/profiles/groups/{name}", s.handleDeleteGroup).Methods("DELETE")
	api.HandleFunc("/profiles/links", s.handleAddLink).Methods("POST")
	api.HandleFunc("/profiles/links/{group}/{remark}", s.handleDeleteLink).Methods("DELETE")

	// Tunnels
	api.HandleFunc("/tunnels", s.handleListTunnels).Methods("GET")
	api.HandleFunc("/tunnels/start", s.handleStartTunnel).Methods("POST")
	api.HandleFunc("/tunnels/{name}/stop", s.handleStopTunnel).Methods("POST")

	// Chains
	api.HandleFunc("/chains", s.handleListChains).Methods("GET")

	// Engines
	api.HandleFunc("/engines", s.handleListEngines).Methods("GET")

	// Subscriptions
	api.HandleFunc("/subscriptions/update/{group}", s.handleUpdateSubscription).Methods("POST")

	// Config
	api.HandleFunc("/config/reload", s.handleConfigReload).Methods("POST")

	// Prometheus metrics. The TCP router applies the API token middleware to
	// every path, this one included, so a tokenless root daemon answers 401.
	// Configure the scraper with the bearer token.
	router.Handle("/metrics", promhttp.Handler()).Methods("GET")
}

// --- Response Helpers ---

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func errorResponse(w http.ResponseWriter, status int, message string) {
	jsonResponse(w, status, map[string]string{"error": message})
}
