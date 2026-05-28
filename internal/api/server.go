package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/gateway"
)

// Server is the REST API server for managing Liberoute.
type Server struct {
	config    *config.Config
	gateway   *gateway.Gateway
	engineMgr *engine.Manager
	router    *mux.Router
}

// NewServer creates a new API server.
func NewServer(cfg *config.Config, gw *gateway.Gateway, engineMgr *engine.Manager) *Server {
	s := &Server{
		config:    cfg,
		gateway:   gw,
		engineMgr: engineMgr,
		router:    mux.NewRouter(),
	}

	s.registerRoutes()
	return s
}

// Start begins listening for API requests.
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Server.Listen, s.config.Server.APIPort)
	log.Printf("🌐 API server starting on %s", addr)
	return http.ListenAndServe(addr, s.router)
}

func (s *Server) registerRoutes() {
	api := s.router.PathPrefix("/api/v1").Subrouter()

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

	// Whitelist
	api.HandleFunc("/whitelist/stats", s.handleWhitelistStats).Methods("GET")
	api.HandleFunc("/whitelist/check/{ip}", s.handleWhitelistCheck).Methods("GET")

	// Engines
	api.HandleFunc("/engines", s.handleListEngines).Methods("GET")

	// Subscriptions
	api.HandleFunc("/subscriptions/update/{group}", s.handleUpdateSubscription).Methods("POST")
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
