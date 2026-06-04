package api

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/liberoute/bypath/internal/build"
	"github.com/liberoute/bypath/internal/profile"
)

// --- Status ---

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	tunnelStatus := s.gateway.GetTunnelManager().GetStatus()
	chainStatus := s.gateway.GetTunnelManager().GetChainStatus()
	whitelistStats := s.gateway.GetWhitelistManager().GetStats()

	status := map[string]interface{}{
		"version":   build.Version,
		"tunnels":   tunnelStatus,
		"chains":    chainStatus,
		"whitelist": whitelistStats,
	}

	jsonResponse(w, http.StatusOK, status)
}

// --- Profiles ---

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	pm := s.gateway.GetProfileManager()
	groups := pm.ListGroups()
	jsonResponse(w, http.StatusOK, map[string]interface{}{"groups": groups})
}

func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	pm := s.gateway.GetProfileManager()
	group, err := pm.GetGroup(name)
	if err != nil {
		errorResponse(w, http.StatusNotFound, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, group)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		errorResponse(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Type == "" {
		req.Type = "basic"
	}

	pm := s.gateway.GetProfileManager()
	if err := pm.CreateGroup(req.Name, req.Type); err != nil {
		errorResponse(w, http.StatusConflict, err.Error())
		return
	}

	jsonResponse(w, http.StatusCreated, map[string]string{"message": "group created"})
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	pm := s.gateway.GetProfileManager()
	if err := pm.DeleteGroup(name); err != nil {
		errorResponse(w, http.StatusNotFound, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{"message": "group deleted"})
}

// --- Links ---

func (s *Server) handleAddLink(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Group string `json:"group"`
		URI   string `json:"uri"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.URI == "" {
		errorResponse(w, http.StatusBadRequest, "uri is required")
		return
	}
	if req.Group == "" {
		req.Group = "default"
	}

	// Parse the URI
	link, err := profile.ParseURI(req.URI)
	if err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid link URI: "+err.Error())
		return
	}

	pm := s.gateway.GetProfileManager()
	if err := pm.AddLink(req.Group, link); err != nil {
		errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonResponse(w, http.StatusCreated, map[string]interface{}{
		"message":  "link added",
		"remark":   link.Remark,
		"protocol": link.Protocol,
	})
}

func (s *Server) handleDeleteLink(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	group := vars["group"]
	remark := vars["remark"]

	pm := s.gateway.GetProfileManager()
	if err := pm.RemoveLink(group, remark); err != nil {
		errorResponse(w, http.StatusNotFound, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{"message": "link deleted"})
}

// --- Tunnels ---

func (s *Server) handleListTunnels(w http.ResponseWriter, r *http.Request) {
	status := s.gateway.GetTunnelManager().GetStatus()
	jsonResponse(w, http.StatusOK, map[string]interface{}{"tunnels": status})
}

func (s *Server) handleStartTunnel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		Profile string `json:"profile"`
		Engine  string `json:"engine"`
		Isolate bool   `json:"isolate"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// TODO: Implement tunnel start via API
	jsonResponse(w, http.StatusAccepted, map[string]string{"message": "tunnel start requested"})
}

func (s *Server) handleStopTunnel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	tm := s.gateway.GetTunnelManager()
	if err := tm.StopTunnel(name); err != nil {
		errorResponse(w, http.StatusNotFound, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{"message": "tunnel stopped"})
}

// --- Chains ---

func (s *Server) handleListChains(w http.ResponseWriter, r *http.Request) {
	status := s.gateway.GetTunnelManager().GetChainStatus()
	jsonResponse(w, http.StatusOK, map[string]interface{}{"chains": status})
}

// --- Whitelist ---

func (s *Server) handleWhitelistStats(w http.ResponseWriter, r *http.Request) {
	stats := s.gateway.GetWhitelistManager().GetStats()
	jsonResponse(w, http.StatusOK, map[string]interface{}{"stats": stats})
}

func (s *Server) handleWhitelistCheck(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	ipStr := vars["ip"]

	ip := net.ParseIP(ipStr)
	if ip == nil {
		errorResponse(w, http.StatusBadRequest, "invalid IP address")
		return
	}

	whitelisted := s.gateway.GetWhitelistManager().IsWhitelisted(ip)
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"ip":          ipStr,
		"whitelisted": whitelisted,
	})
}

// --- Engines ---

func (s *Server) handleListEngines(w http.ResponseWriter, r *http.Request) {
	// TODO: expose engine list from manager
	jsonResponse(w, http.StatusOK, map[string]string{"message": "not yet implemented"})
}

// --- Subscriptions ---

func (s *Server) handleUpdateSubscription(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	group := vars["group"]

	pm := s.gateway.GetProfileManager()
	count, err := pm.UpdateSubscriptions(group)
	if err != nil {
		errorResponse(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"message": "subscriptions updated",
		"links":   count,
	})
}
