package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/metrics"
	"github.com/liberoute/bypath/internal/profile"
)

// --- Status ---

// handleStatus keeps the legacy response shape while filling it from the
// shared service, so it can never contradict /app/status.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	tunnelStatus := s.gateway.GetTunnelManager().GetStatus()
	chainStatus := s.gateway.GetTunnelManager().GetChainStatus()
	st, err := s.svc.Status(r.Context())
	if err != nil {
		appError(w, err)
		return
	}

	status := map[string]interface{}{
		"version":                st.Version,
		"variant":                st.Variant,
		"active_engine":          st.Engine,
		"state":                  st.State,
		"active_link":            st.ActiveLink,
		"protocol":               st.Protocol,
		"restarts":               st.Restarts,
		"tun_restarts":           st.TunRestarts,
		"recovery_attempt":       st.Recovery,
		"last_error":             st.LastError,
		"last_health":            st.LastHealth,
		"health_code":            st.HealthCode,
		"health_detail":          st.HealthDetail,
		"health_tunnel_answered": st.HealthTunnelAnswered,
		"health_exit_ip":         st.HealthExitIP,
		"health_uplink_samples":  st.HealthUplinkSamples,
		"uptime_sec":             st.UptimeSec,
		"gateway_mode":           st.GatewayMode,
		"dns_mode":               st.DNSMode,
		"profile_count":          st.ProfileCount,
		"tunnels":                tunnelStatus,
		"chains":                 chainStatus,
	}

	jsonResponse(w, http.StatusOK, status)
}

// --- Profiles ---

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	groups := s.svc.Profiles().ListGroups()
	jsonResponse(w, http.StatusOK, map[string]interface{}{"groups": groups})
}

func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	group, err := s.svc.Profiles().GetGroup(name)
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

	pm := s.svc.Profiles()
	if err := pm.CreateGroup(req.Name, req.Type); err != nil {
		if errors.Is(err, profile.ErrInvalidGroupName) {
			errorResponse(w, http.StatusBadRequest, err.Error())
			return
		}
		errorResponse(w, http.StatusConflict, err.Error())
		return
	}

	jsonResponse(w, http.StatusCreated, map[string]string{"message": "group created"})
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	name := vars["name"]

	pm := s.svc.Profiles()
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
	if err := sanitizeURI(req.URI); err != nil {
		appError(w, err)
		return
	}

	res, err := s.svc.ImportURI(r.Context(), req.Group, req.URI)
	if err != nil {
		appError(w, err)
		return
	}

	out := map[string]interface{}{"message": "link added", "group": res.Group}
	if len(res.Created) > 0 {
		out["remark"] = res.Created[0].Remark
		out["protocol"] = res.Created[0].Protocol
	}
	jsonResponse(w, http.StatusCreated, out)
}

func (s *Server) handleDeleteLink(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := app.ConnectionID(vars["group"], vars["remark"])

	if err := s.svc.DeleteConnection(r.Context(), id); err != nil {
		appError(w, err)
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
	// Starting an ad-hoc tunnel is intentionally unsupported: it would create a
	// second state owner next to the managed profile link.
	jsonResponse(w, http.StatusNotImplemented, map[string]string{
		"code":    "not_implemented",
		"message": "ad-hoc tunnels are not supported; select a connection instead",
	})
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

// --- Engines ---

func (s *Server) handleListEngines(w http.ResponseWriter, r *http.Request) {
	engines, err := s.svc.Engines(r.Context())
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{"engines": engines})
}

// --- Subscriptions ---

func (s *Server) handleUpdateSubscription(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	group := vars["group"]

	subs, err := s.svc.ListSubscriptions(r.Context())
	if err != nil {
		appError(w, err)
		return
	}
	total := 0
	var failures []string
	for _, sub := range subs {
		if sub.Group != group {
			continue
		}
		updated, err := s.svc.RefreshSubscription(r.Context(), sub.Group, sub.URL, nil)
		if err != nil {
			failures = append(failures, sub.RedactedURL+": "+err.Error())
			continue
		}
		total += updated.LinkCount
	}
	if len(failures) > 0 {
		jsonResponse(w, http.StatusBadGateway, map[string]interface{}{
			"code":     app.CodeUnavailable,
			"message":  "some subscriptions could not be refreshed; existing links were kept",
			"failures": failures,
			"links":    total,
		})
		return
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"message": "subscriptions updated",
		"links":   total,
	})
}

// --- Config ---

func (s *Server) handleConfigReload(w http.ResponseWriter, r *http.Request) {
	needRestart, err := s.svc.ReloadConfig()
	if err != nil {
		appError(w, err)
		return
	}
	metrics.ConfigReloads.Inc()
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"message":          "config reloaded",
		"restart_required": needRestart,
	})
}
