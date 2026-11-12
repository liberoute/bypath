package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/liberoute/bypath/internal/app"
)

func (s *Server) serviceOperationGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions && s.svc.ServiceOperationPending() {
			appError(w, &app.Error{Code: app.CodeConflict, Message: "service verification/rollback pending; configuration and selection are frozen"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Strict decoding is mandatory for root lifecycle operations: no shell, unit,
// executable, config path, ignored fields or trailing JSON can be supplied.
func decodeLifecycle(w http.ResponseWriter, r *http.Request, dst interface{}, limit int64) bool {
	defer r.Body.Close()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	body = bytes.TrimSpace(body)
	if err != nil || len(body) == 0 || body[0] != '{' {
		errorResponse(w, http.StatusBadRequest, "request must be a JSON object")
		return false
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid structured request")
		return false
	}
	var extra interface{}
	if err := d.Decode(&extra); err != io.EOF {
		errorResponse(w, http.StatusBadRequest, "request must contain one JSON object")
		return false
	}
	return true
}
func (s *Server) appServiceRestart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Confirm bool `json:"confirm"`
	}
	if !decodeLifecycle(w, r, &req, 1024) {
		return
	}
	op, err := s.svc.RestartService(r.Context(), req.Confirm)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusAccepted, op)
}
func (s *Server) appProxyApply(w http.ResponseWriter, r *http.Request) {
	var req app.ProxyApply
	if !decodeLifecycle(w, r, &req, 1024) {
		return
	}
	op, err := s.svc.ApplyProxy(r.Context(), req)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusAccepted, op)
}
func (s *Server) appServiceOperation(w http.ResponseWriter, r *http.Request) {
	op, err := s.svc.ServiceOperation(r.Context(), r.URL.Query().Get("id"))
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, op)
}
