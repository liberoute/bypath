package api

import (
	"net/http"
	"strings"

	"github.com/liberoute/bypath/internal/app"
)

func (s *Server) appRoutingOverview(w http.ResponseWriter, r *http.Request) {
	overview, err := s.svc.RoutingOverview(r.Context())
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, overview)
}

func (s *Server) appRoutingExplain(w http.ResponseWriter, r *http.Request) {
	explanation, err := s.svc.ExplainRoute(r.Context(), r.URL.Query().Get("target"))
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, explanation)
}

func (s *Server) appRoutingTest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Target string `json:"target"`
		Port   int    `json:"port"`
	}
	if !decodeBody(w, r, &req, 64<<10) {
		return
	}
	result, err := s.svc.TestRoute(r.Context(), req.Target, req.Port)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, result)
}

func (s *Server) appRoutingPreview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Edit app.RoutingEdit `json:"edit"`
	}
	if !decodeBody(w, r, &req, 256<<10) {
		return
	}
	preview, err := s.svc.PreviewRouting(r.Context(), req.Edit)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, preview)
}

func (s *Server) appRoutingApply(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Edit      app.RoutingEdit `json:"edit"`
		Revision  string          `json:"revision"`
		Note      string          `json:"note"`
		Confirmed bool            `json:"confirmed"`
	}
	if !decodeBody(w, r, &req, 256<<10) {
		return
	}
	if !req.Confirmed {
		errorResponse(w, http.StatusBadRequest, "the change must be confirmed after reviewing the preview")
		return
	}
	// An apply must name the revision it previewed; without it a stale tab could
	// overwrite a policy change made after the preview was composed.
	if strings.TrimSpace(req.Revision) == "" {
		errorResponse(w, http.StatusBadRequest, "reload the routing screen and preview the change before applying it")
		return
	}
	change, err := s.svc.ApplyRouting(r.Context(), req.Edit, req.Revision, req.Note)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, change)
}

func (s *Server) appRoutingRollback(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Snapshot  string `json:"snapshot"`
		Confirmed bool   `json:"confirmed"`
	}
	if !decodeBody(w, r, &req, 64<<10) {
		return
	}
	if !req.Confirmed {
		errorResponse(w, http.StatusBadRequest, "the rollback must be confirmed")
		return
	}
	change, err := s.svc.RollbackRouting(r.Context(), req.Snapshot)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, change)
}

func (s *Server) appRoutingEgress(w http.ResponseWriter, r *http.Request) {
	check, err := s.svc.CheckEgress(r.Context())
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, check)
}
