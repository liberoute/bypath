package api

import (
	"net/http"

	"github.com/liberoute/bypath/internal/app"
)

// The organisation layer shares one service surface with every other
// frontend; these handlers only translate JSON to app calls.

func (s *Server) appLayerStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.svc.LayerStatus(r.Context())
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, st)
}

func (s *Server) appLayerPlan(w http.ResponseWriter, r *http.Request) {
	plan, err := s.svc.LayerPlan(r.Context())
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, plan)
}

func (s *Server) appLayerMigrate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DryRun bool `json:"dry_run"`
	}
	if !decodeBody(w, r, &req, 4<<10) {
		return
	}
	plan, err := s.svc.LayerMigrate(r.Context(), req.DryRun)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, plan)
}

func (s *Server) appLayerRollback(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Confirm bool `json:"confirm"`
	}
	if !decodeBody(w, r, &req, 4<<10) {
		return
	}
	report, err := s.svc.LayerRollback(r.Context(), req.Confirm)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, report)
}

func (s *Server) appLayerGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := s.svc.LayerGroups(r.Context())
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{"groups": groups})
}

func (s *Server) appLayerCreateGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !decodeBody(w, r, &req, 16<<10) {
		return
	}
	g, err := s.svc.CreateLayerGroup(r.Context(), req.Name)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, g)
}

func (s *Server) appLayerRenameGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if !decodeBody(w, r, &req, 16<<10) {
		return
	}
	if err := s.svc.RenameLayerGroup(r.Context(), req.ID, req.Name); err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "group renamed"})
}

func (s *Server) appLayerReorderGroups(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if !decodeBody(w, r, &req, 64<<10) {
		return
	}
	if err := s.svc.ReorderLayerGroups(r.Context(), req.IDs); err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "groups reordered"})
}

func (s *Server) appLayerDeleteGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID            string            `json:"id"`
		DeleteMembers bool              `json:"delete_members"`
		Options       app.DeleteOptions `json:"options"`
	}
	if !decodeBody(w, r, &req, 64<<10) {
		return
	}
	if err := s.svc.DeleteLayerGroup(r.Context(), req.ID, req.DeleteMembers, req.Options); err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "group deleted"})
}

func (s *Server) appLayerMove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs     []string `json:"ids"`
		GroupID string   `json:"group_id"`
	}
	if !decodeBody(w, r, &req, 256<<10) {
		return
	}
	if err := s.svc.MoveLayerConnections(r.Context(), req.IDs, req.GroupID); err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "connections moved"})
}

func (s *Server) appLayerDisplayName(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if !decodeBody(w, r, &req, 16<<10) {
		return
	}
	if err := s.svc.SetDisplayName(r.Context(), req.ID, req.Name); err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "display name updated"})
}

func (s *Server) appLayerHide(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs    []string `json:"ids"`
		Hidden bool     `json:"hidden"`
	}
	if !decodeBody(w, r, &req, 256<<10) {
		return
	}
	if err := s.svc.HideConnections(r.Context(), req.IDs, req.Hidden); err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "visibility updated"})
}

func (s *Server) appConnectionDeletePlan(w http.ResponseWriter, r *http.Request) {
	impact, err := s.svc.ConnectionDeletePlan(r.Context(), r.URL.Query().Get("id"))
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, impact)
}

func (s *Server) appSourceDeletePlan(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	impact, err := s.svc.SourceDeletePlan(r.Context(), q.Get("group"), q.Get("url"))
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, impact)
}
