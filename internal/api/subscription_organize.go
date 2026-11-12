package api

import "net/http"

func (s *Server) appOrganizeSubscription(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Group string `json:"group"`
		URL   string `json:"url"`
		Name  string `json:"name"`
	}
	if !decodeBody(w, r, &req, 64<<10) {
		return
	}
	sub, err := s.svc.OrganizeSubscription(r.Context(), req.Group, req.URL, req.Name)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, sub)
}
