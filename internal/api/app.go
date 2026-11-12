package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/bench"
	"github.com/liberoute/bypath/internal/profile"
)

// registerAppRoutesOn mounts the application handlers on any router. OpenVPN
// sources may never name a path on the daemon's filesystem: the daemon runs as
// root, and a caller of either surface (TCP or the local control socket) must
// not be able to make it read an arbitrary file. Callers upload text and
// referenced file contents instead.
func (s *Server) registerAppRoutesOn(r *mux.Router) {
	r.Use(s.serviceOperationGate)
	r.HandleFunc("/status", s.appStatus).Methods("GET")
	r.HandleFunc("/exit-ip", s.appExitIP).Methods("POST")

	r.HandleFunc("/connections", s.appListConnections).Methods("GET")
	r.HandleFunc("/connection", s.appGetConnection).Methods("GET")
	r.HandleFunc("/connections/import", s.appImportURI).Methods("POST")
	r.HandleFunc("/connections/ovpn/preview", s.previewOVPN).Methods("POST")
	r.HandleFunc("/connections/ovpn/import", s.importOVPN).Methods("POST")
	r.HandleFunc("/connections/delete", s.appDeleteConnection).Methods("POST")
	r.HandleFunc("/connections/delete-plan", s.appConnectionDeletePlan).Methods("GET")
	r.HandleFunc("/connections/rename", s.appRenameConnection).Methods("POST")
	r.HandleFunc("/connections/credentials", s.appSetCredentials).Methods("POST")
	r.HandleFunc("/connections/active", s.appSetActive).Methods("POST")

	r.HandleFunc("/subscriptions", s.appListSubscriptions).Methods("GET")
	r.HandleFunc("/subscriptions/preview", s.appPreviewSubscription).Methods("POST")
	r.HandleFunc("/subscriptions/preview-text", s.appPreviewSubscriptionText).Methods("POST")
	r.HandleFunc("/subscriptions/add", s.appAddSubscription).Methods("POST")
	r.HandleFunc("/subscriptions/organize", s.appOrganizeSubscription).Methods("POST")
	r.HandleFunc("/subscriptions/delete", s.appRemoveSubscription).Methods("POST")
	r.HandleFunc("/subscriptions/delete-plan", s.appSourceDeletePlan).Methods("GET")
	r.HandleFunc("/subscriptions/refresh", s.appRefreshSubscription).Methods("POST")
	r.HandleFunc("/subscriptions/import", s.appImportSubscriptionText).Methods("POST")

	r.HandleFunc("/connect", s.appConnect).Methods("POST")
	r.HandleFunc("/connections/restore", s.appRestorePrevious).Methods("POST")
	r.HandleFunc("/disconnect", s.appDisconnect).Methods("POST")
	r.HandleFunc("/restart", s.appRestart).Methods("POST")
	r.HandleFunc("/service/restart", s.appServiceRestart).Methods("POST")
	r.HandleFunc("/proxy/apply", s.appProxyApply).Methods("POST")
	r.HandleFunc("/service/operation", s.appServiceOperation).Methods("GET")
	r.HandleFunc("/shutdown", s.appShutdown).Methods("POST")

	r.HandleFunc("/logs", s.appLogs).Methods("GET")
	r.HandleFunc("/bench", s.appBench).Methods("POST")
	r.HandleFunc("/tests/jobs", s.appStartTestJob).Methods("POST")
	r.HandleFunc("/tests/jobs/{id}", s.appGetTestJob).Methods("GET")
	r.HandleFunc("/tests/jobs/{id}/cancel", s.appCancelTestJob).Methods("POST")
	r.HandleFunc("/tests/jobs/{id}/events", s.appTestJobEvents).Methods("GET")
	r.HandleFunc("/tests/results", s.appTestResults).Methods("GET")
	r.HandleFunc("/tests/targets", s.appSpeedTargets).Methods("GET")
	r.HandleFunc("/tests/targets", s.appAddSpeedTarget).Methods("POST")
	r.HandleFunc("/tests/targets/{id}", s.appDeleteSpeedTarget).Methods("DELETE")
	r.HandleFunc("/tests/targets/{id}/validate", s.appValidateSpeedTarget).Methods("POST")
	r.HandleFunc("/tests/budget", s.appTestBudget).Methods("POST")
	r.HandleFunc("/tests/usage", s.appTestUsage).Methods("GET")
	r.HandleFunc("/engines", s.appEngines).Methods("GET")
	r.HandleFunc("/settings", s.appSettings).Methods("GET")
	r.HandleFunc("/settings", s.appUpdateSettings).Methods("PATCH")
	r.HandleFunc("/backup", s.appBackup).Methods("GET")
	r.HandleFunc("/restore", s.appRestore).Methods("POST")

	r.HandleFunc("/routing", s.appRoutingOverview).Methods("GET")
	r.HandleFunc("/routing/explain", s.appRoutingExplain).Methods("GET")
	r.HandleFunc("/routing/test", s.appRoutingTest).Methods("POST")
	r.HandleFunc("/routing/preview", s.appRoutingPreview).Methods("POST")
	r.HandleFunc("/routing/apply", s.appRoutingApply).Methods("POST")
	r.HandleFunc("/routing/rollback", s.appRoutingRollback).Methods("POST")
	r.HandleFunc("/routing/egress", s.appRoutingEgress).Methods("POST")

	r.HandleFunc("/layer/status", s.appLayerStatus).Methods("GET")
	r.HandleFunc("/layer/plan", s.appLayerPlan).Methods("GET")
	r.HandleFunc("/layer/migrate", s.appLayerMigrate).Methods("POST")
	r.HandleFunc("/layer/rollback", s.appLayerRollback).Methods("POST")
	r.HandleFunc("/layer/groups", s.appLayerGroups).Methods("GET")
	r.HandleFunc("/layer/groups/create", s.appLayerCreateGroup).Methods("POST")
	r.HandleFunc("/layer/groups/rename", s.appLayerRenameGroup).Methods("POST")
	r.HandleFunc("/layer/groups/reorder", s.appLayerReorderGroups).Methods("POST")
	r.HandleFunc("/layer/groups/delete", s.appLayerDeleteGroup).Methods("POST")
	r.HandleFunc("/layer/move", s.appLayerMove).Methods("POST")
	r.HandleFunc("/layer/display-name", s.appLayerDisplayName).Methods("POST")
	r.HandleFunc("/layer/hide", s.appLayerHide).Methods("POST")
}

// appError maps a typed application error to an HTTP status without changing
// the stable code the client switches on.
func appError(w http.ResponseWriter, err error) {
	var ae *app.Error
	if !errors.As(err, &ae) {
		jsonResponse(w, http.StatusInternalServerError, map[string]string{
			"code": app.CodeInternal, "message": "internal error",
		})
		return
	}
	status := http.StatusInternalServerError
	switch ae.Code {
	case app.CodeInvalid:
		status = http.StatusBadRequest
	case app.CodeNotFound:
		status = http.StatusNotFound
	case app.CodeConflict:
		status = http.StatusConflict
	case app.CodeNeedsCreds:
		status = http.StatusBadRequest
	case app.CodeUnauthorized:
		status = http.StatusUnauthorized
	case app.CodeUnavailable:
		status = http.StatusServiceUnavailable
	case app.CodePermanent:
		status = http.StatusUnprocessableEntity
	case app.CodeUnsupported:
		status = http.StatusNotImplemented
	}
	jsonResponse(w, status, map[string]string{
		"code": ae.Code, "message": ae.Message, "hint": ae.Hint,
	})
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst interface{}, limit int64) bool {
	if limit <= 0 {
		limit = 1 << 20
	}
	defer r.Body.Close()
	if err := json.NewDecoder(io.LimitReader(r.Body, limit)).Decode(dst); err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

func (s *Server) appStatus(w http.ResponseWriter, r *http.Request) {
	st, err := s.svc.Status(r.Context())
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, st)
}

func (s *Server) appExitIP(w http.ResponseWriter, r *http.Request) {
	info, err := s.svc.ProbeExitInfo(r.Context())
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, info)
}

func (s *Server) appListConnections(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	list, err := s.svc.ListConnections(r.Context(), app.ConnectionFilter{
		Group:         q.Get("group"),
		Search:        q.Get("search"),
		Protocol:      q.Get("protocol"),
		IncludeHidden: q.Get("include_hidden") == "1",
	})
	if err != nil {
		appError(w, err)
		return
	}
	if list == nil {
		list = []app.Connection{}
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{"connections": list})
}

func (s *Server) appGetConnection(w http.ResponseWriter, r *http.Request) {
	detail, err := s.svc.GetConnection(r.Context(), r.URL.Query().Get("id"))
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, detail)
}

func (s *Server) appImportURI(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Group string `json:"group"`
		URI   string `json:"uri"`
	}
	if !decodeBody(w, r, &req, 256<<10) {
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
	jsonResponse(w, http.StatusCreated, res)
}

// sanitizeURI rejects an SSH private-key path supplied by a caller of this
// API. The in-process CLI may name a local key because it runs as the operator,
// but the daemon is root and must not let a socket or web caller choose which
// file root's ssh client authenticates with.
func sanitizeURI(raw string) error {
	link, err := profile.ParseURI(strings.TrimSpace(raw))
	if err != nil || link == nil {
		// The service reports the parse error with its own message.
		return nil
	}
	if link.SSHKeyPath != "" {
		return &app.Error{
			Code:    app.CodeInvalid,
			Message: "SSH key file paths are not accepted over this API",
			Hint:    "use password authentication, or import the link locally",
		}
	}
	return nil
}

func (s *Server) previewOVPN(w http.ResponseWriter, r *http.Request) {
	var src app.OVPNSource
	// The body cap leaves room for the 4 MiB of referenced files that
	// sanitizeOVPNSource accepts without trusting its own JSON size.
	if !decodeBody(w, r, &src, 5<<20) {
		return
	}
	if err := sanitizeOVPNSource(&src); err != nil {
		appError(w, err)
		return
	}
	preview, err := s.svc.PreviewOpenVPN(r.Context(), src)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, preview)
}

func (s *Server) importOVPN(w http.ResponseWriter, r *http.Request) {
	var req app.OVPNImport
	if !decodeBody(w, r, &req, 5<<20) {
		return
	}
	if err := sanitizeOVPNSource(&req.OVPNSource); err != nil {
		appError(w, err)
		return
	}
	res, err := s.svc.ImportOpenVPN(r.Context(), req)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, res)
}

// sanitizeOVPNSource keeps callers from naming server files. An import must
// carry the profile text; certificates and keys may be uploaded alongside it
// and are staged by the service, never read from disk by a client-supplied
// path. This applies to the web panel and to the local control socket alike,
// because the daemon runs as root on both.
func sanitizeOVPNSource(src *app.OVPNSource) error {
	if src == nil {
		return &app.Error{Code: app.CodeInvalid, Message: "missing OpenVPN source"}
	}
	if strings.TrimSpace(src.Path) != "" {
		return &app.Error{
			Code:    app.CodeInvalid,
			Message: "file paths are not accepted over this API",
			Hint:    "upload the profile contents and its referenced files instead",
		}
	}
	if strings.TrimSpace(src.Text) == "" {
		return &app.Error{Code: app.CodeInvalid, Message: "OpenVPN profile text is empty"}
	}
	if len(src.Text) > 1<<20 {
		return &app.Error{Code: app.CodeInvalid, Message: "OpenVPN profile text is larger than 1 MiB"}
	}
	total := 0
	for _, ref := range src.Refs {
		total += len(ref.Content)
	}
	if total > 4<<20 {
		return &app.Error{Code: app.CodeInvalid, Message: "uploaded OpenVPN files exceed 4 MiB in total"}
	}
	return app.ValidateOVPNRefs(src.Refs)
}

func (s *Server) appDeleteConnection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID      string            `json:"id"`
		Options app.DeleteOptions `json:"options"`
	}
	if !decodeBody(w, r, &req, 64<<10) {
		return
	}
	if err := s.svc.DeleteConnectionWithOptions(r.Context(), req.ID, req.Options); err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "connection deleted"})
}

func (s *Server) appRenameConnection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if !decodeBody(w, r, &req, 64<<10) {
		return
	}
	if err := s.svc.RenameConnection(r.Context(), req.ID, req.Name); err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "connection renamed"})
}

func (s *Server) appSetCredentials(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Password string `json:"password"`
		Save     bool   `json:"save"`
	}
	if !decodeBody(w, r, &req, 64<<10) {
		return
	}
	err := s.svc.SetCredentials(r.Context(), req.ID,
		app.Credentials{Username: req.Username, Password: req.Password}, req.Save)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]bool{"saved": req.Save})
}

func (s *Server) appSetActive(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if !decodeBody(w, r, &req, 64<<10) {
		return
	}
	res, err := s.svc.SetActive(r.Context(), req.ID)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, res)
}

func (s *Server) appListSubscriptions(w http.ResponseWriter, r *http.Request) {
	list, err := s.svc.ListSubscriptions(r.Context())
	if err != nil {
		appError(w, err)
		return
	}
	if list == nil {
		list = []app.Subscription{}
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{"subscriptions": list})
}

func (s *Server) appPreviewSubscription(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if !decodeBody(w, r, &req, 64<<10) {
		return
	}
	preview, err := s.svc.PreviewSubscription(r.Context(), req.URL)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, preview)
}

func (s *Server) appPreviewSubscriptionText(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Text string `json:"text"`
	}
	if !decodeBody(w, r, &req, 4<<20) {
		return
	}
	preview, err := s.svc.PreviewSubscriptionText(r.Context(), req.Text)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, preview)
}

func (s *Server) appAddSubscription(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Group string `json:"group"`
		URL   string `json:"url"`
	}
	if !decodeBody(w, r, &req, 64<<10) {
		return
	}
	sub, err := s.svc.AddSubscription(r.Context(), req.Group, req.URL)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, sub)
}

func (s *Server) appRemoveSubscription(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Group   string            `json:"group"`
		URL     string            `json:"url"`
		Options app.DeleteOptions `json:"options"`
	}
	if !decodeBody(w, r, &req, 64<<10) {
		return
	}
	if err := s.svc.RemoveSubscriptionWithOptions(r.Context(), req.Group, req.URL, req.Options); err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "subscription removed"})
}

func (s *Server) appRefreshSubscription(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Group string `json:"group"`
		URL   string `json:"url"`
	}
	if !decodeBody(w, r, &req, 64<<10) {
		return
	}
	sub, err := s.svc.RefreshSubscription(r.Context(), req.Group, req.URL, nil)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, sub)
}

func (s *Server) appImportSubscriptionText(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Group string `json:"group"`
		Text  string `json:"text"`
	}
	if !decodeBody(w, r, &req, 4<<20) {
		return
	}
	res, err := s.svc.ImportSubscriptionText(r.Context(), req.Group, req.Text)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusCreated, res)
}

func (s *Server) appConnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if !decodeBody(w, r, &req, 64<<10) {
		return
	}
	res, err := s.svc.Connect(r.Context(), req.ID)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, res)
}

func (s *Server) appDisconnect(w http.ResponseWriter, r *http.Request) {
	res, err := s.svc.Disconnect(r.Context())
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, res)
}

func (s *Server) appRestart(w http.ResponseWriter, r *http.Request) {
	res, err := s.svc.Restart(r.Context())
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, res)
}

func (s *Server) appRestorePrevious(w http.ResponseWriter, r *http.Request) {
	res, err := s.svc.RestorePrevious(r.Context())
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, res)
}

func (s *Server) appShutdown(w http.ResponseWriter, r *http.Request) {
	res, err := s.svc.Shutdown(r.Context())
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, res)
}

func (s *Server) appLogs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	logs, err := s.svc.Logs(r.Context(), app.LogQuery{Limit: limit})
	if err != nil {
		appError(w, err)
		return
	}
	if logs == nil {
		logs = []app.LogEntry{}
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{"logs": logs})
}

func (s *Server) appBench(w http.ResponseWriter, r *http.Request) {
	var req app.BenchRequest
	if !decodeBody(w, r, &req, 4<<10) {
		return
	}
	report, err := s.svc.Bench(r.Context(), req)
	if err != nil {
		appError(w, err)
		return
	}
	if report.Rows == nil {
		report.Rows = []bench.Row{}
	}
	jsonResponse(w, http.StatusOK, report)
}

func (s *Server) appEngines(w http.ResponseWriter, r *http.Request) {
	engines, err := s.svc.Engines(r.Context())
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{"engines": engines})
}

func (s *Server) appSettings(w http.ResponseWriter, r *http.Request) {
	st, err := s.svc.Settings(r.Context())
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, st)
}

func (s *Server) appUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var patch app.SettingsPatch
	if !decodeLifecycle(w, r, &patch, 64<<10) {
		return
	}
	change, err := s.svc.UpdateSettings(r.Context(), patch)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, change)
}

func (s *Server) appBackup(w http.ResponseWriter, r *http.Request) {
	includeSecrets := r.URL.Query().Get("secrets") == "1"
	backup, err := s.svc.Backup(r.Context(), includeSecrets)
	if err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, backup)
}

func (s *Server) appRestore(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		errorResponse(w, http.StatusBadRequest, "invalid backup body")
		return
	}
	if err := s.svc.Restore(r.Context(), data); err != nil {
		appError(w, err)
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"message": "configuration restored"})
}
