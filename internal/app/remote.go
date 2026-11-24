package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/liberoute/bypath/internal/bench"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/control"
	"github.com/liberoute/bypath/internal/layer"
)

const (
	// requestTimeout bounds ordinary control calls. Lifecycle calls get their
	// own, larger budget: a fallback start may legally spend the gateway's
	// total_timeout (5 minutes by default) before the first candidate answers,
	// and aborting the HTTP request tears the startup down through the
	// request context.
	requestTimeout   = 90 * time.Second
	lifecycleTimeout = 10 * time.Minute
	// benchTimeout bounds a full benchmark: each link may take the relay
	// budget, and Run works through the list in small parallel batches.
	benchTimeout = 10 * time.Minute
)

// Remote is the HTTP implementation of Contract. The CLI and the TUI use it
// when a gateway process owns the profile state, so there is exactly one
// writer of profiles and configuration.
type Remote struct {
	base   string
	token  string
	http   *http.Client
	socket string
}

// NewRemote builds a client for a running gateway.
func NewRemote(host string, port int, token string) *Remote {
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	base := fmt.Sprintf("http://%s", net.JoinHostPort(host, strconv.Itoa(port)))
	return &Remote{
		base:  base,
		token: token,
		http:  &http.Client{},
	}
}

// RemoteFromConfig targets the API of the local installation.
func RemoteFromConfig(cfg *config.Config) *Remote {
	return NewRemote(cfg.Server.Listen, cfg.Server.APIPort, cfg.Server.APIToken)
}

// NewRemoteSocket targets the daemon over its local control socket. Access is
// enforced by the socket's owner/group mode, so no API token is needed and the
// frontend never has to read the root-owned configuration.
func NewRemoteSocket(path string) *Remote {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		},
	}
	return &Remote{
		base:   "http://bypath.local",
		socket: path,
		http:   &http.Client{Transport: transport},
	}
}

// BaseURL is the API root, useful for diagnostics.
func (r *Remote) BaseURL() string { return r.base }

// do performs one JSON request and decodes either the result or a typed error.
func (r *Remote) do(ctx context.Context, method, path string, body, out interface{}) error {
	return r.doWithin(ctx, requestTimeout, method, path, body, out)
}

// doLifecycle performs a call that may run the whole startup budget server-side.
func (r *Remote) doLifecycle(ctx context.Context, method, path string, body, out interface{}) error {
	return r.doWithin(ctx, lifecycleTimeout, method, path, body, out)
}

func (r *Remote) doWithin(ctx context.Context, timeout time.Duration, method, path string, body, out interface{}) error {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return asAppError(err, CodeInternal, "encoding request")
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.base+path, reader)
	if err != nil {
		return asAppError(err, CodeInternal, "building request")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		if r.socket != "" {
			return &Error{
				Code:    CodeUnavailable,
				Message: "gateway control socket is not usable: " + Redact(err.Error()),
				Hint:    "make sure the gateway is running and this account may access " + r.socket + " (the '" + control.GroupName + "' group is root-equivalent; add only trusted administrators)",
				Err:     err,
			}
		}
		return &Error{
			Code:    CodeUnavailable,
			Message: "gateway API is not reachable: " + Redact(err.Error()),
			Hint:    "start the gateway with 'bypath run'",
			Err:     err,
		}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return asAppError(err, CodeUnavailable, "reading API response")
	}
	if resp.StatusCode >= 400 {
		var env Error
		if json.Unmarshal(data, &env) == nil && env.Message != "" {
			if env.Code == "" {
				env.Code = codeForStatus(resp.StatusCode)
			}
			return &env
		}
		return &Error{Code: codeForStatus(resp.StatusCode), Message: fmt.Sprintf("API returned %s", resp.Status)}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return asAppError(err, CodeUnavailable, "decoding API response")
	}
	return nil
}

func codeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return CodeInvalid
	case http.StatusUnauthorized:
		return CodeUnauthorized
	case http.StatusNotFound:
		return CodeNotFound
	case http.StatusConflict:
		return CodeConflict
	case http.StatusServiceUnavailable:
		return CodeUnavailable
	default:
		return CodeInternal
	}
}

func (r *Remote) Status(ctx context.Context) (Status, error) {
	var out Status
	err := r.do(ctx, http.MethodGet, "/api/v1/app/status", nil, &out)
	return out, err
}

func (r *Remote) ProbeExitIP(ctx context.Context) (string, error) {
	var out struct {
		IP string `json:"ip"`
	}
	err := r.do(ctx, http.MethodPost, "/api/v1/app/exit-ip", nil, &out)
	return out.IP, err
}

// ProbeExitIdentity runs the daemon's multi-oracle identity probe. The budget
// covers every oracle and, when needed, the separate data-path check.
func (r *Remote) ProbeExitIdentity(ctx context.Context) (ExitProof, error) {
	var out ExitProof
	err := r.doWithin(ctx, 30*time.Second, http.MethodPost, "/api/v1/app/exit-identity", nil, &out)
	return out, err
}

// CheckEgress asks the running gateway for its tunnel exit and the address its
// direct path uses. Both probes are bounded server-side.
func (r *Remote) CheckEgress(ctx context.Context) (EgressCheck, error) {
	var out EgressCheck
	err := r.doWithin(ctx, 25*time.Second, http.MethodPost, "/api/v1/app/routing/egress", nil, &out)
	return out, err
}

func (r *Remote) ListConnections(ctx context.Context, filter ConnectionFilter) ([]Connection, error) {
	q := url.Values{}
	if filter.Group != "" {
		q.Set("group", filter.Group)
	}
	if filter.Search != "" {
		q.Set("search", filter.Search)
	}
	if filter.Protocol != "" {
		q.Set("protocol", filter.Protocol)
	}
	var out struct {
		Connections []Connection `json:"connections"`
	}
	err := r.do(ctx, http.MethodGet, "/api/v1/app/connections?"+q.Encode(), nil, &out)
	return out.Connections, err
}

func (r *Remote) GetConnection(ctx context.Context, id string) (ConnectionDetail, error) {
	var out ConnectionDetail
	err := r.do(ctx, http.MethodGet, "/api/v1/app/connection?id="+url.QueryEscape(id), nil, &out)
	return out, err
}

func (r *Remote) ImportURI(ctx context.Context, group, uri string) (ImportResult, error) {
	var out ImportResult
	err := r.do(ctx, http.MethodPost, "/api/v1/app/connections/import",
		map[string]string{"group": group, "uri": uri}, &out)
	return out, err
}

func (r *Remote) PreviewOpenVPN(ctx context.Context, src OVPNSource) (OVPNPreview, error) {
	var out OVPNPreview
	err := r.do(ctx, http.MethodPost, "/api/v1/app/connections/ovpn/preview", src, &out)
	return out, err
}

func (r *Remote) ImportOpenVPN(ctx context.Context, req OVPNImport) (ImportResult, error) {
	var out ImportResult
	err := r.do(ctx, http.MethodPost, "/api/v1/app/connections/ovpn/import", req, &out)
	return out, err
}

func (r *Remote) DeleteConnection(ctx context.Context, id string) error {
	return r.do(ctx, http.MethodPost, "/api/v1/app/connections/delete", map[string]string{"id": id}, nil)
}

func (r *Remote) RenameConnection(ctx context.Context, id, name string) error {
	return r.do(ctx, http.MethodPost, "/api/v1/app/connections/rename",
		map[string]string{"id": id, "name": name}, nil)
}

func (r *Remote) SetCredentials(ctx context.Context, id string, creds Credentials, persist bool) error {
	return r.do(ctx, http.MethodPost, "/api/v1/app/connections/credentials", map[string]interface{}{
		"id": id, "username": creds.Username, "password": creds.Password, "save": persist,
	}, nil)
}

func (r *Remote) SetActive(ctx context.Context, id string) (ActionResult, error) {
	var out ActionResult
	err := r.do(ctx, http.MethodPost, "/api/v1/app/connections/active", map[string]string{"id": id}, &out)
	return out, err
}

func (r *Remote) ListSubscriptions(ctx context.Context) ([]Subscription, error) {
	var out struct {
		Subscriptions []Subscription `json:"subscriptions"`
	}
	err := r.do(ctx, http.MethodGet, "/api/v1/app/subscriptions", nil, &out)
	return out.Subscriptions, err
}

func (r *Remote) PreviewSubscription(ctx context.Context, rawURL string) (SubscriptionPreview, error) {
	var out SubscriptionPreview
	err := r.do(ctx, http.MethodPost, "/api/v1/app/subscriptions/preview",
		map[string]string{"url": rawURL}, &out)
	return out, err
}

func (r *Remote) PreviewSubscriptionText(ctx context.Context, text string) (SubscriptionPreview, error) {
	var out SubscriptionPreview
	err := r.do(ctx, http.MethodPost, "/api/v1/app/subscriptions/preview-text",
		map[string]string{"text": text}, &out)
	return out, err
}

func (r *Remote) AddSubscription(ctx context.Context, group, rawURL string) (Subscription, error) {
	var out Subscription
	err := r.do(ctx, http.MethodPost, "/api/v1/app/subscriptions/add",
		map[string]string{"group": group, "url": rawURL}, &out)
	return out, err
}

func (r *Remote) OrganizeSubscription(ctx context.Context, group, rawURL, name string) (Subscription, error) {
	var out Subscription
	err := r.do(ctx, http.MethodPost, "/api/v1/app/subscriptions/organize",
		map[string]string{"group": group, "url": rawURL, "name": name}, &out)
	return out, err
}

func (r *Remote) RemoveSubscription(ctx context.Context, group, rawURL string) error {
	return r.do(ctx, http.MethodPost, "/api/v1/app/subscriptions/delete",
		map[string]string{"group": group, "url": rawURL}, nil)
}

func (r *Remote) RefreshSubscription(ctx context.Context, group, rawURL string, progress func(RefreshProgress)) (Subscription, error) {
	// The API is synchronous; progress is delivered once completion is known so
	// callers that render a spinner still see a truthful final state.
	var out Subscription
	err := r.do(ctx, http.MethodPost, "/api/v1/app/subscriptions/refresh",
		map[string]string{"group": group, "url": rawURL}, &out)
	if progress != nil {
		p := RefreshProgress{Group: group, URL: rawURL, Done: true, Links: out.LinkCount, Err: out.LastError}
		if err != nil {
			p.Err = err.Error()
		}
		progress(p)
	}
	return out, err
}

func (r *Remote) ImportSubscriptionText(ctx context.Context, group, text string) (ImportResult, error) {
	var out ImportResult
	err := r.do(ctx, http.MethodPost, "/api/v1/app/subscriptions/import",
		map[string]string{"group": group, "text": text}, &out)
	return out, err
}

// --- Organisation layer ---

func (r *Remote) LayerStatus(ctx context.Context) (layer.Status, error) {
	var out layer.Status
	err := r.do(ctx, http.MethodGet, "/api/v1/app/layer/status", nil, &out)
	return out, err
}

func (r *Remote) LayerPlan(ctx context.Context) (layer.MigrationPlan, error) {
	var out layer.MigrationPlan
	err := r.do(ctx, http.MethodGet, "/api/v1/app/layer/plan", nil, &out)
	return out, err
}

func (r *Remote) LayerMigrate(ctx context.Context, dryRun bool) (layer.MigrationPlan, error) {
	var out layer.MigrationPlan
	err := r.do(ctx, http.MethodPost, "/api/v1/app/layer/migrate",
		map[string]bool{"dry_run": dryRun}, &out)
	return out, err
}

func (r *Remote) LayerRollback(ctx context.Context, confirm bool) (layer.RollbackReport, error) {
	var out layer.RollbackReport
	err := r.do(ctx, http.MethodPost, "/api/v1/app/layer/rollback",
		map[string]bool{"confirm": confirm}, &out)
	return out, err
}

func (r *Remote) LayerGroups(ctx context.Context) ([]layer.GroupView, error) {
	var out struct {
		Groups []layer.GroupView `json:"groups"`
	}
	err := r.do(ctx, http.MethodGet, "/api/v1/app/layer/groups", nil, &out)
	return out.Groups, err
}

func (r *Remote) CreateLayerGroup(ctx context.Context, name string) (layer.Group, error) {
	var out layer.Group
	err := r.do(ctx, http.MethodPost, "/api/v1/app/layer/groups/create",
		map[string]string{"name": name}, &out)
	return out, err
}

func (r *Remote) RenameLayerGroup(ctx context.Context, id, name string) error {
	return r.do(ctx, http.MethodPost, "/api/v1/app/layer/groups/rename",
		map[string]string{"id": id, "name": name}, nil)
}

func (r *Remote) ReorderLayerGroups(ctx context.Context, ids []string) error {
	return r.do(ctx, http.MethodPost, "/api/v1/app/layer/groups/reorder",
		map[string][]string{"ids": ids}, nil)
}

func (r *Remote) DeleteLayerGroup(ctx context.Context, id string, deleteMembers bool, opts DeleteOptions) error {
	return r.do(ctx, http.MethodPost, "/api/v1/app/layer/groups/delete",
		map[string]interface{}{"id": id, "delete_members": deleteMembers, "options": opts}, nil)
}

func (r *Remote) MoveLayerConnections(ctx context.Context, ids []string, groupID string) error {
	return r.do(ctx, http.MethodPost, "/api/v1/app/layer/move",
		map[string]interface{}{"ids": ids, "group_id": groupID}, nil)
}

func (r *Remote) SetDisplayName(ctx context.Context, id, name string) error {
	return r.do(ctx, http.MethodPost, "/api/v1/app/layer/display-name",
		map[string]string{"id": id, "name": name}, nil)
}

func (r *Remote) HideConnections(ctx context.Context, ids []string, hidden bool) error {
	return r.do(ctx, http.MethodPost, "/api/v1/app/layer/hide",
		map[string]interface{}{"ids": ids, "hidden": hidden}, nil)
}

func (r *Remote) ConnectionDeletePlan(ctx context.Context, id string) (DeleteImpact, error) {
	var out DeleteImpact
	err := r.do(ctx, http.MethodGet, "/api/v1/app/connections/delete-plan?id="+url.QueryEscape(id), nil, &out)
	return out, err
}

func (r *Remote) DeleteConnectionWithOptions(ctx context.Context, id string, opts DeleteOptions) error {
	return r.do(ctx, http.MethodPost, "/api/v1/app/connections/delete",
		map[string]interface{}{"id": id, "options": opts}, nil)
}

func (r *Remote) SourceDeletePlan(ctx context.Context, group, rawURL string) (SourceDeleteImpact, error) {
	q := url.Values{}
	q.Set("group", group)
	q.Set("url", rawURL)
	var out SourceDeleteImpact
	err := r.do(ctx, http.MethodGet, "/api/v1/app/subscriptions/delete-plan?"+q.Encode(), nil, &out)
	return out, err
}

func (r *Remote) RemoveSubscriptionWithOptions(ctx context.Context, group, rawURL string, opts DeleteOptions) error {
	return r.do(ctx, http.MethodPost, "/api/v1/app/subscriptions/delete",
		map[string]interface{}{"group": group, "url": rawURL, "options": opts}, nil)
}

func (r *Remote) RoutingOverview(ctx context.Context) (RoutingOverview, error) {
	var out RoutingOverview
	err := r.do(ctx, http.MethodGet, "/api/v1/app/routing", nil, &out)
	return out, err
}

func (r *Remote) Connect(ctx context.Context, id string) (ActionResult, error) {
	var out ActionResult
	err := r.doLifecycle(ctx, http.MethodPost, "/api/v1/app/connect", map[string]string{"id": id}, &out)
	return out, err
}

func (r *Remote) Disconnect(ctx context.Context) (ActionResult, error) {
	var out ActionResult
	err := r.doLifecycle(ctx, http.MethodPost, "/api/v1/app/disconnect", nil, &out)
	return out, err
}

func (r *Remote) Restart(ctx context.Context) (ActionResult, error) {
	var out ActionResult
	err := r.doLifecycle(ctx, http.MethodPost, "/api/v1/app/restart", nil, &out)
	return out, err
}

func (r *Remote) RestartService(ctx context.Context, confirm bool) (ServiceOperation, error) {
	var out ServiceOperation
	err := r.do(ctx, http.MethodPost, "/api/v1/app/service/restart", map[string]bool{"confirm": confirm}, &out)
	return out, err
}

func (r *Remote) ApplyProxy(ctx context.Context, req ProxyApply) (ServiceOperation, error) {
	var out ServiceOperation
	err := r.do(ctx, http.MethodPost, "/api/v1/app/proxy/apply", req, &out)
	return out, err
}

func (r *Remote) ServiceOperation(ctx context.Context, id string) (ServiceOperation, error) {
	var out ServiceOperation
	err := r.do(ctx, http.MethodGet, "/api/v1/app/service/operation?id="+url.QueryEscape(id), nil, &out)
	return out, err
}

// Shutdown stops the daemon process; Disconnect only stops the tunnel.
func (r *Remote) Shutdown(ctx context.Context) (ActionResult, error) {
	var out ActionResult
	err := r.doLifecycle(ctx, http.MethodPost, "/api/v1/app/shutdown", nil, &out)
	return out, err
}

func (r *Remote) Logs(ctx context.Context, query LogQuery) ([]LogEntry, error) {
	path := "/api/v1/app/logs?limit=" + strconv.Itoa(query.Limit)
	var out struct {
		Logs []LogEntry `json:"logs"`
	}
	err := r.do(ctx, http.MethodGet, path, nil, &out)
	return out.Logs, err
}

func (r *Remote) Bench(ctx context.Context, req BenchRequest) (bench.Report, error) {
	var out bench.Report
	err := r.doWithin(ctx, benchTimeout, http.MethodPost, "/api/v1/app/bench", req, &out)
	return out, err
}

func (r *Remote) Engines(ctx context.Context) ([]Engine, error) {
	var out struct {
		Engines []Engine `json:"engines"`
	}
	err := r.do(ctx, http.MethodGet, "/api/v1/app/engines", nil, &out)
	return out.Engines, err
}

func (r *Remote) Settings(ctx context.Context) (Settings, error) {
	var out Settings
	err := r.do(ctx, http.MethodGet, "/api/v1/app/settings", nil, &out)
	return out, err
}

func (r *Remote) UpdateSettings(ctx context.Context, patch SettingsPatch) (SettingsChange, error) {
	var out SettingsChange
	err := r.do(ctx, http.MethodPatch, "/api/v1/app/settings", patch, &out)
	return out, err
}

func (r *Remote) Backup(ctx context.Context, includeSecrets bool) (Backup, error) {
	var out Backup
	err := r.do(ctx, http.MethodGet, "/api/v1/app/backup", nil, &out)
	return out, err
}

func (r *Remote) Restore(ctx context.Context, data []byte) error {
	var probe Backup
	if err := json.Unmarshal(data, &probe); err != nil {
		return errorf(CodeInvalid, "invalid backup file: %v", err)
	}
	return r.do(ctx, http.MethodPost, "/api/v1/app/restore", json.RawMessage(data), nil)
}

// StartTestJob starts a measurement job and returns its initial state.
func (r *Remote) StartTestJob(ctx context.Context, req TestRequest) (TestJob, error) {
	var out TestJob
	err := r.do(ctx, http.MethodPost, "/api/v1/app/tests/jobs", req, &out)
	return out, err
}

// GetTestJob returns one job's state.
func (r *Remote) GetTestJob(ctx context.Context, id string) (TestJob, error) {
	var out TestJob
	err := r.do(ctx, http.MethodGet, "/api/v1/app/tests/jobs/"+url.PathEscape(id), nil, &out)
	return out, err
}

// CancelTestJob asks the daemon to stop a running job.
func (r *Remote) CancelTestJob(ctx context.Context, id string) error {
	return r.do(ctx, http.MethodPost, "/api/v1/app/tests/jobs/"+url.PathEscape(id)+"/cancel", nil, nil)
}

// TestResults reads stored measurements for one connection.
func (r *Remote) TestResults(ctx context.Context, connectionID string) ([]TestResult, error) {
	var out []TestResult
	err := r.do(ctx, http.MethodGet, "/api/v1/app/tests/results?connection="+url.QueryEscape(connectionID), nil, &out)
	return out, err
}

// SpeedTargets lists registered download targets.
func (r *Remote) SpeedTargets(ctx context.Context) ([]SpeedTarget, error) {
	var out []SpeedTarget
	err := r.do(ctx, http.MethodGet, "/api/v1/app/tests/targets", nil, &out)
	return out, err
}

// AddSpeedTarget registers one target URL.
func (r *Remote) AddSpeedTarget(ctx context.Context, rawURL string) (SpeedTarget, error) {
	var out SpeedTarget
	err := r.do(ctx, http.MethodPost, "/api/v1/app/tests/targets", map[string]string{"url": rawURL}, &out)
	return out, err
}

// DeleteSpeedTarget removes a registered target.
func (r *Remote) DeleteSpeedTarget(ctx context.Context, id string) error {
	return r.do(ctx, http.MethodDelete, "/api/v1/app/tests/targets/"+url.PathEscape(id), nil, nil)
}

// ValidateSpeedTarget re-checks a target through the tested path.
func (r *Remote) ValidateSpeedTarget(ctx context.Context, id string) (SpeedTarget, error) {
	var out SpeedTarget
	err := r.do(ctx, http.MethodPost, "/api/v1/app/tests/targets/"+url.PathEscape(id)+"/validate", nil, &out)
	return out, err
}

// TestBudget reports the traffic a run would use.
func (r *Remote) TestBudget(ctx context.Context, req TestRequest) (TestBudget, error) {
	var out TestBudget
	err := r.do(ctx, http.MethodPost, "/api/v1/app/tests/budget", req, &out)
	return out, err
}

// UsageInfo reads the counted-byte counter.
func (r *Remote) UsageInfo(ctx context.Context) (SpeedUsage, error) {
	var out SpeedUsage
	err := r.do(ctx, http.MethodGet, "/api/v1/app/tests/usage", nil, &out)
	return out, err
}
