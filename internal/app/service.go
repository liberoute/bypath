package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/liberoute/bypath/internal/bench"
	"github.com/liberoute/bypath/internal/build"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/credential"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/layer"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/pidfile"
	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/serviceop"
)

// Contract is the application surface implemented by the in-process service
// and by the HTTP client used by the TUI and CLI.
type Contract interface {
	Status(ctx context.Context) (Status, error)
	ProbeExitIP(ctx context.Context) (string, error)
	ProbeExitIdentity(ctx context.Context) (ExitProof, error)

	ListConnections(ctx context.Context, filter ConnectionFilter) ([]Connection, error)
	GetConnection(ctx context.Context, id string) (ConnectionDetail, error)
	ImportURI(ctx context.Context, group, uri string) (ImportResult, error)
	PreviewOpenVPN(ctx context.Context, src OVPNSource) (OVPNPreview, error)
	ImportOpenVPN(ctx context.Context, req OVPNImport) (ImportResult, error)
	DeleteConnection(ctx context.Context, id string) error
	RenameConnection(ctx context.Context, id, name string) error
	SetCredentials(ctx context.Context, id string, creds Credentials, persist bool) error
	SetActive(ctx context.Context, id string) (ActionResult, error)

	ListSubscriptions(ctx context.Context) ([]Subscription, error)
	PreviewSubscription(ctx context.Context, rawURL string) (SubscriptionPreview, error)
	PreviewSubscriptionText(ctx context.Context, text string) (SubscriptionPreview, error)
	AddSubscription(ctx context.Context, group, url string) (Subscription, error)
	OrganizeSubscription(ctx context.Context, group, url, name string) (Subscription, error)
	RemoveSubscription(ctx context.Context, group, url string) error
	RefreshSubscription(ctx context.Context, group, url string, progress func(RefreshProgress)) (Subscription, error)
	ImportSubscriptionText(ctx context.Context, group, text string) (ImportResult, error)

	Connect(ctx context.Context, id string) (ActionResult, error)
	Disconnect(ctx context.Context) (ActionResult, error)
	Restart(ctx context.Context) (ActionResult, error)
	RestartService(ctx context.Context, confirm bool) (ServiceOperation, error)
	ApplyProxy(ctx context.Context, req ProxyApply) (ServiceOperation, error)
	ServiceOperation(ctx context.Context, id string) (ServiceOperation, error)
	Shutdown(ctx context.Context) (ActionResult, error)

	Logs(ctx context.Context, query LogQuery) ([]LogEntry, error)
	Bench(ctx context.Context, req BenchRequest) (bench.Report, error)
	StartTestJob(ctx context.Context, req TestRequest) (TestJob, error)
	GetTestJob(ctx context.Context, id string) (TestJob, error)
	CancelTestJob(ctx context.Context, id string) error
	TestResults(ctx context.Context, connectionID string) ([]TestResult, error)
	SpeedTargets(ctx context.Context) ([]SpeedTarget, error)
	AddSpeedTarget(ctx context.Context, rawURL string) (SpeedTarget, error)
	DeleteSpeedTarget(ctx context.Context, id string) error
	ValidateSpeedTarget(ctx context.Context, id string) (SpeedTarget, error)
	TestBudget(ctx context.Context, req TestRequest) (TestBudget, error)
	UsageInfo(ctx context.Context) (SpeedUsage, error)
	Engines(ctx context.Context) ([]Engine, error)
	Settings(ctx context.Context) (Settings, error)
	UpdateSettings(ctx context.Context, patch SettingsPatch) (SettingsChange, error)
	Backup(ctx context.Context, includeSecrets bool) (Backup, error)
	Restore(ctx context.Context, data []byte) error

	// Organisation layer: stable identity, user groups, migration and the
	// guarded delete/selection operations shared by every frontend.
	LayerStatus(ctx context.Context) (layer.Status, error)
	LayerPlan(ctx context.Context) (layer.MigrationPlan, error)
	LayerMigrate(ctx context.Context, dryRun bool) (layer.MigrationPlan, error)
	LayerRollback(ctx context.Context, confirm bool) (layer.RollbackReport, error)
	LayerGroups(ctx context.Context) ([]layer.GroupView, error)
	CreateLayerGroup(ctx context.Context, name string) (layer.Group, error)
	RenameLayerGroup(ctx context.Context, id, name string) error
	ReorderLayerGroups(ctx context.Context, ids []string) error
	DeleteLayerGroup(ctx context.Context, id string, deleteMembers bool, opts DeleteOptions) error
	MoveLayerConnections(ctx context.Context, ids []string, groupID string) error
	SetDisplayName(ctx context.Context, id, name string) error
	HideConnections(ctx context.Context, ids []string, hidden bool) error
	ConnectionDeletePlan(ctx context.Context, id string) (DeleteImpact, error)
	DeleteConnectionWithOptions(ctx context.Context, id string, opts DeleteOptions) error
	SourceDeletePlan(ctx context.Context, group, rawURL string) (SourceDeleteImpact, error)
	RemoveSubscriptionWithOptions(ctx context.Context, group, rawURL string, opts DeleteOptions) error

	// RoutingOverview is the effective policy every frontend reads. Release 1
	// surfaces it read-only in the terminal UI; editing stays in the panel and
	// the CLI.
	RoutingOverview(ctx context.Context) (RoutingOverview, error)
}

// RuntimeStatus is the gateway's live view, mirrored without importing the
// gateway package into frontends.
type RuntimeStatus struct {
	State       string
	ActiveLink  string
	ActiveGroup string
	Protocol    string
	Engine      string
	Restarts    int
	TunRestarts int
	Recovery    int
	LastError   string
	LastHealth  string
	// Health evidence distinguishes a forwarding failure from an identity
	// verification failure; see gateway.HealthEvidence.
	HealthCode           string
	HealthDetail         string
	HealthTunnelAnswered bool
	HealthExitIP         string
	HealthUplinkSamples  int
	FallbackFrom         string
	FallbackError        string
}

// Runtime is the live gateway as seen by the application service. A nil
// Runtime means the gateway is not running in this process.
type Runtime interface {
	Status() RuntimeStatus
	ApplyActiveLink(ctx context.Context) error
	StopTunnel(ctx context.Context) error
	RequestStop() error
	Engines() []Engine
	Reload(cfg *config.Config) []string
}

// Options configures the in-process service.
type Options struct {
	Paths             *paths.Resolved
	Config            *config.Config
	ConfigPath        string
	Profiles          *profile.Manager
	Credentials       *credential.Store
	Runtime           Runtime
	Engines           *engine.Manager
	Logs              *LogBuffer
	Shutdown          func()
	StartedAt         time.Time
	ServiceOperations *serviceop.Manager
}

// Local is the authoritative application service inside the gateway process.
// It wraps the gateway's existing profile manager; it never creates a second
// one, so file state and live state cannot diverge inside a process.
type Local struct {
	paths      *paths.Resolved
	configPath string
	profiles   *profile.Manager
	creds      *credential.Store
	runtime    Runtime
	engines    *engine.Manager
	logs       *LogBuffer
	shutdown   func()
	serviceOps *serviceop.Manager

	// layer is the organisation sidecar. A nil layer means the profile store
	// could not be attached; every layer operation then reports unavailable
	// while the legacy view keeps working.
	layer    *layer.Manager
	layerMu  sync.RWMutex
	layerErr string

	mu        sync.RWMutex
	cfg       *config.Config
	startedAt time.Time

	refreshMu sync.Mutex
	refresh   map[string]context.CancelFunc
	lastRef   map[string]refreshState

	benchMu sync.Mutex

	// testMu guards the in-memory job registry. One job runs at a time so the
	// S0.3 concurrency budget (2, hard cap 3) is never exceeded globally.
	testMu      sync.Mutex
	testJobs    map[string]*testJob
	testCancels map[string]context.CancelFunc
	activeTest  string
	// testLink is the per-link measurement. Tests replace it; nil means the
	// real isolated relay path.
	testLink func(ctx context.Context, t testTarget, shared testShared) TestResult

	// routingApplyMu serialises routing writes. It is separate from mu so a
	// slow tunnel restart never blocks status or read-only API calls.
	routingApplyMu sync.Mutex

	// switchMu serialises connection switches. A switch restarts the tunnel in
	// place, so two overlapping requests would fight over the same engine.
	switchMu sync.Mutex
	// prevMu guards previousID, the connection that served before the last
	// successful switch.
	prevMu     sync.RWMutex
	previousID string
}

type refreshState struct {
	at    time.Time
	err   string
	links int
}

// NewLocal builds the service. Profiles may be nil only for read-only tools;
// the gateway passes its own manager.
func NewLocal(opts Options) (*Local, error) {
	if opts.Paths == nil {
		opts.Paths = paths.Get()
	}
	if opts.Config == nil {
		cfg, err := config.Load(opts.ConfigPath)
		if err != nil {
			return nil, errorf(CodeUnavailable, "loading config: %v", err)
		}
		opts.Config = cfg
	}
	if opts.ConfigPath == "" {
		opts.ConfigPath = opts.Paths.ConfigFile
	}
	if opts.Profiles == nil {
		mgr, err := profile.NewManager(opts.Config.Profiles.Directory, opts.Config.Profiles.ActiveGroup)
		if err != nil {
			return nil, errorf(CodeInternal, "opening profiles: %v", err)
		}
		opts.Profiles = mgr
	}
	if opts.Credentials == nil {
		opts.Credentials = credential.Open(
			filepath.Join(opts.Config.Profiles.Directory, "credentials"),
			filepath.Join(opts.Paths.TmpDir, "session-credentials"),
		)
	}
	if opts.StartedAt.IsZero() {
		opts.StartedAt = time.Now()
	}
	credential.SetDefault(opts.Credentials)
	if opts.ServiceOperations == nil {
		opts.ServiceOperations = serviceop.New()
	}

	svc := &Local{
		paths:      opts.Paths,
		configPath: opts.ConfigPath,
		profiles:   opts.Profiles,
		creds:      opts.Credentials,
		runtime:    opts.Runtime,
		engines:    opts.Engines,
		logs:       opts.Logs,
		shutdown:   opts.Shutdown,
		serviceOps: opts.ServiceOperations,
		cfg:        opts.Config,
		startedAt:  opts.StartedAt,
		refresh:    make(map[string]context.CancelFunc),
		lastRef:    make(map[string]refreshState),
	}
	svc.attachLayer()
	return svc, nil
}

// Config returns the current configuration snapshot.
func (s *Local) Config() *config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Profiles exposes the shared manager to the API layer (read-only use).
func (s *Local) Profiles() *profile.Manager { return s.profiles }

// Credentials exposes the credential store to lifecycle code.
func (s *Local) Credentials() *credential.Store { return s.creds }

// Runtime exposes the live gateway, if any.
func (s *Local) Runtime() Runtime { return s.runtime }

// Running reports whether a gateway process is alive (this one or another).
func (s *Local) Running() (int, bool) {
	if s.runtime != nil {
		if pid, ok := pidfile.IsRunningFromFile(s.paths.PidFile); ok {
			return pid, true
		}
		return os.Getpid(), true
	}
	return pidfile.IsRunningFromFile(s.paths.PidFile)
}

// Status implements Contract.
func (s *Local) Status(ctx context.Context) (Status, error) {
	cfg := s.Config()
	st := Status{
		Version:      build.Version,
		Variant:      build.Variant,
		Commit:       build.Commit,
		BuildDate:    build.BuildDate,
		State:        "DISCONNECTED",
		GatewayMode:  cfg.Gateway.Enabled,
		DNSMode:      cfg.Gateway.DNSMode,
		APIPort:      cfg.Server.APIPort,
		DNSPort:      cfg.Server.DNSPort,
		SOCKSPort:    cfg.Server.SOCKSPort,
		LANInterface: cfg.Gateway.Interface,
	}
	if st.DNSMode == "" {
		st.DNSMode = "strict"
	}

	pid, running := s.Running()
	st.Running = running
	st.PID = pid
	if running {
		st.UptimeSec = int64(time.Since(s.startedAt).Seconds())
		st.State = "CONNECTING"
	}
	if s.runtime != nil {
		rs := s.runtime.Status()
		st.State = rs.State
		st.ActiveLink = rs.ActiveLink
		st.ActiveGroup = rs.ActiveGroup
		st.Protocol = rs.Protocol
		st.Engine = rs.Engine
		st.Restarts = rs.Restarts
		st.TunRestarts = rs.TunRestarts
		st.Recovery = rs.Recovery
		st.LastError = rs.LastError
		st.LastHealth = rs.LastHealth
		st.HealthCode = rs.HealthCode
		st.HealthDetail = rs.HealthDetail
		st.HealthTunnelAnswered = rs.HealthTunnelAnswered
		st.HealthExitIP = rs.HealthExitIP
		st.HealthUplinkSamples = rs.HealthUplinkSamples
		st.FallbackFrom = rs.FallbackFrom
		st.FallbackError = rs.FallbackError
	}
	// The persisted selection is reported separately: after a startup fallback
	// the gateway runs a different link than the one the operator chose.
	if link := s.profiles.GetActiveLink(); link != nil {
		st.SelectedLink = link.Remark
		st.SelectedID = ConnectionID(link.Group, link.Remark)
	}
	if prevID := s.previous(); prevID != "" {
		st.PreviousID = prevID
		if _, remark, ok := SplitID(prevID); ok {
			st.PreviousLink = remark
		}
	}
	if st.ActiveLink == "" {
		if link := s.profiles.GetActiveLink(); link != nil {
			st.ActiveLink = link.Remark
			st.ActiveGroup = link.Group
			st.ActiveID = ConnectionID(link.Group, link.Remark)
			st.Protocol = link.Protocol
			if st.Engine == "" {
				st.Engine = EngineFor(link)
			}
		}
	} else if st.ActiveGroup != "" {
		st.ActiveID = ConnectionID(st.ActiveGroup, st.ActiveLink)
	} else if link := s.findLinkByRemark(st.ActiveLink); link != nil {
		st.ActiveID = ConnectionID(link.Group, link.Remark)
	}

	for _, name := range s.profiles.ListGroups() {
		g, err := s.profiles.GetGroup(name)
		if err != nil {
			continue
		}
		st.SubCount += len(g.Subscriptions)
		for _, l := range g.Links {
			if l.Port >= 10 && l.Address != "" && l.Address != "0.0.0.0" {
				st.ProfileCount++
			}
		}
	}
	st.Selection = s.selectionInfo()
	if s.layer != nil {
		lst := s.layer.Status()
		st.LayerMigrated = lst.Migrated
		st.LayerReadOnly = lst.ReadOnly
	}
	st.LayerWarning = s.layerWarning()
	return st, nil
}

func (s *Local) findLinkByRemark(remark string) *profile.Link {
	for _, name := range s.profiles.ListGroups() {
		g, err := s.profiles.GetGroup(name)
		if err != nil {
			continue
		}
		for _, l := range g.Links {
			if l.Remark == remark {
				return l
			}
		}
	}
	return nil
}

// activeID returns the persisted active connection id, if resolvable.
func (s *Local) activeID() string {
	if s.runtime != nil {
		if rs := s.runtime.Status(); rs.ActiveLink != "" {
			if rs.ActiveGroup != "" {
				return ConnectionID(rs.ActiveGroup, rs.ActiveLink)
			}
			if l := s.findLinkByRemark(rs.ActiveLink); l != nil {
				return ConnectionID(l.Group, l.Remark)
			}
		}
	}
	if l := s.profiles.GetActiveLink(); l != nil {
		return ConnectionID(l.Group, l.Remark)
	}
	return ""
}

// findLink maps a connection id to its link and group.
func (s *Local) findLink(id string) (*profile.Link, *profile.Group, error) {
	group, remark, ok := SplitID(id)
	if !ok {
		return nil, nil, errorf(CodeInvalid, "invalid connection id %q", id)
	}
	g, err := s.profiles.GetGroup(group)
	if err != nil {
		return nil, nil, errorf(CodeNotFound, "group %q not found", group)
	}
	for _, l := range g.Links {
		if l.Remark == remark {
			return l, g, nil
		}
	}
	return nil, nil, errorf(CodeNotFound, "connection %q not found", remark)
}

// saveGroup persists the owning group of a link.
func (s *Local) saveGroup(g *profile.Group) error {
	if g == nil {
		return errorf(CodeInternal, "missing group")
	}
	if err := s.profiles.SaveGroup(g.Name); err != nil {
		return errorf(CodeInternal, "saving group %q: %v", g.Name, err)
	}
	return nil
}

// StopRuntime requests a graceful gateway shutdown.
func (s *Local) StopRuntime() error {
	if s.runtime == nil {
		return errorf(CodeUnavailable, "gateway is not running in this process")
	}
	return s.runtime.RequestStop()
}

// ShutdownNow invokes the process shutdown callback (used by API restart/stop).
func (s *Local) ShutdownNow() {
	if s.shutdown != nil {
		s.shutdown()
	}
}

// IsGatewayMode reports whether the gateway (TUN/DNS) is enabled.
func (s *Local) IsGatewayMode() bool { return s.Config().Gateway.Enabled }

// ConfigFilePath returns the active config file path.
func (s *Local) ConfigFilePath() string { return s.configPath }

// Token equals the configured API token; used by the CLI/TUI client.
func (s *Local) Token() string { return s.Config().Server.APIToken }

// ErrNotRunning is returned by lifecycle calls with no live gateway.
func ErrNotRunning() *Error {
	return &Error{
		Code:    CodeUnavailable,
		Message: "gateway is not running",
		Hint:    "start it with 'bypath run' or the service manager, then retry",
	}
}

// asAppError wraps arbitrary errors with a stable code.
func asAppError(err error, code string, context string) error {
	if err == nil {
		return nil
	}
	var ae *Error
	if errors.As(err, &ae) {
		return ae
	}
	return &Error{Code: code, Message: context + ": " + err.Error(), Err: err}
}

func joinStrings(list []string) string { return strings.Join(list, ", ") }
