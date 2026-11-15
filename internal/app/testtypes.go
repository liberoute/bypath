package app

// Test scopes, kinds and result statuses. They are part of the frozen API the
// web and TUI frontends consume; change them only with the frontends.
const (
	TestKindLatency = "latency"
	TestKindSpeed   = "speed"

	TestScopeLink  = "link"
	TestScopeGroup = "group"
	TestScopeAll   = "all"

	TestStatusOK           = "ok"
	TestStatusInconclusive = "inconclusive"
	TestStatusUnavailable  = "unavailable"
	TestStatusFailed       = "failed"
	TestStatusCancelled    = "cancelled"
	TestStatusSkipped      = "skipped"

	TestJobQueued    = "queued"
	TestJobRunning   = "running"
	TestJobDone      = "done"
	TestJobFailed    = "failed"
	TestJobCancelled = "cancelled"

	// Inconclusive reasons from TEST_PATH_PROOF_v3 §4.
	ReasonConfigNotIsolated   = "CONFIG_NOT_ISOLATED"
	ReasonPathDirectTarget    = "PATH_DIRECT_TARGET"
	ReasonExitEqualsUplink    = "EXIT_EQUALS_UPLINK"
	ReasonExitEqualsServing   = "EXIT_EQUALS_SERVING"
	ReasonExitAmbiguous       = "EXIT_AMBIGUOUS"
	ReasonExitChanged         = "EXIT_CHANGED"
	ReasonExitUnknown         = "EXIT_UNKNOWN"
	ReasonPolicyChanged       = "POLICY_CHANGED"
	ReasonControlFailed       = "CONTROL_FAILED"
	ReasonRouteExplainMissing = "ROUTE_EXPLAIN_UNAVAILABLE"
	ReasonIsolationUnverified = "ISOLATION_UNVERIFIED"
	ReasonTargetRejected      = "TARGET_REJECTED"
	ReasonBudgetReached       = "BUDGET_REACHED"
	ReasonNoProvenResult      = "NO_PROVEN_RESULT"
	// ReasonWorkerUnavailable means this daemon runs inside a network
	// namespace where an isolated instance could not be trusted, and the
	// host-side worker could not run the measurement.
	ReasonWorkerUnavailable = "WORKER_UNAVAILABLE"
)

// TestRequest starts one measurement job. The scope selects links by stable
// connection id, by organisation group, or everything.
type TestRequest struct {
	Kind          string    `json:"kind"`
	Scope         TestScope `json:"scope"`
	Parallel      int       `json:"parallel,omitempty"`
	IncludeHidden bool      `json:"include_hidden,omitempty"`
	// Upload is never supported in Release 1. The field exists so the API can
	// reject it explicitly instead of silently ignoring a request.
	Upload bool `json:"upload,omitempty"`
}

// TestScope selects the connections a job covers.
type TestScope struct {
	Kind         string `json:"kind"`
	Group        string `json:"group,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"`
}

// TestJob is the observable state of one job.
type TestJob struct {
	ID         string       `json:"id"`
	Kind       string       `json:"kind"`
	Scope      TestScope    `json:"scope"`
	State      string       `json:"state"`
	Stage      string       `json:"stage,omitempty"`
	Total      int          `json:"total"`
	Completed  int          `json:"completed"`
	StartedAt  string       `json:"started_at,omitempty"`
	FinishedAt string       `json:"finished_at,omitempty"`
	Error      string       `json:"error,omitempty"`
	Results    []TestResult `json:"results"`
}

// TestEvent is one progress event. Seq is monotonic per job so a polling or
// reconnecting client can resume after the last event it saw.
type TestEvent struct {
	Seq       int         `json:"seq"`
	JobID     string      `json:"job_id"`
	State     string      `json:"state"`
	Stage     string      `json:"stage,omitempty"`
	Completed int         `json:"completed"`
	Total     int         `json:"total"`
	Result    *TestResult `json:"result,omitempty"`
	Error     string      `json:"error,omitempty"`
}

// TestResult is one connection's outcome with the proof that produced it.
type TestResult struct {
	ConnectionID string `json:"connection_id"`
	Group        string `json:"group"`
	Remark       string `json:"remark"`
	Protocol     string `json:"protocol"`
	Kind         string `json:"kind"`
	Engine       string `json:"engine,omitempty"`
	Status       string `json:"status"`
	Reason       string `json:"reason,omitempty"`
	Detail       string `json:"detail,omitempty"`
	Category     string `json:"category,omitempty"`
	Superseded   bool   `json:"superseded,omitempty"`
	LatencyMS    int64  `json:"latency_ms"`
	P50MS        int64  `json:"p50_ms"`
	P90MS        int64  `json:"p90_ms"`
	// Speed fields. MBps is counted payload throughput; Bytes is what Bypath
	// itself counted, never true link-level usage.
	MBps          float64 `json:"mbps,omitempty"`
	Bytes         int64   `json:"bytes,omitempty"`
	Seconds       float64 `json:"seconds,omitempty"`
	Target        string  `json:"target,omitempty"`
	SupportsRange bool    `json:"supports_range,omitempty"`
	TestedAt      string  `json:"tested_at"`
	// Stale is computed at read time (older than 24 h), never stored.
	Stale bool       `json:"stale"`
	Path  *PathProof `json:"path,omitempty"`
}

// PathProof records construction, identity and accounting evidence. A result
// without L1+L2 is never rendered as healthy or ranked.
type PathProof struct {
	ProofVersion      string          `json:"proof_version,omitempty"`
	ConfigSHA256      string          `json:"config_sha256,omitempty"`
	ProfileSHA256     string          `json:"profile_sha256,omitempty"`
	EngineOwned       bool            `json:"engine_owned,omitempty"`
	TunneledHTTPS     bool            `json:"tunneled_https,omitempty"`
	Kind              string          `json:"kind"`  // "isolated" or "live"
	Level             string          `json:"level"` // "L1+L2"
	ConfigAudit       string          `json:"config_audit"`
	IsolationVerified bool            `json:"isolation_verified"`
	ExitBefore        string          `json:"exit_ip_before,omitempty"`
	ExitAfter         string          `json:"exit_ip_after,omitempty"`
	UplinkIP          string          `json:"uplink_ip,omitempty"`
	ServingExitIP     string          `json:"serving_exit_ip,omitempty"`
	Echoes            []EchoResult    `json:"echoes,omitempty"`
	RouteDecisions    []RouteDecision `json:"route_decisions,omitempty"`
	PolicyRevision    string          `json:"policy_revision,omitempty"`
	PolicyAfter       string          `json:"policy_revision_after,omitempty"`
	NegativeControl   string          `json:"negative_control"`
	Counters          *Counters       `json:"counters,omitempty"`
	Note              string          `json:"note,omitempty"`
}

// RouteDecision is the policy verdict for one measured destination, resolved
// through the same rules the tunnel runs.
type RouteDecision struct {
	Host     string   `json:"host"`
	IPs      []string `json:"ips,omitempty"`
	Decision string   `json:"decision"`
}

// EchoResult is one independent exit-identity observation.
type EchoResult struct {
	Service string `json:"service"`
	IP      string `json:"ip"`
}

// Counters is engine-reported accounting when the engine exposes it (S0.6).
type Counters struct {
	TestedOutboundBytes int64 `json:"tested_outbound_bytes"`
	DirectBytes         int64 `json:"direct_bytes"`
}

// TestBudget is what the budget dialog can show before a run starts. It never
// claims a number that stage 0 has not validated: the target is re-checked
// when the job starts.
type TestBudget struct {
	Kind          string `json:"kind"`
	Links         int    `json:"links"`
	PerLinkMB     int    `json:"per_link_mb"`
	PerBatchMB    int    `json:"per_batch_mb"`
	WorstCaseMB   int    `json:"worst_case_mb"`
	MonthlyCapMB  int    `json:"monthly_cap_mb,omitempty"`
	MonthUsedMB   int    `json:"month_used_mb"`
	Target        string `json:"target"`
	TargetURL     string `json:"target_url"`
	RouteCheck    string `json:"route_check,omitempty"`
	CheckNote     string `json:"check_note"`
	UploadEnabled bool   `json:"upload_enabled"`
}

// SpeedUsage is the counted-byte counter as shown in the accounting footnote.
type SpeedUsage struct {
	Month        string `json:"month"`
	Bytes        int64  `json:"bytes"`
	MonthlyCapMB int    `json:"monthly_cap_mb,omitempty"`
	// Label states what the number is. It is payload counted by Bypath, never
	// true link-level usage.
	Label string `json:"label"`
}
