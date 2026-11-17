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
	TestStatusMeasured     = "measured"
	TestStatusInconclusive = "inconclusive"
	TestStatusUnavailable  = "unavailable"
	TestStatusFailed       = "failed"
	TestStatusCancelled    = "cancelled"
	TestStatusSkipped      = "skipped"

	// Evidence layers. An operational result answers a real HTTPS request
	// through the tested connection but does not bind the exit identity. A
	// verified result carries the full L1+L2 proof. Only the verified layer is
	// ranked as a proven path; the operational layer is what makes shared-exit
	// subscriptions usable at all.
	EvidenceOperational = "operational"
	EvidenceVerified    = "verified"

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
	// Traffic plan for a speed job, computed before the first byte moves. The
	// worst case is what the monthly refusal checks; the batch stops on the
	// bytes it actually spent, so a cheap run can cover more connections than
	// the worst case promises.
	PlannedBytes  int64 `json:"planned_bytes,omitempty"`
	PlannedLinks  int   `json:"planned_links,omitempty"`
	BudgetSkipped int   `json:"budget_skipped,omitempty"`
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
	// Evidence names the layer behind the numbers: "verified" for an L1+L2
	// proof, "operational" for a real HTTPS measurement whose exit ownership
	// is unproven. Empty on legacy rows and on rows with no measurement.
	Evidence string `json:"evidence,omitempty"`
	// HTTPSProven is set only after a real HTTPS response arrived through the
	// tested connection. An open listener or a TCP handshake never sets it.
	HTTPSProven bool  `json:"https_proven,omitempty"`
	Superseded  bool  `json:"superseded,omitempty"`
	LatencyMS   int64 `json:"latency_ms"`
	P50MS       int64 `json:"p50_ms"`
	P90MS       int64 `json:"p90_ms"`
	// DelayMS is the fast per-connection delay: one low-overhead HTTPS request
	// that stops at the response headers. LatencyMS/P50/P90 stay the full
	// exchange metric, so a slow body never inflates the delay.
	DelayMS int64 `json:"delay_ms,omitempty"`
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
	// Bootstrap records where the tested endpoint's address was pinned from:
	// "lan:<ip:port>" for a configured LAN resolver, "host" for the
	// pre-takeover DHCP resolvers, "literal" when no lookup was needed. The
	// pin must never come from the tunnel this host serves.
	Bootstrap string     `json:"bootstrap,omitempty"`
	Counters  *Counters  `json:"counters,omitempty"`
	Note      string     `json:"note,omitempty"`
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
	LinksMeasured int    `json:"links_measured"`
	LinksSkipped  int    `json:"links_skipped"`
	PerLinkMB     int    `json:"per_link_mb"`
	PerBatchMB    int    `json:"per_batch_mb"`
	WorstCaseMB   int    `json:"worst_case_mb"`
	MonthlyCapMB  int    `json:"monthly_cap_mb,omitempty"`
	MonthUsedMB   int    `json:"month_used_mb"`
	RemainingMB   int    `json:"month_remaining_mb,omitempty"`
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
