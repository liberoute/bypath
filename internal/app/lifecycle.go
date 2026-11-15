package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/gateway"
	"github.com/liberoute/bypath/internal/profile"
)

// ProbeExitIP asks a public echo service through the tunnel what address the
// world sees. It returns an error rather than a guess when the gateway is not
// carrying traffic.
func (s *Local) ProbeExitIP(ctx context.Context) (string, error) {
	if s.runtime == nil {
		return "", ErrNotRunning()
	}
	if rs := s.runtime.Status(); rs.State != "CONNECTED" {
		return "", errorf(CodeUnavailable, "gateway is %s; the exit address is unknown", strings.ToLower(rs.State))
	}
	body, err := profile.FetchThroughProxy(ctx, s.Config().Server.SOCKSPort, "https://api.ipify.org", 128)
	if err != nil {
		return "", asAppError(err, CodeUnavailable, "exit IP probe failed")
	}
	candidate := strings.TrimSpace(string(body))
	if ip := net.ParseIP(candidate); ip == nil {
		return "", errorf(CodeUnavailable, "exit IP probe returned an unexpected response")
	}
	return candidate, nil
}

// ExitProof is the pre-activation evidence for a first-run gateway. It keeps
// three questions apart: did the tunnel carry traffic (DataPathOK, sampled
// only when no identity oracle answered), what did the identity services see
// through the tunnel (Exits), and what does this host look like directly
// (Uplink). Empty sides mean the oracles were unreachable, not that the tunnel
// failed.
type ExitProof struct {
	Exits          []string `json:"exits,omitempty"`
	Uplink         []string `json:"uplink,omitempty"`
	Oracles        int      `json:"oracles"`
	DataPathOK     bool     `json:"data_path_ok"`
	DataPathDetail string   `json:"data_path_detail,omitempty"`
}

// ActivationVerdict is the outcome a caller may act on. Allowed says the
// gateway may be enabled; Verified says the exit was positively identified and
// differs from the direct uplink. Only Verified evidence may be reported as
// healthy or verified.
type ActivationVerdict struct {
	Allowed  bool
	Verified bool
	Detail   string
}

// Verdict applies the activation rule. A blocked oracle set is not a dead
// tunnel: when the data-path check passed, activation is allowed but the exit
// stays UNVERIFIED. A refused verdict is reserved for a tunnel that carried no
// traffic or an exit that equals this host's own address.
func (p ExitProof) Verdict() ActivationVerdict {
	exits := distinctIPs(p.Exits)
	uplink := distinctIPs(p.Uplink)
	if len(exits) == 0 {
		if p.DataPathOK {
			return ActivationVerdict{
				Allowed: true,
				Detail:  fmt.Sprintf("the tunnel carried traffic, but none of %d identity services answered; the exit address is UNVERIFIED", p.Oracles),
			}
		}
		detail := "the tunnel is connected but no traffic reached the internet"
		if p.DataPathDetail != "" {
			detail += ": " + p.DataPathDetail
		}
		return ActivationVerdict{Detail: detail}
	}
	if len(uplink) == 0 {
		return ActivationVerdict{
			Allowed: true,
			Detail:  "the tunnel exit was observed, but this host's direct address could not be verified; the exit is UNVERIFIED",
		}
	}
	known := make(map[string]bool, len(uplink))
	for _, ip := range uplink {
		known[ip] = true
	}
	for _, exit := range exits {
		if known[exit] {
			return ActivationVerdict{Detail: "the observed exit equals this host's direct address, so the tunnel is not carrying traffic"}
		}
	}
	return ActivationVerdict{Allowed: true, Verified: true, Detail: "the exit differs from the direct address"}
}

// ProbeExitIdentity observes the tunnel exit through every independent oracle
// and, only when none of them answered, verifies the data path separately. It
// never reports the tunnel as failed merely because an identity service is
// unreachable.
func (s *Local) ProbeExitIdentity(ctx context.Context) (ExitProof, error) {
	if s.runtime == nil {
		return ExitProof{}, ErrNotRunning()
	}
	if rs := s.runtime.Status(); rs.State != "CONNECTED" {
		return ExitProof{}, errorf(CodeUnavailable, "gateway is %s; the exit identity is unknown", strings.ToLower(rs.State))
	}
	port := s.Config().Server.SOCKSPort
	through := func(ctx context.Context, target string) (string, error) {
		return gateway.FetchExitIPThroughProxy(ctx, port, target)
	}
	id := gateway.CollectExitIdentity(ctx, through, gateway.FetchExitIPDirect)
	proof := ExitProof{Exits: id.Exits, Uplink: id.Uplink, Oracles: id.Attempts}
	if len(id.Exits) == 0 {
		proof.DataPathOK, proof.DataPathDetail = gateway.ProbeDataPath(ctx, socksProbeAddress(s.Config().Server.SOCKSListen, port), 6*time.Second)
	}
	return proof, nil
}

func socksProbeAddress(listen string, port int) string {
	listen = strings.TrimSpace(listen)
	if listen == "" || listen == "0.0.0.0" || listen == "::" {
		listen = "127.0.0.1"
	}
	return net.JoinHostPort(listen, strconv.Itoa(port))
}

func distinctIPs(samples []string) []string {
	seen := make(map[string]bool, len(samples))
	out := make([]string, 0, len(samples))
	for _, sample := range samples {
		ip := net.ParseIP(strings.TrimSpace(sample))
		if ip == nil || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		out = append(out, ip.String())
	}
	return out
}

// ExitInfo is what an operator needs to see: the address the world sees and
// where it is registered. Country is resolved through the tunnel too, so the
// answer describes the serving exit rather than the gateway host.
type ExitInfo struct {
	IP          string `json:"ip"`
	Country     string `json:"country,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	City        string `json:"city,omitempty"`
	Org         string `json:"org,omitempty"`
}

// ProbeExitInfo resolves the public exit address and its country. The country
// lookup is best effort: a working exit IP is still useful when the geolocation
// service is unreachable.
func (s *Local) ProbeExitInfo(ctx context.Context) (ExitInfo, error) {
	if s.runtime == nil {
		return ExitInfo{}, ErrNotRunning()
	}
	if rs := s.runtime.Status(); rs.State != "CONNECTED" {
		return ExitInfo{}, errorf(CodeUnavailable, "gateway is %s; the exit address is unknown", strings.ToLower(rs.State))
	}
	body, err := profile.FetchThroughProxy(ctx, s.Config().Server.SOCKSPort, "https://ipwho.is/", 8192)
	if err == nil {
		var raw struct {
			Success     bool   `json:"success"`
			IP          string `json:"ip"`
			Country     string `json:"country"`
			CountryCode string `json:"country_code"`
			City        string `json:"city"`
			Connection  struct {
				ISP string `json:"isp"`
			} `json:"connection"`
		}
		if jsonErr := json.Unmarshal(body, &raw); jsonErr == nil && raw.Success && net.ParseIP(raw.IP) != nil {
			return ExitInfo{
				IP:          raw.IP,
				Country:     raw.Country,
				CountryCode: raw.CountryCode,
				City:        raw.City,
				Org:         raw.Connection.ISP,
			}, nil
		}
	}
	ip, ipErr := s.ProbeExitIP(ctx)
	if ipErr != nil {
		return ExitInfo{}, asAppError(ipErr, CodeUnavailable, "exit IP probe failed")
	}
	return ExitInfo{IP: ip}, nil
}

// Connect selects a connection and applies it. Applying means restarting the
// tunnel stack in place; it is never reported as applied when it did not happen.
// A failed switch is rolled back to the connection that was serving before it,
// so a bad profile cannot leave the gateway down with no way back.
func (s *Local) Connect(ctx context.Context, id string) (ActionResult, error) {
	s.switchMu.Lock()
	defer s.switchMu.Unlock()
	return s.connectLocked(ctx, id)
}

func (s *Local) connectLocked(ctx context.Context, id string) (ActionResult, error) {
	if err := s.serviceMutationGuard(); err != nil {
		return ActionResult{}, err
	}
	link, group, err := s.findLink(id)
	if err != nil {
		return ActionResult{}, err
	}
	// Refuse before touching .active: an OpenVPN profile that asks for a
	// username/password cannot start without one, and persisting the request
	// first would leave a selection that can never serve.
	if s.credentialsMissing(link) {
		return ActionResult{}, errorf(CodeNeedsCreds, "%q needs a username and password; enter credentials before connecting", link.Remark)
	}
	// Capture the previous identity before persisting the request: remarks are
	// only unique inside a group, so the remark alone cannot tell "already
	// active" from a same-named link in another group.
	prevGroup, prevRemark := s.activeIdentity()
	prevID := s.activeID()
	s.profiles.SetActiveLink(link)

	if s.runtime == nil {
		s.maybeRecordSelection(link)
		return ActionResult{
			Applied:         false,
			RestartRequired: true,
			Message:         fmt.Sprintf("Selected %q. The gateway is not running; start it to connect.", link.Remark),
		}, nil
	}
	rs := s.runtime.Status()
	if prevGroup == group.Name && prevRemark == link.Remark && rs.State == "CONNECTED" {
		s.maybeRecordSelection(link)
		return ActionResult{Applied: true, Message: fmt.Sprintf("%q is already the active connection.", link.Remark)}, nil
	}
	if err := s.runtime.ApplyActiveLink(ctx); err != nil {
		restored, restoreErr := s.rollbackSelection(prevID, id)
		if restored {
			return ActionResult{}, &Error{
				Code:    CodeUnavailable,
				Message: fmt.Sprintf("could not connect to %q: %s", link.Remark, Redact(err.Error())),
				Hint:    fmt.Sprintf("the switch was rolled back and %q is serving again", s.previousLinkLabel()),
				Err:     err,
			}
		}
		hint := "the gateway stopped the previous tunnel before the new link was ready; check Status and the logs, then retry"
		if restoreErr != nil {
			hint = fmt.Sprintf("the previous connection could not be restored (%s); use Restore Previous or reconnect manually", Redact(restoreErr.Error()))
		}
		return ActionResult{}, &Error{
			Code:    CodeUnavailable,
			Message: "could not apply the connection: " + Redact(err.Error()),
			Hint:    hint,
			Err:     err,
		}
	}
	// The gateway may fail over to another link in the group. Report the link
	// that is actually carrying traffic, not the one that was requested.
	activeGroup, activeRemark := s.activeIdentity()
	if prevID != "" && prevID != id {
		s.setPrevious(prevID)
	}
	s.maybeRecordSelection(link)
	if activeRemark != "" && (activeRemark != link.Remark || (activeGroup != "" && activeGroup != group.Name)) {
		label := activeRemark
		if activeGroup != "" && activeGroup != group.Name {
			label = ConnectionID(activeGroup, activeRemark)
		}
		return ActionResult{
			Applied: true,
			Message: fmt.Sprintf("Connected through %q instead; %q did not come up. The gateway was restarted to apply the fallback link.", label, link.Remark),
		}, nil
	}
	return ActionResult{
		Applied: true,
		Message: fmt.Sprintf("Connected through %q. The gateway was restarted to apply the new tunnel.", link.Remark),
	}, nil
}

// previousRestoreBudget bounds the automatic rollback. It is deliberately
// independent of the caller's context: a browser that navigated away must not
// prevent the gateway from returning to a working connection.
const previousRestoreBudget = 6 * time.Minute

// rollbackSelection re-applies the connection that served before a failed
// switch. It reports whether the rollback itself succeeded.
func (s *Local) rollbackSelection(prevID, failedID string) (bool, error) {
	if prevID == "" || prevID == failedID {
		return false, nil
	}
	link, _, err := s.findLink(prevID)
	if err != nil {
		return false, err
	}
	s.profiles.SetActiveLink(link)
	if s.runtime == nil {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), previousRestoreBudget)
	defer cancel()
	if err := s.runtime.ApplyActiveLink(ctx); err != nil {
		return false, err
	}
	s.setPrevious(prevID)
	return true, nil
}

// RestorePrevious switches back to the connection that served before the last
// successful switch. It is the operator-facing recovery path after a bad
// profile, and it goes through the same bounded, serialised apply as Connect.
func (s *Local) RestorePrevious(ctx context.Context) (ActionResult, error) {
	s.switchMu.Lock()
	defer s.switchMu.Unlock()
	id := s.previous()
	if id == "" {
		return ActionResult{}, errorf(CodeConflict, "no previous connection is known yet")
	}
	return s.connectLocked(ctx, id)
}

func (s *Local) setPrevious(id string) {
	s.prevMu.Lock()
	s.previousID = id
	s.prevMu.Unlock()
}

func (s *Local) previous() string {
	s.prevMu.RLock()
	defer s.prevMu.RUnlock()
	return s.previousID
}

func (s *Local) previousLinkLabel() string {
	_, remark, ok := SplitID(s.previous())
	if !ok || remark == "" {
		return "the previous connection"
	}
	return remark
}

// activeIdentity resolves the group and remark of the connection the gateway
// reports as carrying traffic. Either value is empty when it is unknown.
func (s *Local) activeIdentity() (string, string) {
	remark, group := "", ""
	if s.runtime != nil {
		rs := s.runtime.Status()
		remark, group = rs.ActiveLink, rs.ActiveGroup
	}
	if l := s.profiles.GetActiveLink(); l != nil && (remark == "" || (l.Remark == remark && (group == "" || l.Group == group))) {
		return l.Group, l.Remark
	}
	if remark != "" {
		if group != "" {
			return group, remark
		}
		if l := s.findLinkByRemark(remark); l != nil {
			return l.Group, l.Remark
		}
		return "", remark
	}
	return "", ""
}

// Disconnect stops the active tunnel but leaves the management service
// running. The web panel and the control socket stay reachable so the operator
// can reconnect without SSH. Shutting the daemon down is an explicit action.
func (s *Local) Disconnect(ctx context.Context) (ActionResult, error) {
	s.switchMu.Lock()
	defer s.switchMu.Unlock()
	if err := s.serviceMutationGuard(); err != nil {
		return ActionResult{}, err
	}
	if s.runtime == nil {
		return ActionResult{Applied: false, Message: "The tunnel is already disconnected."}, nil
	}
	if err := s.runtime.StopTunnel(ctx); err != nil {
		return ActionResult{}, asAppError(err, CodeUnavailable, "disconnecting the tunnel")
	}
	return ActionResult{Applied: true, Message: "Tunnel disconnected. The management service stays available."}, nil
}

// Shutdown stops the daemon process (CLI: bypath stop). It is separate from
// Disconnect so browser-based management is not lost on every VPN disconnect.
func (s *Local) Shutdown(ctx context.Context) (ActionResult, error) {
	if s.runtime == nil {
		return ActionResult{Applied: false, Message: "The daemon is already stopped."}, nil
	}
	if err := s.runtime.RequestStop(); err != nil {
		return ActionResult{}, asAppError(err, CodeUnavailable, "stopping the daemon")
	}
	return ActionResult{Applied: true, Message: "Daemon shutdown requested."}, nil
}

// Restart restarts the tunnel stack in place without stopping the API process.
func (s *Local) Restart(ctx context.Context) (ActionResult, error) {
	s.switchMu.Lock()
	defer s.switchMu.Unlock()
	if err := s.serviceMutationGuard(); err != nil {
		return ActionResult{}, err
	}
	if s.runtime == nil {
		return ActionResult{}, ErrNotRunning()
	}
	activePath := filepath.Join(s.Config().Profiles.Directory, ".active")
	saved, readErr := os.ReadFile(activePath)
	serving := s.activeID()
	applyCtx, cancel := context.WithTimeout(ctx, previousRestoreBudget)
	err := s.runtime.ApplyActiveLink(applyCtx)
	cancel()
	if err != nil {
		if link, _, findErr := s.findLink(serving); findErr == nil {
			s.profiles.SetActiveLink(link)
		}
		recoveryCtx, recoveryCancel := context.WithTimeout(context.Background(), previousRestoreBudget)
		recoveryErr := s.runtime.ApplyActiveLink(recoveryCtx)
		recoveryCancel()
		if readErr == nil {
			if writeErr := os.WriteFile(activePath, saved, 0600); writeErr != nil {
				recoveryErr = writeErr
			}
		}
		hint := "recovery could not restore the previous tunnel; inspect status and retry"
		if recoveryErr == nil && s.runtime.Status().State == "CONNECTED" {
			hint = "the previous tunnel is serving again; the saved selection was preserved"
		}
		return ActionResult{}, &Error{Code: CodeUnavailable, Message: "tunnel reconnect failed: " + Redact(err.Error()), Hint: hint, Err: err}
	}
	rs := s.runtime.Status()
	if rs.State != "CONNECTED" {
		return ActionResult{}, errorf(CodeUnavailable, "tunnel reconnect has not reached serving state")
	}
	return ActionResult{Applied: true, Message: fmt.Sprintf("Tunnel reconnected; %q is currently serving. The daemon/service was not restarted.", ConnectionID(rs.ActiveGroup, rs.ActiveLink))}, nil
}

// Logs returns recent redacted events. The in-memory ring buffer is preferred;
// the log file is only read when no buffer is attached.
func (s *Local) Logs(ctx context.Context, query LogQuery) ([]LogEntry, error) {
	limit := query.Limit
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	if s.logs != nil {
		return s.logs.Recent(limit), nil
	}
	return tailLogFile(s.paths.LogDir, limit)
}

// Engines lists the tunnel engines this installation knows about.
func (s *Local) Engines(ctx context.Context) ([]Engine, error) {
	if s.runtime != nil {
		return s.runtime.Engines(), nil
	}
	if s.engines == nil {
		return nil, nil
	}
	return engineViews(s.engines.List()), nil
}

func engineViews(list []*engine.Engine) []Engine {
	out := make([]Engine, 0, len(list))
	for _, e := range list {
		out = append(out, Engine{
			Name:    e.Name,
			Version: e.Version,
			Path:    e.Path,
			Source:  e.Source,
			Ready:   e.Path != "",
		})
	}
	return out
}

func tailLogFile(logDir string, limit int) ([]LogEntry, error) {
	if logDir == "" {
		return nil, nil
	}
	path := filepath.Join(logDir, "error.log")
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, asAppError(err, CodeUnavailable, "opening the log file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, asAppError(err, CodeUnavailable, "reading the log file")
	}
	const window = 256 << 10
	start := info.Size() - window
	if start < 0 {
		start = 0
	}
	if _, err := f.Seek(start, 0); err != nil {
		return nil, asAppError(err, CodeUnavailable, "seeking the log file")
	}
	data := make([]byte, window)
	n, _ := f.Read(data)
	lines := strings.Split(strings.TrimRight(Redact(string(data[:n])), "\n"), "\n")
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	out := make([]LogEntry, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, LogEntry{Level: levelOf(line), Message: line})
	}
	return out, nil
}
