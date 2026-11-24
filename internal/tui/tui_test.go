package tui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/bench"
	"github.com/liberoute/bypath/internal/layer"
)

// stubService records every contract call the TUI makes so tests can assert the
// frontend owns no business logic of its own.
type stubService struct {
	status    app.Status
	statusErr error

	conns []app.Connection
	subs  []app.Subscription

	engines  []app.Engine
	settings app.Settings
	logs     []app.LogEntry

	preview    app.OVPNPreview
	previewErr error
	importRes  app.ImportResult
	importErr  error

	exitIP  string
	exitErr error

	patchChange app.SettingsChange
	patchErr    error

	previewSub    app.SubscriptionPreview
	previewSubErr error

	lastFilter      app.ConnectionFilter
	lastPreviewURL  string
	lastPreviewText string
	lastAddGroup    string
	lastAddURL      string
	lastCredID      string
	lastCred        app.Credentials
	lastPersist     bool
	lastImport      app.OVPNImport
	lastPreview     app.OVPNSource
	lastPatch       app.SettingsPatch
	lastRefresh     [][2]string
	lastConnect     string
	lastActiveID    string
	disconnects     int

	refreshLinks int

	benchReport    bench.Report
	benchErr       error
	lastBenchGroup string
}

var _ app.Contract = (*stubService)(nil)

func (s *stubService) Status(context.Context) (app.Status, error) { return s.status, s.statusErr }

func (s *stubService) ProbeExitIP(context.Context) (string, error) { return s.exitIP, s.exitErr }

func (s *stubService) ProbeExitIdentity(context.Context) (app.ExitProof, error) {
	if s.exitErr != nil {
		return app.ExitProof{}, s.exitErr
	}
	return app.ExitProof{Exits: []string{s.exitIP}}, nil
}

func (s *stubService) ListConnections(_ context.Context, f app.ConnectionFilter) ([]app.Connection, error) {
	s.lastFilter = f
	if f.Search == "" || f.Group != "" {
		return append([]app.Connection(nil), s.conns...), nil
	}
	needle := strings.ToLower(f.Search)
	var out []app.Connection
	for _, c := range s.conns {
		if strings.Contains(strings.ToLower(c.Remark), needle) || strings.Contains(strings.ToLower(c.Address), needle) {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *stubService) GetConnection(_ context.Context, id string) (app.ConnectionDetail, error) {
	for _, c := range s.conns {
		if c.ID == id {
			d := app.ConnectionDetail{Connection: c, OVPN: c.Protocol == "openvpn"}
			if c.CredentialsSaved {
				d.CredentialStore = "saved"
			} else if c.HasCredentials {
				d.CredentialStore = "session"
			}
			return d, nil
		}
	}
	return app.ConnectionDetail{}, fmt.Errorf("connection %q not found", id)
}

func (s *stubService) ImportURI(_ context.Context, group, _ string) (app.ImportResult, error) {
	return app.ImportResult{Created: []app.Connection{{ID: group + ":imported", Group: group, Remark: "imported"}}, Group: group}, nil
}

func (s *stubService) PreviewOpenVPN(_ context.Context, src app.OVPNSource) (app.OVPNPreview, error) {
	s.lastPreview = src
	return s.preview, s.previewErr
}

func (s *stubService) ImportOpenVPN(_ context.Context, req app.OVPNImport) (app.ImportResult, error) {
	s.lastImport = req
	return s.importRes, s.importErr
}

func (s *stubService) DeleteConnection(context.Context, string) error { return nil }

func (s *stubService) RenameConnection(context.Context, string, string) error { return nil }

func (s *stubService) SetCredentials(_ context.Context, id string, creds app.Credentials, persist bool) error {
	s.lastCredID = id
	s.lastCred = creds
	s.lastPersist = persist
	return nil
}

func (s *stubService) SetActive(_ context.Context, id string) (app.ActionResult, error) {
	s.lastActiveID = id
	return app.ActionResult{Message: "Selection saved; restart the gateway to apply it."}, nil
}

func (s *stubService) ListSubscriptions(context.Context) ([]app.Subscription, error) {
	return append([]app.Subscription(nil), s.subs...), nil
}

func (s *stubService) AddSubscription(_ context.Context, group, url string) (app.Subscription, error) {
	s.lastAddGroup = group
	s.lastAddURL = url
	if group == "" {
		group = "default" // the backend derives the proposed name from the URL
	}
	return app.Subscription{Group: group, URL: url}, nil
}

func (s *stubService) PreviewSubscription(_ context.Context, rawURL string) (app.SubscriptionPreview, error) {
	s.lastPreviewURL = rawURL
	return s.previewSub, s.previewSubErr
}

func (s *stubService) PreviewSubscriptionText(_ context.Context, text string) (app.SubscriptionPreview, error) {
	s.lastPreviewText = text
	return s.previewSub, s.previewSubErr
}

func (s *stubService) RemoveSubscription(context.Context, string, string) error { return nil }

func (s *stubService) RefreshSubscription(_ context.Context, group, url string, _ func(app.RefreshProgress)) (app.Subscription, error) {
	s.lastRefresh = append(s.lastRefresh, [2]string{group, url})
	links := s.refreshLinks
	if links == 0 {
		links = 1
	}
	return app.Subscription{Group: group, URL: url, LinkCount: links}, nil
}

func (s *stubService) ImportSubscriptionText(context.Context, string, string) (app.ImportResult, error) {
	return app.ImportResult{Group: "default", Created: []app.Connection{{ID: "default:one"}}}, nil
}

func (s *stubService) Connect(_ context.Context, id string) (app.ActionResult, error) {
	s.lastConnect = id
	return app.ActionResult{Applied: true, Message: "Tunnel restarted on the selected connection."}, nil
}

func (s *stubService) Disconnect(context.Context) (app.ActionResult, error) {
	s.disconnects++
	return app.ActionResult{Applied: true, Message: "Tunnel disconnected. The management service stays available."}, nil
}

func (s *stubService) Shutdown(context.Context) (app.ActionResult, error) {
	return app.ActionResult{Applied: true, Message: "Daemon shutdown requested."}, nil
}

func (s *stubService) Restart(context.Context) (app.ActionResult, error) {
	return app.ActionResult{Applied: true, Message: "Tunnel restarted."}, nil
}

func (s *stubService) RestartService(context.Context, bool) (app.ServiceOperation, error) {
	return app.ServiceOperation{ID: "stub", State: "restarting"}, nil
}

func (s *stubService) ApplyProxy(context.Context, app.ProxyApply) (app.ServiceOperation, error) {
	return app.ServiceOperation{ID: "stub", State: "restarting"}, nil
}

func (s *stubService) ServiceOperation(context.Context, string) (app.ServiceOperation, error) {
	return app.ServiceOperation{ID: "stub", State: "serving"}, nil
}

func (s *stubService) Logs(context.Context, app.LogQuery) ([]app.LogEntry, error) {
	return append([]app.LogEntry(nil), s.logs...), nil
}

func (s *stubService) Bench(_ context.Context, req app.BenchRequest) (bench.Report, error) {
	s.lastBenchGroup = req.Group
	return s.benchReport, s.benchErr
}

func (s *stubService) Engines(context.Context) ([]app.Engine, error) {
	return append([]app.Engine(nil), s.engines...), nil
}

func (s *stubService) Settings(context.Context) (app.Settings, error) { return s.settings, nil }

func (s *stubService) UpdateSettings(_ context.Context, patch app.SettingsPatch) (app.SettingsChange, error) {
	s.lastPatch = patch
	return s.patchChange, s.patchErr
}

func (s *stubService) Backup(context.Context, bool) (app.Backup, error) {
	return app.Backup{Version: 1}, nil
}

func (s *stubService) Restore(context.Context, []byte) error { return nil }

// --- organisation layer (not exercised by the existing TUI screens yet) ---

func (s *stubService) LayerStatus(context.Context) (layer.Status, error) { return layer.Status{}, nil }

func (s *stubService) LayerPlan(context.Context) (layer.MigrationPlan, error) {
	return layer.MigrationPlan{}, nil
}

func (s *stubService) LayerMigrate(context.Context, bool) (layer.MigrationPlan, error) {
	return layer.MigrationPlan{}, nil
}

func (s *stubService) LayerRollback(context.Context, bool) (layer.RollbackReport, error) {
	return layer.RollbackReport{}, nil
}

func (s *stubService) LayerGroups(context.Context) ([]layer.GroupView, error) { return nil, nil }

func (s *stubService) CreateLayerGroup(context.Context, string) (layer.Group, error) {
	return layer.Group{}, nil
}

func (s *stubService) RenameLayerGroup(context.Context, string, string) error { return nil }

func (s *stubService) ReorderLayerGroups(context.Context, []string) error { return nil }

func (s *stubService) DeleteLayerGroup(context.Context, string, bool, app.DeleteOptions) error {
	return nil
}

func (s *stubService) MoveLayerConnections(context.Context, []string, string) error { return nil }

func (s *stubService) SetDisplayName(context.Context, string, string) error { return nil }

func (s *stubService) HideConnections(context.Context, []string, bool) error { return nil }
func (s *stubService) StartTestJob(context.Context, app.TestRequest) (app.TestJob, error) {
	return app.TestJob{}, nil
}
func (s *stubService) GetTestJob(context.Context, string) (app.TestJob, error) {
	return app.TestJob{}, nil
}
func (s *stubService) SpeedTargets(context.Context) ([]app.SpeedTarget, error) {
	return nil, nil
}
func (s *stubService) AddSpeedTarget(context.Context, string) (app.SpeedTarget, error) {
	return app.SpeedTarget{}, nil
}
func (s *stubService) DeleteSpeedTarget(context.Context, string) error { return nil }
func (s *stubService) ValidateSpeedTarget(context.Context, string) (app.SpeedTarget, error) {
	return app.SpeedTarget{}, nil
}
func (s *stubService) TestBudget(context.Context, app.TestRequest) (app.TestBudget, error) {
	return app.TestBudget{}, nil
}
func (s *stubService) UsageInfo(context.Context) (app.SpeedUsage, error) {
	return app.SpeedUsage{}, nil
}
func (s *stubService) CancelTestJob(context.Context, string) error { return nil }
func (s *stubService) TestResults(context.Context, string) ([]app.TestResult, error) {
	return nil, nil
}

func (s *stubService) ConnectionDeletePlan(context.Context, string) (app.DeleteImpact, error) {
	return app.DeleteImpact{Allowed: true}, nil
}

func (s *stubService) DeleteConnectionWithOptions(context.Context, string, app.DeleteOptions) error {
	return nil
}

func (s *stubService) SourceDeletePlan(context.Context, string, string) (app.SourceDeleteImpact, error) {
	return app.SourceDeleteImpact{Allowed: true}, nil
}

func (s *stubService) RemoveSubscriptionWithOptions(context.Context, string, string, app.DeleteOptions) error {
	return nil
}

func (s *stubService) RoutingOverview(context.Context) (app.RoutingOverview, error) {
	return app.RoutingOverview{Mode: "rules", DefaultOutbound: "proxy", DNSMode: "strict"}, nil
}

// --- harness ---

func testMenu(t *testing.T, svc app.Contract) *Menu {
	t.Helper()
	m := newWithService(svc, nil)
	m.width, m.height = 100, 30
	return m
}

func keyMsg(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "shift+tab":
		return tea.KeyMsg{Type: tea.KeyShiftTab}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "pgup":
		return tea.KeyMsg{Type: tea.KeyPgUp}
	case "pgdown":
		return tea.KeyMsg{Type: tea.KeyPgDown}
	case "ctrl+u":
		return tea.KeyMsg{Type: tea.KeyCtrlU}
	case "ctrl+s":
		return tea.KeyMsg{Type: tea.KeyCtrlS}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

// cmdTimeout is long enough for instant stub calls and short enough to abandon
// ticker commands (120 ms spinner, 4 s poll) instead of sleeping in tests.
const cmdTimeout = 120 * time.Millisecond

// exec runs a command tree, feeding every produced message back into Update.
// Tick-based commands time out and are dropped.
func runCmd(t *testing.T, m *Menu, cmd tea.Cmd) {
	t.Helper()
	if cmd == nil {
		return
	}
	ch := make(chan tea.Msg, 1)
	go func() {
		defer func() { _ = recover() }()
		ch <- cmd()
	}()
	select {
	case msg, ok := <-ch:
		if !ok || msg == nil {
			return
		}
		if batch, isBatch := msg.(tea.BatchMsg); isBatch {
			for _, sub := range batch {
				runCmd(t, m, sub)
			}
			return
		}
		switch msg.(type) {
		case pollMsg, spinnerMsg:
			return
		}
		_, next := m.Update(msg)
		runCmd(t, m, next)
	case <-time.After(cmdTimeout):
		// Ticker command; intentionally abandoned.
	}
}

func press(t *testing.T, m *Menu, keys ...string) {
	t.Helper()
	for _, k := range keys {
		_, cmd := m.Update(keyMsg(k))
		runCmd(t, m, cmd)
	}
}

func typeText(t *testing.T, m *Menu, text string) {
	t.Helper()
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(text)})
	runCmd(t, m, cmd)
}

func sampleConnections() []app.Connection {
	return []app.Connection{
		{
			ID: "examplevpn:Example Amsterdam", Group: "examplevpn", Remark: "Example Amsterdam",
			Protocol: "openvpn", Address: "nl.example.net", Port: 1194, Network: "udp",
			Engine: "sing-box", RequiresAuth: true, Health: "ok",
		},
		{
			ID: "default:Reality", Group: "default", Remark: "Reality",
			Protocol: "vless", Address: "reality.example.net", Port: 443, Network: "tcp",
			Engine: "xray", TLS: true, Reality: true, Active: true,
		},
	}
}

// --- tests ---

func TestNavigationAndResponsiveLayout(t *testing.T) {
	svc := &stubService{conns: sampleConnections()}
	m := testMenu(t, svc)

	press(t, m, "2")
	if m.section != secConnections {
		t.Fatalf("section = %v, want connections", m.section)
	}
	if len(m.conns) != 2 {
		t.Fatalf("connections = %d, want 2", len(m.conns))
	}

	press(t, m, "tab")
	if m.section != secTests {
		t.Fatalf("tab from connections = %v, want tests", m.section)
	}
	press(t, m, "shift+tab")
	if m.section != secConnections {
		t.Fatalf("shift+tab = %v, want connections", m.section)
	}
	press(t, m, "esc")
	if m.section != secDashboard {
		t.Fatalf("esc = %v, want dashboard", m.section)
	}

	press(t, m, "2")
	for _, width := range []int{46, 100} {
		m.Update(tea.WindowSizeMsg{Width: width, Height: 20})
		view := m.View()
		for _, line := range strings.Split(view, "\n") {
			if got := lipgloss.Width(line); got > width {
				t.Fatalf("width %d: line %q rendered at %d columns", width, line, got)
			}
		}
		if !strings.Contains(view, "Connections") {
			t.Fatalf("width %d: view does not show the active section\n%s", width, view)
		}
	}
}

func TestConnectionsSearchDetailAndTruthfulActions(t *testing.T) {
	svc := &stubService{conns: sampleConnections()}
	m := testMenu(t, svc)
	press(t, m, "2")

	press(t, m, "/")
	if m.overlay.kind != ovInput {
		t.Fatalf("search overlay = %v, want input", m.overlay.kind)
	}
	typeText(t, m, "amst")
	press(t, m, "enter")

	if svc.lastFilter.Search != "amst" {
		t.Fatalf("filter sent = %q, want amst", svc.lastFilter.Search)
	}
	if len(m.conns) != 1 || m.conns[0].Remark != "Example Amsterdam" {
		t.Fatalf("filtered connections = %+v", m.conns)
	}

	press(t, m, "enter")
	if m.detail == nil {
		t.Fatal("detail did not open")
	}
	view := m.View()
	for _, want := range []string{"Example Amsterdam", "Server", "Credentials"} {
		if !strings.Contains(view, want) {
			t.Fatalf("detail view missing %q\n%s", want, view)
		}
	}
	press(t, m, "esc")
	if m.detail != nil {
		t.Fatal("detail did not close on esc")
	}

	press(t, m, "a")
	if svc.lastActiveID != "examplevpn:Example Amsterdam" {
		t.Fatalf("active id = %q", svc.lastActiveID)
	}
	if !strings.Contains(m.notice, "restart") {
		t.Fatalf("selecting a connection must say a restart is required, notice = %q", m.notice)
	}

	press(t, m, "c")
	if m.overlay.kind != ovChoice {
		t.Fatalf("connect confirmation = %v, want choice", m.overlay.kind)
	}
	if !strings.Contains(m.overlay.info, "restarts") {
		t.Fatalf("connect confirmation must explain the restart: %q", m.overlay.info)
	}
	press(t, m, "down", "enter")
	if svc.lastConnect != "examplevpn:Example Amsterdam" {
		t.Fatalf("connect id = %q", svc.lastConnect)
	}
	if !strings.Contains(m.notice, "Tunnel restarted") {
		t.Fatalf("notice = %q", m.notice)
	}
}

func TestCredentialFlowNeverRendersPassword(t *testing.T) {
	const secret = "s3cret-pass"
	svc := &stubService{conns: sampleConnections()}
	m := testMenu(t, svc)
	press(t, m, "2")

	press(t, m, "u")
	typeText(t, m, "alice")
	press(t, m, "enter")
	if !m.overlay.masked {
		t.Fatal("password prompt is not masked")
	}
	typeText(t, m, secret)
	if strings.Contains(m.View(), secret) {
		t.Fatal("password leaked into the password prompt view")
	}
	press(t, m, "enter")
	if m.overlay.kind != ovChoice {
		t.Fatalf("save choice = %v, want choice", m.overlay.kind)
	}
	if strings.Contains(m.View(), secret) {
		t.Fatal("password leaked into the save-choice view")
	}
	press(t, m, "enter")

	if svc.lastCredID != "examplevpn:Example Amsterdam" {
		t.Fatalf("credential id = %q", svc.lastCredID)
	}
	if svc.lastCred.Username != "alice" || svc.lastCred.Password != secret {
		t.Fatalf("credentials = %+v", svc.lastCred)
	}
	if !svc.lastPersist {
		t.Fatal("Save securely did not request persistent storage")
	}
	if !strings.Contains(m.notice, "encrypted at rest") {
		t.Fatalf("notice = %q", m.notice)
	}
	if strings.Contains(m.View(), secret) {
		t.Fatal("password leaked into the main view")
	}

	// The session-only path must pass persist=false and describe itself honestly.
	m.notice = ""
	press(t, m, "u")
	typeText(t, m, "alice2")
	press(t, m, "enter")
	typeText(t, m, "another-pass")
	press(t, m, "enter", "down", "enter")
	if svc.lastPersist {
		t.Fatal("Session only still requested persistent storage")
	}
	if !strings.Contains(m.notice, "this run only") {
		t.Fatalf("session-only notice = %q", m.notice)
	}
}

func TestOpenVPNWizardEndToEnd(t *testing.T) {
	svc := &stubService{
		preview:   app.OVPNPreview{Name: "Lab", Host: "vpn.example.net", Port: 1194, Network: "udp", RequiresAuth: true},
		importRes: app.ImportResult{Group: "default", Created: []app.Connection{{ID: "default:Lab VPN", Remark: "Lab VPN"}}},
	}
	m := testMenu(t, svc)

	runCmd(t, m, m.startOpenVPNWizard(app.OVPNSource{Text: "client\nremote vpn.example.net 1194\n", Name: "Lab"}, "default"))
	if m.wiz == nil || m.overlay.kind != ovWizard {
		t.Fatal("wizard did not open")
	}
	if m.wiz.step != wzSummary {
		t.Fatalf("wizard step = %v, want summary", m.wiz.step)
	}
	if svc.lastPreview.Path != "" {
		t.Fatalf("preview sent a server-side path instead of the staged text: %+v", svc.lastPreview)
	}
	if !strings.Contains(svc.lastPreview.Text, "remote vpn.example.net 1194") || svc.lastPreview.Name != "Lab" {
		t.Fatalf("preview did not carry the staged profile: %+v", svc.lastPreview)
	}
	stageDir := m.wiz.stageDir
	if _, err := os.Stat(stageDir); err != nil {
		t.Fatalf("stage missing: %v", err)
	}
	if !strings.Contains(m.View(), "Authentication") || !strings.Contains(m.View(), "username/password") {
		t.Fatalf("summary does not report required auth\n%s", m.View())
	}

	press(t, m, "enter")
	if m.overlay.kind != ovInput {
		t.Fatalf("auth prompt = %v, want input", m.overlay.kind)
	}
	typeText(t, m, "bob")
	press(t, m, "enter")
	if !m.overlay.masked {
		t.Fatal("OpenVPN password prompt is not masked")
	}
	typeText(t, m, "hunter2")
	if strings.Contains(m.View(), "hunter2") {
		t.Fatal("OpenVPN password rendered on screen")
	}
	press(t, m, "enter")
	if m.wiz.step != wzName || m.overlay.kind != ovInput {
		t.Fatalf("name step = %v overlay = %v", m.wiz.step, m.overlay.kind)
	}
	press(t, m, "ctrl+u")
	typeText(t, m, "Lab VPN")
	press(t, m, "enter")
	if m.wiz.step != wzSave {
		t.Fatalf("step = %v, want save choice", m.wiz.step)
	}
	if !strings.Contains(m.View(), "encrypted at rest") || !strings.Contains(m.View(), "Session only") {
		t.Fatalf("save view does not explain both options\n%s", m.View())
	}
	press(t, m, "enter")
	if m.wiz.step != wzConfirm {
		t.Fatalf("step = %v, want confirm", m.wiz.step)
	}
	press(t, m, "enter")

	if svc.lastImport.Name != "Lab VPN" || svc.lastImport.Username != "bob" || svc.lastImport.Password != "hunter2" {
		t.Fatalf("import request = %+v", svc.lastImport)
	}
	if svc.lastImport.Path != "" || !strings.Contains(svc.lastImport.Text, "remote vpn.example.net 1194") {
		t.Fatalf("import sent a server-side path instead of the staged text: %+v", svc.lastImport)
	}
	if !svc.lastImport.SaveCredential {
		t.Fatal("import did not request saved credentials")
	}
	if svc.lastImport.Group != "default" {
		t.Fatalf("group = %q", svc.lastImport.Group)
	}
	if m.wiz == nil || m.wiz.step != wzDone {
		t.Fatalf("wizard step = %v, want done", m.wiz)
	}
	if m.busy != "" {
		t.Fatalf("busy still set: %q", m.busy)
	}
	if strings.Contains(m.View(), "hunter2") {
		t.Fatal("password leaked into the done view")
	}
	if _, err := os.Stat(stageDir); !os.IsNotExist(err) {
		t.Fatalf("staging directory was not removed: %v", err)
	}
	press(t, m, "enter")
	if m.wiz != nil {
		t.Fatal("wizard did not close")
	}
}

func TestOpenVPNSuccessfulImportWithSessionCredentials(t *testing.T) {
	svc := &stubService{
		preview:   app.OVPNPreview{Name: "Cert Only", Host: "vpn.example.net", Port: 443, Network: "tcp", CertFiles: []string{"ca.crt"}},
		importRes: app.ImportResult{Group: "default", Created: []app.Connection{{ID: "default:Cert Only"}}},
	}
	m := testMenu(t, svc)
	runCmd(t, m, m.startOpenVPNWizard(app.OVPNSource{Text: "client\nremote vpn.example.net 443 tcp\n", Name: "Cert Only"}, "default"))
	press(t, m, "enter")
	if m.wiz.step != wzName {
		t.Fatalf("cert-only profile should skip credentials, step = %v", m.wiz.step)
	}
	press(t, m, "enter")
	if m.wiz.step != wzConfirm {
		t.Fatalf("step = %v, want confirm", m.wiz.step)
	}
	press(t, m, "enter")
	if svc.lastImport.Username != "" || svc.lastImport.Password != "" {
		t.Fatalf("cert-only import sent credentials: %+v", svc.lastImport)
	}
}

func TestStageOpenVPNCollectsMissingRefsAndStripsAuthFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("CA"), 0600); err != nil {
		t.Fatal(err)
	}
	profile := strings.Join([]string{
		"client",
		"remote vpn.example.net 1194 udp",
		"ca ca.crt",
		"cert client.crt",
		"auth-user-pass creds.txt",
		"<auth-user-pass>",
		"inlineuser",
		"inlinepass",
		"</auth-user-pass>",
		"",
	}, "\n")
	path := filepath.Join(dir, "lab.ovpn")
	if err := os.WriteFile(path, []byte(profile), 0600); err != nil {
		t.Fatal(err)
	}

	info := stageOpenVPN(app.OVPNSource{Path: path})
	if info.err != nil {
		t.Fatalf("stage error: %v", info.err)
	}
	defer os.RemoveAll(info.dir)

	if len(info.missing) != 1 || info.missing[0] != "client.crt" {
		t.Fatalf("missing refs = %v", info.missing)
	}
	if !info.authGap {
		t.Fatal("missing auth-user-pass file was not reported")
	}
	staged, err := os.ReadFile(info.path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(staged)
	if strings.Contains(text, "creds.txt") {
		t.Fatalf("staged profile still references the missing auth file:\n%s", text)
	}
	if !strings.Contains(text, "auth-user-pass\n") {
		t.Fatalf("staged profile lost the auth directive:\n%s", text)
	}
	if !strings.Contains(text, "<auth-user-pass>") {
		t.Fatalf("staged profile lost the inline auth block:\n%s", text)
	}
	copied, err := os.ReadFile(filepath.Join(info.dir, "ca.crt"))
	if err != nil {
		t.Fatalf("ca.crt not staged: %v", err)
	}
	if string(copied) != "CA" {
		t.Fatalf("staged ca.crt = %q", copied)
	}
	if runtime.GOOS != "windows" {
		if info2, err := os.Stat(filepath.Join(info.dir, "ca.crt")); err == nil && info2.Mode().Perm()&0077 != 0 {
			t.Fatalf("staged file is readable by others: %v", info2.Mode())
		}
	}
}

func TestSafeRefPathConfinement(t *testing.T) {
	base := t.TempDir()
	for _, ref := range []string{"../escape.crt", "/etc/passwd", `\windows\system32`, "ok/ca.crt"} {
		_, ok := safeRefPath(base, ref)
		want := ref == "ok/ca.crt"
		if ok != want {
			t.Fatalf("safeRefPath(%q) = %v, want %v", ref, ok, want)
		}
	}
}

func TestFileBrowserFilteringAndNavigation(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alpha.ovpn", "beta.txt", ".hidden.ovpn"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	m := testMenu(t, &stubService{})
	b := newBrowser(dir, ".ovpn")
	m.overlay = overlay{kind: ovFiles, title: "Pick", browser: b, onFile: func(*Menu, string) tea.Cmd { return nil }}

	names := browserNames(b)
	if len(names) != 2 || names[0] != "sub" || names[1] != "alpha.ovpn" {
		t.Fatalf("entries = %v, want [sub alpha.ovpn]", names)
	}
	if view := m.View(); !strings.Contains(view, "alpha.ovpn/") && !strings.Contains(view, "alpha.ovpn") {
		t.Fatalf("browser view missing file\n%s", view)
	}

	press(t, m, ".")
	names = browserNames(b)
	found := false
	for _, name := range names {
		if name == ".hidden.ovpn" {
			found = true
		}
	}
	if !found {
		t.Fatalf("hidden toggle did not reveal .hidden.ovpn: %v", names)
	}

	press(t, m, ".")
	press(t, m, "right")
	if b.dir != filepath.Join(dir, "sub") {
		t.Fatalf("right did not enter sub dir: %q", b.dir)
	}
	press(t, m, "backspace")
	if b.dir != dir {
		t.Fatalf("backspace did not return to parent: %q", b.dir)
	}
}

func browserNames(b *browserState) []string {
	out := make([]string, 0, len(b.entries))
	for _, e := range b.entries {
		out = append(out, e.name)
	}
	return out
}

func TestFriendlyErrorRedactsURIs(t *testing.T) {
	err := errors.New(`dialing vless://uuid-secret@example.net:443 failed`)
	msg := friendlyError(err)
	if strings.Contains(msg, "uuid-secret") {
		t.Fatalf("URI identifier leaked: %q", msg)
	}
	if !strings.Contains(msg, "vless://<redacted>") {
		t.Fatalf("URI was not redacted: %q", msg)
	}
}

func TestDashboardProbeExitIP(t *testing.T) {
	svc := &stubService{
		status: app.Status{State: "CONNECTED", Running: true, PID: 4242, ActiveID: "default:Reality", ActiveLink: "Reality", GatewayMode: true},
		exitIP: "203.0.113.9",
	}
	m := testMenu(t, svc)
	runCmd(t, m, m.Init())
	if m.status.State != "CONNECTED" {
		t.Fatalf("status = %q", m.status.State)
	}

	_, cmd := m.Update(keyMsg("p"))
	if m.busy == "" {
		t.Fatal("probe did not mark the UI busy")
	}
	runCmd(t, m, cmd)
	if m.exitIP != "203.0.113.9" {
		t.Fatalf("exit ip = %q", m.exitIP)
	}
	if m.busy != "" {
		t.Fatalf("busy not cleared after probe: %q", m.busy)
	}
	if view := m.View(); !strings.Contains(view, "203.0.113.9") {
		t.Fatalf("dashboard does not show the exit IP\n%s", view)
	}
}

func TestDashboardProbeRequiresConnectedState(t *testing.T) {
	svc := &stubService{status: app.Status{State: "IDLE"}}
	m := testMenu(t, svc)
	press(t, m, "p")
	if m.busy != "" {
		t.Fatal("probe ran while the gateway was not connected")
	}
	if !m.noticeErr || !strings.Contains(m.notice, "CONNECTED") {
		t.Fatalf("notice = %q (err %v)", m.notice, m.noticeErr)
	}
}

func TestSettingsEditReportsRestart(t *testing.T) {
	svc := &stubService{
		settings:    app.Settings{GatewayMode: false, DNSMode: "strict", DNSUpstream: []string{"1.1.1.1"}, Listen: "127.0.0.1"},
		patchChange: app.SettingsChange{Settings: app.Settings{GatewayMode: true}, RestartRequired: true},
	}
	m := testMenu(t, svc)
	press(t, m, "6")
	if m.section != secSettings {
		t.Fatalf("section = %v", m.section)
	}
	if len(m.settingRows()) == 0 {
		t.Fatal("settings did not load")
	}
	if m.settings.Listen != "127.0.0.1" {
		t.Fatalf("settings = %+v", m.settings)
	}

	press(t, m, "enter")
	if m.overlay.kind != ovChoice {
		t.Fatalf("gateway toggle overlay = %v", m.overlay.kind)
	}
	if !strings.Contains(m.overlay.info, "Transparent TUN") {
		t.Fatalf("confirmation does not explain the change: %q", m.overlay.info)
	}
	press(t, m, "down", "enter")
	if svc.lastPatch.GatewayMode == nil || !*svc.lastPatch.GatewayMode {
		t.Fatalf("patch = %+v", svc.lastPatch)
	}
	if !strings.Contains(m.notice, "Restart the gateway") {
		t.Fatalf("restart-required notice = %q", m.notice)
	}
}

func TestSubscriptionRefreshThroughService(t *testing.T) {
	svc := &stubService{
		subs: []app.Subscription{{
			Group: "examplevpn", URL: "https://panel.example/sub?token=placeholder-token",
			RedactedURL: "https://panel.example/sub?token=<redacted>", LinkCount: 1,
		}},
		refreshLinks: 3,
	}
	m := testMenu(t, svc)
	press(t, m, "4")
	if len(m.subs) != 1 {
		t.Fatalf("subscriptions = %v", m.subs)
	}
	if strings.Contains(m.View(), "placeholder-token") {
		t.Fatalf("subscription token rendered\n%s", m.View())
	}

	press(t, m, "r")
	if len(svc.lastRefresh) != 1 || svc.lastRefresh[0] != [2]string{"examplevpn", "https://panel.example/sub?token=placeholder-token"} {
		t.Fatalf("refresh calls = %v", svc.lastRefresh)
	}
	if m.busy != "" {
		t.Fatalf("busy not cleared: %q", m.busy)
	}
	if !strings.Contains(m.notice, "3 links") {
		t.Fatalf("notice = %q", m.notice)
	}
}

func TestSubscriptionPreviewBeforeStore(t *testing.T) {
	svc := &stubService{
		previewSub: app.SubscriptionPreview{
			Group: "examplevpn", RedactedURL: "https://panel.example/sub?token=<redacted>",
			Total: 3, Duplicates: 1,
			Links: []app.SubscriptionLink{{
				Remark: "Amsterdam", Protocol: "vless", Address: "nl.example.net", Port: 443, TLS: true, Reality: true,
			}},
		},
		refreshLinks: 2,
	}
	m := testMenu(t, svc)
	press(t, m, "4", "a")
	if m.overlay.kind != ovInput {
		t.Fatalf("add prompt = %v, want input", m.overlay.kind)
	}
	typeText(t, m, "https://panel.example/sub?token=placeholder-token")
	press(t, m, "enter")

	if svc.lastPreviewURL != "https://panel.example/sub?token=placeholder-token" {
		t.Fatalf("preview URL = %q", svc.lastPreviewURL)
	}
	if m.overlay.kind != ovChoice {
		t.Fatalf("preview overlay = %v, want choice", m.overlay.kind)
	}
	if strings.Contains(m.overlay.info, "placeholder-token") {
		t.Fatalf("preview leaks the subscription token\n%s", m.overlay.info)
	}
	for _, want := range []string{"nl.example.net", "TLS", "REALITY", "1 already installed"} {
		if !strings.Contains(m.overlay.info, want) {
			t.Fatalf("preview missing %q\n%s", want, m.overlay.info)
		}
	}
	if svc.lastAddURL != "" {
		t.Fatalf("subscription stored before confirmation: %+v", svc)
	}

	press(t, m, "enter") // "Add and fetch links"
	// No override is sent: the backend derives the proposed group name and
	// resolves collisions at store time, so the preview never becomes a
	// second naming authority.
	if svc.lastAddGroup != "" || svc.lastAddURL != "https://panel.example/sub?token=placeholder-token" {
		t.Fatalf("add call = %q %q", svc.lastAddGroup, svc.lastAddURL)
	}
	if len(svc.lastRefresh) != 1 {
		t.Fatalf("refresh calls = %v", svc.lastRefresh)
	}
	if !strings.Contains(m.notice, "2 link") {
		t.Fatalf("notice = %q", m.notice)
	}
}

func TestSubscriptionDumpPreviewImport(t *testing.T) {
	svc := &stubService{previewSub: app.SubscriptionPreview{Group: "imported", RedactedURL: "<pasted subscription dump>", Total: 1}}
	m := testMenu(t, svc)
	press(t, m, "4", "i")
	if m.overlay.kind != ovText {
		t.Fatalf("dump overlay = %v, want text", m.overlay.kind)
	}
	typeText(t, m, "vless://uuid-secret@example.net:443?security=reality#Lab")
	press(t, m, "ctrl+s")
	if svc.lastPreviewText == "" {
		t.Fatal("dump was not previewed")
	}
	if m.overlay.kind != ovChoice {
		t.Fatalf("preview overlay = %v, want choice", m.overlay.kind)
	}
	if strings.Contains(m.overlay.info, "uuid-secret") {
		t.Fatalf("dump preview leaks the URI\n%s", m.overlay.info)
	}
	press(t, m, "enter")
	if !strings.Contains(m.notice, "imported") {
		t.Fatalf("notice = %q", m.notice)
	}
}

func TestURIImportFlowUsesSharedService(t *testing.T) {
	svc := &stubService{}
	m := testMenu(t, svc)
	press(t, m, "8")
	if m.section != secImport {
		t.Fatalf("section = %v", m.section)
	}
	press(t, m, "enter")
	if m.overlay.kind != ovText {
		t.Fatalf("paste overlay = %v", m.overlay.kind)
	}
	typeText(t, m, "vless://uuid-secret@example.net:443?security=reality#Lab")
	press(t, m, "ctrl+s")
	if m.overlay.kind != ovInput {
		t.Fatalf("group prompt = %v", m.overlay.kind)
	}
	if strings.Contains(m.View(), "uuid-secret") {
		t.Fatalf("raw URI rendered while asking for the group\n%s", m.View())
	}
	press(t, m, "enter")
	if m.overlay.kind != ovChoice {
		t.Fatalf("confirm overlay = %v", m.overlay.kind)
	}
	if strings.Contains(m.overlay.info, "uuid-secret") {
		t.Fatalf("confirmation leaks the UUID: %q", m.overlay.info)
	}
	press(t, m, "down", "enter")
	if !strings.Contains(m.notice, "imported 1 connection(s)") {
		t.Fatalf("notice = %q", m.notice)
	}
}

func TestFatalViewWithoutService(t *testing.T) {
	m := newWithService(nil, errors.New("config is unreadable"))
	m.width, m.height = 80, 20
	view := m.View()
	for _, want := range []string{"could not be opened", "config is unreadable", "retry"} {
		if !strings.Contains(view, want) {
			t.Fatalf("fatal view missing %q\n%s", want, view)
		}
	}
}

// TestEscapeCancelsBusyActionOnFirstPress covers the double-ESC bug: a single
// Escape while an action runs must cancel it and stay on the current section
// instead of navigating to the dashboard first.
func TestEscapeCancelsBusyActionOnFirstPress(t *testing.T) {
	m := testMenu(t, &stubService{})
	m.section = secGateway
	m.busy = "Connect"
	m.busySince = time.Now()
	reqCtx, cancel := context.WithCancel(context.Background())
	m.cancelOp = cancel

	press(t, m, "esc")

	if m.section != secGateway {
		t.Fatalf("section = %v, want the gateway section after cancelling", m.section)
	}
	if m.busy != "" {
		t.Fatalf("busy still set: %q", m.busy)
	}
	if m.cancelOp != nil {
		t.Fatal("cancel function was not released")
	}
	select {
	case <-reqCtx.Done():
	default:
		t.Fatal("the action request context was not cancelled")
	}
}

// TestCancelledActionReportsCancellation proves the result of a cancelled call
// arrives as a cancellation notice, not as an error, and clears the busy flag.
func TestCancelledActionReportsCancellation(t *testing.T) {
	m := testMenu(t, &stubService{})
	m.section = secGateway
	m.busy = "Connect"
	reqCtx, cancel := context.WithCancel(context.Background())
	m.cancelOp = cancel
	_ = reqCtx

	press(t, m, "esc")
	_, _ = m.Update(doneMsg{label: "Connect", err: context.Canceled})

	if m.busy != "" {
		t.Fatalf("busy not cleared: %q", m.busy)
	}
	if m.noticeErr {
		t.Fatalf("cancellation was reported as an error: %q", m.notice)
	}
	if !strings.Contains(strings.ToLower(m.notice), "cancelled") {
		t.Fatalf("notice = %q, want a cancellation notice", m.notice)
	}
}

// TestEscapePropagatesCancellationToTheService verifies the context handed to
// the contract call is what Escape cancels, so the daemon sees the abort.
func TestEscapePropagatesCancellationToTheService(t *testing.T) {
	m := testMenu(t, &stubService{})
	m.section = secGateway

	canceled := make(chan struct{})
	cmd := m.runAction("Connect", func(ctx context.Context, _ app.Contract) (app.ActionResult, error) {
		<-ctx.Done()
		close(canceled)
		return app.ActionResult{}, ctx.Err()
	})
	if cmd == nil {
		t.Fatal("runAction returned no command")
	}
	batch, ok := cmd().(tea.BatchMsg)
	if !ok || len(batch) == 0 {
		t.Fatal("runAction did not return a batch with the action command")
	}
	done := make(chan tea.Msg, 1)
	go func() { done <- batch[0]() }()

	press(t, m, "esc")

	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("the contract call did not observe cancellation")
	}
	select {
	case msg := <-done:
		_, _ = m.Update(msg)
	case <-time.After(2 * time.Second):
		t.Fatal("the cancelled action never returned")
	}
	if m.busy != "" {
		t.Fatalf("busy not cleared after cancellation: %q", m.busy)
	}
}

// Cancelling a connect must reach the daemon as a disconnect, so the gateway
// ends DISCONNECTED instead of reporting a failed start, and cancelling an
// action that never touched the tunnel must not disconnect a working one.
func TestCancellingConnectAlsoDisconnects(t *testing.T) {
	svc := &stubService{}
	m := testMenu(t, svc)
	m.section = secGateway
	m.busy = "Connect"
	_, cancel := context.WithCancel(context.Background())
	m.cancelOp = cancel

	cmd := m.cancelBusy()
	if cmd == nil {
		t.Fatal("cancelling a connect returned no disconnect command")
	}
	msg := cmd()
	if _, ok := msg.(tunnelCanceledMsg); !ok {
		t.Fatalf("cancel command returned %T, want tunnelCanceledMsg", msg)
	}
	if svc.disconnects != 1 {
		t.Fatalf("disconnect calls = %d, want 1", svc.disconnects)
	}
	_, _ = m.Update(msg)
	if m.noticeErr {
		t.Fatalf("disconnect after cancel reported an error: %q", m.notice)
	}
}

func TestCancellingSelectDoesNotDisconnect(t *testing.T) {
	svc := &stubService{}
	m := testMenu(t, svc)
	m.section = secConnections
	m.busy = "Select"
	_, cancel := context.WithCancel(context.Background())
	m.cancelOp = cancel

	if cmd := m.cancelBusy(); cmd != nil {
		t.Fatal("cancelling a select produced a command")
	}
	if svc.disconnects != 0 {
		t.Fatalf("disconnect calls = %d, want 0", svc.disconnects)
	}
}
