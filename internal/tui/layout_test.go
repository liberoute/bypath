package tui

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/paths"
)

var updateLayout = flag.Bool("update-layout", false, "rewrite the rendered layout golden files")

// layoutTestStamp returns a whole-hour offset from now, so the relative age
// label is deterministic ("12h ago") and certified rows stay inside the
// freshness window the verifier enforces.
func layoutTestStamp(hours int) string {
	return time.Now().UTC().Add(-time.Duration(hours) * time.Hour).Truncate(time.Minute).Format(time.RFC3339)
}

func layoutTestResults() []app.TestResult {
	proven := func(id, remark, protocol string, p50, p90 int64) app.TestResult {
		return app.TestResult{
			ConnectionID: id, Group: "imported", Remark: remark, Protocol: protocol,
			Kind: "latency", Status: "ok", Category: app.CategoryVerified,
			P50MS: p50, P90MS: p90, LatencyMS: p50,
			TestedAt: layoutTestStamp(12),
			Path: &app.PathProof{
				ProofVersion: "P5", Kind: "isolated", Level: "L1+L2", ConfigAudit: "pass",
				IsolationVerified: true, EngineOwned: true, TunneledHTTPS: true,
				ConfigSHA256: strings.Repeat("a", 64), ProfileSHA256: strings.Repeat("b", 64),
				ExitBefore: "203.0.113.9", ExitAfter: "203.0.113.9",
				UplinkIP: "198.51.100.4", ServingExitIP: "198.51.100.4",
				Echoes:         []app.EchoResult{{Service: "ipify", IP: "203.0.113.9"}, {Service: "ipwho", IP: "203.0.113.9"}},
				PolicyRevision: "r-8fa2c1", NegativeControl: "DIRECT exit differs",
			},
		}
	}
	return []app.TestResult{
		proven("imported:Maple-IPv4", "Maple-IPv4", "vless", 41, 88),
		proven("imported:Tokyo — 东京节点-非常长-的-连接名称", "东京节点-非常长-的-连接名称", "trojan", 180, 260),
		{
			ConnectionID: "imported:Example VPN Europe 3 (TCP)", Group: "imported",
			Remark: "Example VPN Europe 3 (TCP) — a deliberately long remark", Protocol: "openvpn",
			Kind: "latency", Status: "inconclusive", Reason: "EXIT_EQUALS_SERVING",
			TestedAt: layoutTestStamp(11),
		},
		{
			ConnectionID: "imported:eu-tcp", Group: "imported",
			Remark: "eu-tcp", Protocol: "openvpn",
			Kind: "latency", Status: "failed", Reason: "CONTROL_FAILED",
			TestedAt: layoutTestStamp(10),
		},
	}
}

func layoutTestSubscriptions() []app.Subscription {
	return []app.Subscription{
		{
			Group: "examplevpn", URL: "https://panel.example/sub?token=placeholder-token",
			RedactedURL: "https://panel.example/sub?token=<redacted>",
			LinkCount:   3, LastRefresh: "2026-11-09T14:30:00Z",
		},
		{
			Group: "imported-dump-2026-11", RedactedURL: "<pasted subscription dump>",
			LinkCount: 12, LastError: "the last refresh returned an unreadable body; existing links were kept",
		},
	}
}

func layoutTestRouting() *app.RoutingOverview {
	return &app.RoutingOverview{
		Revision: "r-8fa2c1", Mode: "rules", Engine: "sing-box",
		DefaultOutbound: "proxy", DNSMode: "strict", GatewayConnected: true,
		CanEdit: true,
		Rules: []app.RoutingRuleView{
			{Position: 1, Scope: "built-in", Source: "built-in", Kind: "safety", Match: "local DNS and loopback", Outbound: "direct", Effect: "direct"},
			{Position: 2, Scope: "policy", Source: "country-direct policy", Kind: "geoip", Match: "geoip:de", Outbound: "direct", Effect: "direct"},
			{Position: 3, Scope: "policy", Source: "country-direct policy", Kind: "geosite", Match: "geosite:category-de", Outbound: "direct", Effect: "direct"},
			{Position: 4, Scope: "exception", Source: "exception (web panel)", Kind: "domain_suffix", Match: "domain_suffix:openai.com", Outbound: "proxy", Effect: "proxy"},
			{Position: 5, Scope: "exception", Source: "exception (web panel)", Kind: "domain", Match: "domain:chat.openai.com", Outbound: "proxy", Effect: "proxy"},
			{Position: 6, Scope: "built-in", Source: "built-in blocklist", Kind: "domain", Match: "domain:ads.example", Outbound: "block", Effect: "block"},
			{
				Position: 7, Scope: "exception", Source: "exception (web panel)", Kind: "ip_cidr",
				Match: "ip_cidr:203.0.113.0/24", Outbound: "direct", Effect: "direct",
				Note: "geosite.dat is missing, so this rule cannot run", Skipped: true,
			},
			{Position: 8, Scope: "exception", Source: "exception (web panel)", Kind: "domain_suffix", Match: "domain_suffix:東京.example", Outbound: "proxy", Effect: "proxy"},
		},
		Warnings: []string{
			"geosite.dat is not installed where the engine looks for it: domain-list rules are inactive and the traffic they would match falls through.",
		},
		Assets: app.RoutingAssets{
			GeoIPPath: "/var/lib/bypath/geoip.dat", GeoIPPresent: true,
			GeoSitePath: "/var/lib/bypath/geosite.dat", GeoSitePresent: false,
		},
		LocalDNS: []app.LocalDNSView{
			{Server: "10.20.30.53:53", Domains: []string{"ha.home", "vpn.example.test"}},
			{Server: "127.0.0.1:5353", Domains: []string{"lan"}},
		},
	}
}

func layoutMenu(s section, width, height int) *Menu {
	return &Menu{
		section: s,
		width:   width,
		height:  height,
		status: app.Status{
			Version:      "3.0.0",
			Variant:      "FULL",
			Commit:       "477458f",
			Running:      true,
			PID:          4242,
			State:        "CONNECTED",
			ActiveID:     "imported:Maple-IPv4",
			ActiveLink:   "Maple-IPv4",
			ActiveGroup:  "imported",
			SelectedID:   "imported:Maple-IPv4",
			SelectedLink: "Maple-IPv4",
			Protocol:     "vless",
			Engine:       "sing-box",
			GatewayMode:  true,
			DNSMode:      "strict",
			UptimeSec:    3600,
			APIPort:      8080,
			SOCKSPort:    2801,
			DNSPort:      53,
			ProfileCount: 12,
			SubCount:     1,
		},
		conns: []app.Connection{
			{
				ID:             "imported:Maple-IPv4",
				Group:          "imported",
				Remark:         "Maple-IPv4",
				Protocol:       "vless",
				Address:        "cdn.example.net",
				Port:           2083,
				Engine:         "sing-box",
				TLS:            true,
				Active:         true,
				Network:        "ws",
				Health:         "ok",
				CDN:            true,
				EncryptedVLESS: false,
			},
			{
				ID:       "imported:Example VPN Europe 3 (TCP) — a deliberately long remark",
				Group:    "imported",
				Remark:   "东京节点-非常长-的-连接名称-用于-回归测试",
				Protocol: "openvpn",
				Address:  "europe3.vpn.example.net",
				Port:     443,
				Engine:   "sing-box",
				Network:  "tcp",
				Health:   "failed",
			},
		},
		logs: []app.LogEntry{
			{
				Time:  "2026-11-09T14:30:00Z",
				Level: "error",
				Message: "engine start failed for [openvpn] eu-tcp\n" +
					"local configuration error for link 'eu-tcp': OpenVPN profile is unreadable\n" +
					"falling back to the next link in the group",
			},
		},
		tests: testState{
			resultsLoaded: true,
			results:       layoutTestResults(),
			compareKind:   "latency",
		},
		subs: layoutTestSubscriptions(),
		routing: routingState{
			overview: layoutTestRouting(),
		},
	}
}

// TestLayoutFitsTerminalWidth renders every section at widths from a narrow
// phone-width SSH session to a wide window. No rendered line may exceed the
// terminal, because a wrapped line pushes the footer off-screen.
func TestLayoutFitsTerminalWidth(t *testing.T) {
	for _, width := range []int{40, 60, 80, 100, 120, 160} {
		for s := section(0); s < secCount; s++ {
			m := layoutMenu(s, width, 30)
			for i, line := range strings.Split(m.View(), "\n") {
				if got := lipgloss.Width(line); got > width {
					t.Fatalf("%s at width %d: line %d is %d columns: %q", sectionTitles[s], width, i, got, line)
				}
			}
		}
	}
}

// TestHeaderKeepsEditionAndStateWhenNarrow proves the identity segments are
// never traded away for the link name.
func TestHeaderKeepsEditionAndStateWhenNarrow(t *testing.T) {
	for _, width := range []int{40, 60, 100} {
		m := layoutMenu(secDashboard, width, 30)
		line := m.viewHeader()
		for _, want := range []string{"BYPATH", "[FULL]", "CONNECTED"} {
			if !strings.Contains(line, want) {
				t.Fatalf("width %d: header %q lost %q", width, line, want)
			}
		}
		if got := lipgloss.Width(line); got > width {
			t.Fatalf("width %d: header is %d columns", width, got)
		}
	}
}

// TestHeaderLabelsRunningVersusSelected keeps a saved selection from looking
// applied. 'a' only saves; 'c' starts the gateway on it.
func TestHeaderLabelsRunningVersusSelected(t *testing.T) {
	m := layoutMenu(secDashboard, 100, 30)
	if line := m.viewHeader(); !strings.Contains(line, "running") {
		t.Fatalf("header %q does not say the link is running", line)
	}

	m.status.Running = false
	if line := m.viewHeader(); !strings.Contains(line, "selected") || strings.Contains(line, "running") {
		t.Fatalf("header %q does not say the link is only selected", line)
	}
}

// TestFailedWithHealthyFallbackShowsDegraded proves a working fallback tunnel
// is never reported as FAILED while verified traffic is flowing through it.
func TestFailedWithHealthyFallbackShowsDegraded(t *testing.T) {
	m := layoutMenu(secDashboard, 100, 30)
	m.status.State = "FAILED"
	m.status.ActiveLink = "us-tcp"
	m.status.FallbackFrom = "imported:eu-tcp"
	m.status.LastError = "link 'imported:eu-tcp' failed at 2026-11-09T14:30:00Z: local configuration error"

	state, _ := m.displayState()
	if state != "FAILED" {
		t.Fatalf("an unverified fallback reported %q, want FAILED", state)
	}

	m.status.LastHealth = time.Now().UTC().Format(time.RFC3339)
	state, _ = m.displayState()
	if state != "DEGRADED" {
		t.Fatalf("a verified fallback reported %q, want DEGRADED", state)
	}
	view := m.dashboardView(30)
	if strings.Contains(view, "FAILED") {
		t.Fatalf("dashboard still says FAILED while the fallback carries traffic:\n%s", view)
	}
	if !strings.Contains(view, "Fallback from") || !strings.Contains(view, "imported:eu-tcp") {
		t.Fatalf("dashboard does not name the failed link:\n%s", view)
	}
}

// TestDashboardWrapsErrorCause proves the reason survives narrow widths: the
// operator must be able to read "local configuration error" without widening
// the terminal or opening the journal.
func TestDashboardWrapsErrorCause(t *testing.T) {
	m := layoutMenu(secDashboard, 60, 40)
	m.status.State = "FAILED"
	m.status.LastError = "link 'imported:Example VPN Europe 3 (TCP)' failed at 2026-11-09T14:30:00Z: " +
		"local configuration error for link 'eu-tcp': OpenVPN profile for \"eu-tcp\": " +
		"artifact \"data/profiles/ovpn/sample.ovpn\" not found under /etc/bypath/profiles"

	view := m.dashboardView(30)
	flat := strings.Join(strings.Fields(strings.ReplaceAll(view, "\n", " ")), " ")
	for _, want := range []string{"local configuration error", "not found under /etc/bypath/profiles"} {
		if !strings.Contains(flat, want) {
			t.Fatalf("dashboard lost %q:\n%s", want, view)
		}
	}
	for _, line := range strings.Split(view, "\n") {
		if lipgloss.Width(line) > 60 {
			t.Fatalf("dashboard line overflows: %q", line)
		}
	}
}

// TestConnectionsColumnsAlign is the regression for the misaligned table: a
// long name, a group prefix and a wide (CJK) character must not shift the
// address column away from its header.
func TestConnectionsColumnsAlign(t *testing.T) {
	for _, width := range []int{40, 50, 60, 80, 100, 120} {
		m := layoutMenu(secConnections, width, 30)
		view := m.connectionsView(20)
		lines := strings.Split(view, "\n")

		headerAddr := -1
		headerProto := -1
		for _, line := range lines {
			if strings.Contains(line, "ADDRESS") {
				headerAddr = columnOf(line, "ADDRESS")
				headerProto = columnOf(line, "PROTO")
				break
			}
		}
		if headerAddr < 0 {
			t.Fatalf("width %d: no ADDRESS header in:\n%s", width, view)
		}
		for _, line := range lines {
			switch {
			case strings.Contains(line, "cdn.example.net"):
				if got := columnOf(line, "cdn.example.net"); got != headerAddr {
					t.Fatalf("width %d: address starts at %d, header at %d: %q", width, got, headerAddr, line)
				}
			case strings.Contains(line, "europe3.vpn.example.net"):
				if got := columnOf(line, "europe3.vpn.example.net"); got != headerAddr {
					t.Fatalf("width %d: openvpn address starts at %d, header at %d: %q", width, got, headerAddr, line)
				}
			}
			// The address is clipped on narrow terminals, but the protocol
			// column must still line up with its header.
			for _, value := range []string{"VLESS", "OPENVPN"} {
				if strings.Contains(line, value) {
					if got := columnOf(line, value); got != headerProto {
						t.Fatalf("width %d: %s starts at %d, PROTO header at %d: %q", width, value, got, headerProto, line)
					}
				}
			}
		}
	}
}

// TestRoutingColumnsAlign proves the read-only routing table keeps its effect
// and match columns aligned even when a rule carries a wide (CJK) match.
func TestRoutingColumnsAlign(t *testing.T) {
	for _, width := range []int{80, 120} {
		m := layoutMenu(secRouting, width, 30)
		view := stripANSI(m.routingView(26))
		lines := strings.Split(view, "\n")

		headerEffect, headerMatch := -1, -1
		headerAt := -1
		for i, line := range lines {
			if strings.Contains(line, "WHAT IT MATCHES") {
				headerEffect = columnOf(line, "EFFECT")
				headerMatch = columnOf(line, "WHAT IT MATCHES")
				headerAt = i
				break
			}
		}
		if headerAt < 0 || headerEffect < 0 || headerMatch < 0 {
			t.Fatalf("width %d: no routing header in:\n%s", width, view)
		}
		checks := []struct {
			needle string
			column int
		}{
			{"geoip:de", headerMatch},
			{"domain_suffix:openai.com", headerMatch},
			{"domain_suffix:東京.example", headerMatch},
			{"PROXY", headerEffect},
			{"BLOCK", headerEffect},
		}
		for _, check := range checks {
			found := false
			for _, line := range lines[headerAt+1:] {
				if strings.Contains(line, "local DNS") {
					continue // the highlighted row carries its own padding
				}
				if !strings.Contains(line, check.needle) {
					continue
				}
				found = true
				if got := columnOf(line, check.needle); got != check.column {
					t.Fatalf("width %d: %q starts at %d, header at %d: %q", width, check.needle, got, check.column, line)
				}
				break
			}
			if !found {
				t.Fatalf("width %d: routing table lost %q:\n%s", width, check.needle, view)
			}
		}
	}
}

// TestTestsCompareRanksOnlyProven proves the Compare list puts proven paths
// first in metric order and never ranks an inconclusive one, while still
// showing it with its reason.
func TestTestsCompareRanksOnlyProven(t *testing.T) {
	m := layoutMenu(secTests, 100, 30)
	m.tests.tab = testTabCompare
	entries := m.compareEntries()
	if len(entries) != 4 {
		t.Fatalf("entries = %d, want 4", len(entries))
	}
	if entries[0].res.Remark != "Maple-IPv4" || entries[1].res.Remark != "东京节点-非常长-的-连接名称" {
		t.Fatalf("proven rows not ranked by latency: %q, %q", entries[0].res.Remark, entries[1].res.Remark)
	}
	if entries[2].heading != "Not ranked" {
		t.Fatalf("third entry heading = %q, want Not ranked", entries[2].heading)
	}
	if entries[2].res.Status == "ok" || entries[3].res.Status == "ok" {
		t.Fatal("an unproven result was ranked above the section boundary")
	}

	view := stripANSI(m.testsView(28))
	for _, want := range []string{"Ranked (proven path)", "Not ranked", "the exit matches the serving connection"} {
		if !strings.Contains(view, want) {
			t.Fatalf("compare view lost %q:\n%s", want, view)
		}
	}
}

// TestSourcesRenderRedactedURLs proves the terminal source list never shows a
// subscription token, including the selected row.
func TestSourcesRenderRedactedURLs(t *testing.T) {
	m := layoutMenu(secSubscriptions, 80, 30)
	view := stripANSI(m.subscriptionsView(20))
	if strings.Contains(view, "placeholder-token") {
		t.Fatalf("subscription token rendered:\n%s", view)
	}
	if !strings.Contains(view, "<redacted>") {
		t.Fatalf("redacted URL missing:\n%s", view)
	}
}

// TestLogsIndentMessageContinuations proves a multi-line engine error keeps its
// structure instead of collapsing into one clipped line.
func TestLogsIndentMessageContinuations(t *testing.T) {
	m := layoutMenu(secLogs, 70, 30)
	view := m.logsView(20)
	if !strings.Contains(view, "local configuration error for link 'eu-tcp'") {
		t.Fatalf("log view lost the cause:\n%s", view)
	}
	for _, line := range strings.Split(view, "\n") {
		if strings.Contains(line, "local configuration error") {
			// The timestamp (8) and severity (5) columns are reserved on every
			// line, so continuation text starts at column 16.
			if got := len(line) - len(strings.TrimLeft(line, " ")); got != 16 {
				t.Fatalf("continuation indented %d columns, want 16: %q", got, line)
			}
			return
		}
	}
	t.Fatalf("no continuation line found:\n%s", view)
}

// TestTruncatePlainCountsDisplayColumns proves truncation counts terminal
// columns, not bytes or runes.
func TestTruncatePlainCountsDisplayColumns(t *testing.T) {
	cases := []struct {
		in    string
		width int
		want  string
	}{
		{"abcdef", 3, "ab…"},
		{"东京", 3, "东…"},
		{"东京", 4, "东京"},
		{"a东京b", 4, "a东…"},
	}
	for _, c := range cases {
		got := truncatePlain(c.in, c.width)
		if got != c.want {
			t.Errorf("truncatePlain(%q, %d) = %q, want %q", c.in, c.width, got, c.want)
		}
		if lipgloss.Width(got) > c.width {
			t.Errorf("truncatePlain(%q, %d) = %q is %d columns", c.in, c.width, got, lipgloss.Width(got))
		}
	}
}

// TestOpenVPNCertOnlyConnectionDoesNotClaimMissingCredentials proves the
// footer no longer implies an OpenVPN certificate profile needs a password.
func TestOpenVPNCertOnlyConnectionDoesNotClaimMissingCredentials(t *testing.T) {
	m := layoutMenu(secConnections, 100, 30)
	m.connCursor = 1
	view := m.connectionsView(20)
	if strings.Contains(view, "no credentials") {
		t.Fatalf("cert-only OpenVPN connection reported missing credentials:\n%s", view)
	}
	if !strings.Contains(view, "certificate only") {
		t.Fatalf("view does not explain the certificate-only auth:\n%s", view)
	}
}

// TestBenchEmptyStateWrapsAtNarrowWidth proves the benchmark explanation is
// wrapped rather than clipped mid-word on a phone-width SSH session.
func TestBenchEmptyStateWrapsAtNarrowWidth(t *testing.T) {
	m := layoutMenu(secBench, 40, 30)
	flat := flatten(m.View())
	for _, want := range []string{"benchmark the stored links", "HTTPS request through it", "limit the run to one group"} {
		if !strings.Contains(flat, want) {
			t.Fatalf("bench view lost %q:\n%s", want, m.View())
		}
	}
}

// TestDNSViewWrapsExplanationAndRows keeps the fail-closed explanation and a
// long upstream list readable at narrow widths.
func TestDNSViewWrapsExplanationAndRows(t *testing.T) {
	m := layoutMenu(secDNS, 40, 40)
	m.settings.DNSUpstream = []string{"https://dns.quad9.net/dns-query", "tls://one.one.one.one:853"}
	view := m.dnsView(24)
	flat := flatten(view)
	for _, want := range []string{"leaking to the local resolver", "dns.quad9.net"} {
		if !strings.Contains(flat, want) {
			t.Fatalf("dns view lost %q:\n%s", want, view)
		}
	}
	if strings.Contains(flat, "…") {
		t.Fatalf("dns view clipped a value instead of wrapping it:\n%s", view)
	}
}

// TestImportLastImportWraps keeps the imported-link name readable instead of
// cutting it off at the content edge.
func TestImportLastImportWraps(t *testing.T) {
	m := layoutMenu(secImport, 40, 30)
	m.lastImport = "imported:Example VPN Europe 3 (TCP) — europe3.vpn.example.net"
	view := m.importView(24)
	flat := flatten(view)
	for _, want := range []string{"Last import", "Example VPN Europe 3", "europe3.vpn.example.net"} {
		if !strings.Contains(flat, want) {
			t.Fatalf("import view lost %q:\n%s", want, view)
		}
	}
}

// TestLayoutGoldenCaptures stores the rendered frames an operator would see at
// three terminal widths, so a later layout change shows up as a readable diff
// instead of a silently shifted column. Regenerate with -update-layout.
func TestLayoutGoldenCaptures(t *testing.T) {
	cases := []struct {
		name  string
		s     section
		width int
		setup func(*Menu)
	}{
		{"dashboard-40", secDashboard, 40, nil},
		{"dashboard-80", secDashboard, 80, nil},
		{"dashboard-120", secDashboard, 120, nil},
		{"connections-40", secConnections, 40, nil},
		{"connections-80", secConnections, 80, nil},
		{"tests-run-40", secTests, 40, nil},
		{"tests-run-80", secTests, 80, nil},
		{"tests-run-120", secTests, 120, nil},
		{"tests-results-80", secTests, 80, func(m *Menu) { m.tests.tab = testTabResults }},
		{"tests-compare-40", secTests, 40, func(m *Menu) { m.tests.tab = testTabCompare }},
		{"tests-compare-80", secTests, 80, func(m *Menu) { m.tests.tab = testTabCompare }},
		{"tests-compare-120", secTests, 120, func(m *Menu) { m.tests.tab = testTabCompare }},
		{"sources-40", secSubscriptions, 40, nil},
		{"sources-80", secSubscriptions, 80, nil},
		{"sources-120", secSubscriptions, 120, nil},
		{"routing-40", secRouting, 40, nil},
		{"routing-80", secRouting, 80, nil},
		{"routing-120", secRouting, 120, nil},
		{"gateway-40", secGateway, 40, nil},
		{"gateway-80", secGateway, 80, nil},
		{"bench-40", secBench, 40, nil},
		{"import-40", secImport, 40, nil},
		{"settings-40", secSettings, 40, nil},
		{"about-40", secAbout, 40, nil},
		{"logs-80", secLogs, 80, nil},
	}
	for _, c := range cases {
		restore := pinAboutPaths()
		m := layoutMenu(c.s, c.width, 30)
		if c.setup != nil {
			c.setup(m)
		}
		got := stripANSI(m.View())
		restore()
		path := filepath.Join("testdata", "layout", c.name+".txt")
		if *updateLayout {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run go test ./internal/tui -update-layout)", c.name, err)
		}
		// Git may check golden files out with CRLF on Windows; the rendered frame
		// is always LF, so compare on normalized text.
		wantText := strings.ReplaceAll(string(want), "\r\n", "\n")
		if wantText != got {
			t.Fatalf("%s: rendered frame differs from %s:\n--- want ---\n%s\n--- got ---\n%s", c.name, path, wantText, got)
		}
	}
}

// pinAboutPaths makes the Installation rows independent of the test machine so
// a golden capture stays stable between runs.
func pinAboutPaths() func() {
	prev := aboutPaths
	aboutPaths = func() *paths.Resolved {
		return &paths.Resolved{
			ConfigFile: "/etc/bypath/config.yaml",
			ProfileDir: "/etc/bypath/profiles",
			TmpDir:     "/run/bypath/tmp",
			LogDir:     "/var/log/bypath",
		}
	}
	return func() { aboutPaths = prev }
}

var ansiPattern = regexp.MustCompile("\x1b\\[[0-9;]*m")

func stripANSI(s string) string { return ansiPattern.ReplaceAllString(s, "") }

// flatten collapses rendered text into one line so assertions do not depend on
// where the wrap fell.
func flatten(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
}

// columnOf returns the display column at which needle starts in line, or -1.
func columnOf(line, needle string) int {
	idx := strings.Index(line, needle)
	if idx < 0 {
		return -1
	}
	return lipgloss.Width(line[:idx])
}
