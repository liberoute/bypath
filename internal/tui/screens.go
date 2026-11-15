package tui

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

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/paths"
)

// View implements tea.Model.
func (m *Menu) View() string {
	if m.width == 0 {
		m.width, m.height = 100, 30
	}
	if m.svc == nil && m.svcErr != nil {
		return m.fatalView()
	}
	header := m.viewHeader()
	tabs := m.viewTabs()
	footer := m.viewFooter()
	h := m.bodyHeight()
	var body string
	switch {
	case m.overlay.kind != ovNone:
		body = m.overlayView(h)
	case m.detail != nil:
		body = m.detailView(h)
	default:
		body = m.sectionView(h)
	}
	lines := []string{header, tabs}
	if m.notice != "" {
		lines = append(lines, m.noticeLine())
	}
	lines = append(lines, body, footer)
	return strings.Join(lines, "\n")
}

func (m *Menu) fatalView() string {
	w := m.width
	lines := []string{
		styleTitle.Render("BYPATH"),
		"",
		styleErr.Render("The application service could not be opened."),
		"",
		friendlyError(m.svcErr),
		"",
		styleMuted.Render("r  retry        q  quit"),
	}
	for i := range lines {
		lines[i] = fillLine(clipLine(lines[i], w), w)
	}
	return strings.Join(lines, "\n")
}

// --- chrome ---

// viewHeader renders the identity line. Every segment is optional except the
// product, its variant and the state; the link name is shortened before any of
// those is dropped, so a narrow window never loses the edition or the state.
//
// The link is labelled "running" or "selected" on purpose: the persisted
// selection and the link actually carrying traffic are different facts, and a
// header that shows one unlabelled name invites the wrong conclusion.
func (m *Menu) viewHeader() string {
	w := m.contentWidth()
	state, stateStyle := m.displayState()
	variant := strings.ToUpper(m.status.Variant)
	if variant == "" {
		variant = "BUILD"
	}

	core := styleTitle.Render("BYPATH") + " " + styleMuted.Render("["+variant+"]")
	core += "  " + stateStyle.Bold(true).Render(state)
	if m.status.Running && m.status.PID > 0 {
		core += "  " + styleMuted.Render(fmt.Sprintf("pid %d", m.status.PID))
	}

	if m.status.ActiveLink != "" {
		label := "running "
		if !m.status.Running {
			label = "selected "
		}
		labelStyled := styleMuted.Render("  ·  " + label)
		room := w - lipgloss.Width(core) - lipgloss.Width(labelStyled) - 1
		if room >= 6 {
			core += labelStyled + styleAccent.Render(truncatePlain(m.status.ActiveLink, room))
		}
	}
	return fillLine(core, w)
}

// displayState is what the header and status lines report. A FAILED runtime
// with a fallback link carrying verified traffic is DEGRADED, not down: the
// operator needs to know the tunnel works, and that it is not on the link they
// asked for.
func (m *Menu) displayState() (string, lipgloss.Style) {
	state := strings.ToUpper(m.status.State)
	if state == "" {
		state = "…"
	}
	if state == "FAILED" && m.fallbackCarrying() && m.healthFresh() {
		return "DEGRADED", styleWarn
	}
	return state, stateColor(state)
}

// fallbackCarrying reports whether a group fallback is serving traffic.
func (m *Menu) fallbackCarrying() bool {
	return m.status.FallbackFrom != "" && m.status.ActiveLink != ""
}

// healthFresh bounds the fallback claim: without a recent successful health
// check the fallback is only "last known good", which must not be presented as
// a working tunnel.
func (m *Menu) healthFresh() bool {
	if m.status.LastHealth == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, m.status.LastHealth)
	if err != nil {
		return false
	}
	return time.Since(t) < 5*time.Minute
}

// healthSummary maps the gateway's health proof to a short label and the
// evidence behind it. An identity lookup failure is labelled as such and is
// never presented as a dead tunnel.
func (m *Menu) healthSummary() (string, string) {
	switch strings.ToUpper(m.status.HealthCode) {
	case "VERIFIED":
		return "verified", ""
	case "TUNNEL_DOWN":
		return "tunnel down", m.status.HealthDetail
	case "DATA_PATH_DOWN":
		return "data path down", m.status.HealthDetail
	case "EXIT_UNKNOWN":
		return "exit unverified", m.status.HealthDetail
	case "UPLINK_UNVERIFIED":
		return "uplink unverified", m.status.HealthDetail
	case "EXIT_IS_UPLINK":
		return "exit is uplink", m.status.HealthDetail
	}
	return "", ""
}

// healthProofRow renders the health evidence row, falling back to the bare
// timestamp for gateways that predate the proof codes.
func (m *Menu) healthProofRow(labelW int) []string {
	label, detail := m.healthSummary()
	if label == "" {
		if m.status.LastHealth == "" {
			return nil
		}
		return m.kvRow("Last health", m.status.LastHealth, labelW)
	}
	value := label
	if m.status.LastHealth != "" {
		value += styleMuted.Render("  " + m.status.LastHealth)
	}
	if detail != "" {
		value += styleMuted.Render("  (" + detail + ")")
	}
	return m.kvRow("Health proof", value, labelW)
}

func (m *Menu) viewTabs() string {
	w := m.contentWidth()
	var parts []string
	total := 1 // leading space
	for i, title := range sectionTitles {
		// Ten sections exceed the nine numeric shortcuts; the last stays
		// reachable through tab/shift+tab.
		label := fmt.Sprintf("%d %s", i+1, title)
		if i >= 9 {
			label = "· " + title
		}
		if section(i) == m.section {
			parts = append(parts, styleActive.Render(" "+label+" "))
			total += lipgloss.Width(label) + 2
		} else {
			parts = append(parts, styleMuted.Render(label))
			total += lipgloss.Width(label)
		}
	}
	line := " " + strings.Join(parts, "  ")
	if len(parts) > 1 {
		total += 2 * (len(parts) - 1)
	}
	if total > w || lipgloss.Width(line) > w {
		line = fmt.Sprintf(" %d/%d %s", int(m.section)+1, int(secCount), styleAccent.Render(sectionTitles[m.section]))
		// The navigation hint is a convenience; on a narrow terminal it is dropped
		// whole rather than left cut off mid-word.
		hint := "   tab/shift+tab: cycle · 1-9: jump"
		if lipgloss.Width(line)+lipgloss.Width(hint) <= w {
			line += styleMuted.Render(hint)
		}
	}
	return fillLine(clipLine(line, w), w)
}

func (m *Menu) noticeLine() string {
	prefix := styleOK.Render("✓ ")
	if m.noticeErr {
		prefix = styleErr.Render("! ")
	}
	return fillLine(" "+prefix+clipLine(m.notice, m.contentWidth()-3), m.contentWidth())
}

func (m *Menu) viewFooter() string {
	w := m.contentWidth()
	lines := m.footerLines(w)
	if m.busy != "" {
		spinner := spinnerFrames[m.spinner%len(spinnerFrames)]
		right := styleWarn.Render(spinner + " " + truncatePlain(m.busy, 40))
		last := lines[len(lines)-1]
		gap := w - lipgloss.Width(last) - lipgloss.Width(right) - 1
		if gap > 0 {
			lines[len(lines)-1] = last + strings.Repeat(" ", gap+1) + right
		} else {
			lines = append(lines, fillLine(" "+right, w))
		}
	}
	for i := range lines {
		lines[i] = fillLine(lines[i], w)
	}
	return strings.Join(lines, "\n")
}

// footerLines wraps the key hints instead of clipping them. An 80-column SSH
// session is the most common terminal, and a cut-off hint is undiscoverable.
func (m *Menu) footerLines(width int) []string {
	keys := m.footerKeys()
	parts := strings.Split(keys, "  ")
	avail := width - 1 // leading space
	var lines []string
	cur := ""
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if cur == "" {
			cur = part
			continue
		}
		if lipgloss.Width(cur)+2+lipgloss.Width(part) <= avail {
			cur += "  " + part
			continue
		}
		lines = append(lines, cur)
		cur = part
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	if len(lines) == 0 {
		lines = []string{""}
	}
	for i := range lines {
		lines[i] = " " + clipLine(lines[i], avail)
		lines[i] = styleMuted.Render(lines[i])
	}
	return lines
}

func (m *Menu) footerHeight() int {
	// Measure what is actually rendered: the busy spinner shares the last line
	// when it fits and adds one only when it does not.
	return lipgloss.Height(m.viewFooter())
}

func (m *Menu) footerKeys() string {
	if m.overlay.kind != ovNone {
		return m.overlayFooter()
	}
	if m.detail != nil {
		return "↑/↓ scroll   esc close"
	}
	switch m.section {
	case secDashboard:
		return "2 connections  3 tests  8 import  p probe exit IP  r refresh  q quit"
	case secConnections:
		return "↑/↓ move  enter inspect  c connect  a next start  u credentials  e rename  d display name  x delete  h hide  H hidden  m move  N group  R rename group  X delete group  [ ] order  g filter  / search  f clear  M migrate  n import"
	case secTests:
		return "t run/results/compare  K kind  s scope  g group  l link  i hidden  enter start/evidence  c cancel  r reload  ↑/↓ move"
	case secSubscriptions:
		return "↑/↓ move  enter details  a add source  o organize  x remove source  r refresh  R refresh all  i import dump"
	case secRouting:
		return "↑/↓ move  / filter  c clear  r reload  read-only in terminal"
	case secBench:
		return "↑/↓ move  r run  enter/a select  g scope  s sort  esc dashboard"
	case secImport:
		return "↑/↓ choose  enter start  r refresh  esc dashboard"
	case secGateway:
		return "c connect  d disconnect  R restart  r refresh  1-9 sections  q quit"
	case secDNS:
		return "m mode  u upstreams  r refresh  q quit"
	case secSettings:
		return "↑/↓ move  enter edit  r reload  q quit"
	case secLogs:
		return "↑/↓ scroll  f follow  / filter  c clear  e export  r refresh"
	case secAbout:
		return "1-9 jump  tab cycle  q quit"
	}
	return "1-9 sections  tab next  q quit"
}

// --- section dispatch ---

func (m *Menu) sectionView(h int) string {
	switch m.section {
	case secDashboard:
		return m.dashboardView(h)
	case secConnections:
		return m.connectionsView(h)
	case secTests:
		return m.testsView(h)
	case secSubscriptions:
		return m.subscriptionsView(h)
	case secRouting:
		return m.routingView(h)
	case secSettings:
		return m.settingsView(h)
	case secBench:
		return m.benchView(h)
	case secImport:
		return m.importView(h)
	case secGateway:
		return m.gatewayView(h)
	case secDNS:
		return m.dnsView(h)
	case secLogs:
		return m.logsView(h)
	case secAbout:
		return m.aboutView(h)
	}
	return ""
}

func (m *Menu) panel(title string, rows []string) []string {
	out := []string{"", " " + styleTitle.Render(title)}
	out = append(out, rows...)
	return out
}

func kv(label, value string, labelWidth int) string {
	return " " + styleLabel.Render(fmt.Sprintf("%-*s", labelWidth, label)) + " " + value
}

// kvRow is kv with a fallback: a value that does not fit wraps under itself
// instead of losing its tail to the terminal edge.
func (m *Menu) kvRow(label, value string, labelWidth int) []string {
	if labelWidth+2+lipgloss.Width(value) <= m.contentWidth() {
		return []string{kv(label, value, labelWidth)}
	}
	return m.kvLines(label, value, labelWidth, lipgloss.NewStyle())
}

// --- dashboard ---

func (m *Menu) dashboardView(h int) string {
	const labelW = 15
	state, stateStyle := m.displayState()
	statusLine := " " + stateStyle.Bold(true).Render("● "+state)
	if m.status.Running {
		statusLine += styleMuted.Render(fmt.Sprintf("   pid %d", m.status.PID))
		if m.status.UptimeSec > 0 {
			statusLine += styleMuted.Render("   uptime " + formatDuration(time.Duration(m.status.UptimeSec)*time.Second))
		}
	}
	if m.fallbackCarrying() {
		statusLine += styleWarn.Render("   fallback")
	}

	var rows []string
	rows = append(rows, statusLine)
	if m.statusErr != "" {
		rows = append(rows, m.indentedLines(m.statusErr, 2, styleErr)...)
	}
	if banner := m.selectionBannerLines(); len(banner) > 0 {
		rows = append(rows, banner...)
	}
	if m.status.LayerWarning != "" {
		rows = append(rows, m.indentedLines("Organisation layer: "+m.status.LayerWarning, 2, styleWarn)...)
	}
	rows = append(rows, "")

	running := styleMuted.Render("not running")
	if m.status.Running {
		running = orDash(m.status.ActiveLink)
	}
	rows = append(rows, m.kvRow("Running", running, labelW)...)

	selected := m.status.SelectedLink
	switch {
	case selected == "":
		rows = append(rows, m.kvRow("Selected", styleMuted.Render("none selected"), labelW)...)
	case m.status.Running && m.status.ActiveLink != "" && selected != m.status.ActiveLink:
		rows = append(rows, m.kvRow("Selected", selected+styleMuted.Render("   (applies on next connect)"), labelW)...)
	default:
		rows = append(rows, m.kvRow("Selected", selected, labelW)...)
	}
	if m.status.FallbackFrom != "" {
		rows = append(rows, m.kvLines("Fallback from", m.status.FallbackFrom, labelW, lipgloss.NewStyle())...)
		if m.status.FallbackError != "" {
			rows = append(rows, m.kvLines("Fallback cause", m.status.FallbackError, labelW, styleWarn)...)
		}
	}

	proto := m.status.Protocol
	engine := m.status.Engine
	if proto == "" && engine == "" {
		rows = append(rows, m.kvRow("Protocol", styleMuted.Render("—"), labelW)...)
	} else {
		rows = append(rows, m.kvRow("Protocol", proto+styleMuted.Render(" / ")+engine, labelW)...)
	}
	gateway := "proxy only (no TUN)"
	if m.status.GatewayMode {
		gateway = "transparent TUN gateway"
	}
	dns := m.status.DNSMode
	if dns == "" {
		dns = "strict"
	}
	rows = append(rows, m.kvRow("Gateway mode", gateway, labelW)...)
	rows = append(rows, m.kvRow("DNS mode", dns, labelW)...)

	switch {
	case m.exitIP != "":
		rows = append(rows, m.kvRow("Public exit IP", m.exitIP+styleMuted.Render("  probed "+shortAge(m.exitAt)), labelW)...)
	case m.exitErr != "":
		rows = append(rows, m.kvLines("Public exit IP", m.exitErr, labelW, styleWarn)...)
	default:
		rows = append(rows, m.kvRow("Public exit IP", styleMuted.Render("unknown — press p to probe"), labelW)...)
	}

	rows = append(rows, m.kvRow("Restarts", fmt.Sprintf("%d   data-path %d   recovery attempt %d", m.status.Restarts, m.status.TunRestarts, m.status.Recovery), labelW)...)
	if row := m.healthProofRow(labelW); len(row) > 0 {
		rows = append(rows, row...)
	}
	rows = append(rows, m.kvRow("Profiles", fmt.Sprintf("%d connections in %d source(s)", m.status.ProfileCount, m.status.SubCount), labelW)...)
	rows = append(rows, m.kvRow("Organisation", m.organisationSummary(), labelW)...)
	rows = append(rows, m.kvRow("Tests", m.testSummary(), labelW)...)
	rows = append(rows, m.kvRow("Listeners", fmt.Sprintf("api %d · socks %d · dns %d", m.status.APIPort, m.status.SOCKSPort, m.status.DNSPort), labelW)...)
	if m.status.LANInterface != "" {
		rows = append(rows, m.kvRow("LAN interface", m.status.LANInterface, labelW)...)
	}
	if m.status.LastError != "" {
		rows = append(rows, "", " "+styleErr.Render("Last error"))
		rows = append(rows, m.indentedLines(m.status.LastError, 2, styleErr)...)
	}
	if !m.status.Running {
		rows = append(rows, "", " "+styleWarn.Render("The gateway is not running."))
		rows = append(rows, " "+styleMuted.Render("Start it with: sudo bypath run"))
	}
	return m.layoutRows(rows, h)
}

func (m *Menu) dashboardKey(key string) tea.Cmd {
	switch key {
	case "p":
		if m.status.State != "CONNECTED" {
			m.setNotice(true, "The exit address can only be probed while the gateway is CONNECTED.")
			return nil
		}
		return m.probeExit()
	case "c":
		if m.status.ActiveID == "" {
			m.setNotice(true, "No active connection. Choose one in Connections (2).")
			return nil
		}
		id := m.status.ActiveID
		return m.runAction("Connect", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
			return svc.Connect(ctx, id)
		})
	}
	return nil
}

// --- connections ---

// filteredConnections applies the organisation-group filter client-side. The
// list itself is fetched with the legacy filter plus hidden entries, so one
// reload serves both organisations that exist and organisations that do not.
func (m *Menu) filteredConnections() []app.Connection {
	if m.connLayerGroup == "" {
		return m.conns
	}
	out := make([]app.Connection, 0, len(m.conns))
	for _, c := range m.conns {
		if m.connLayerGroup == layerUngrouped {
			if c.LayerGroupID == "" {
				out = append(out, c)
			}
			continue
		}
		if c.LayerGroupID == m.connLayerGroup {
			out = append(out, c)
		}
	}
	return out
}

func (m *Menu) connectionsView(h int) string {
	w := m.contentWidth()
	list := m.filteredConnections()
	view := "all"
	if m.connLayerGroup == layerUngrouped {
		view = "Ungrouped"
	} else if m.connLayerGroup != "" {
		view = m.groupName(m.connLayerGroup)
	}
	search := m.connFilter
	if search == "" {
		search = "—"
	}
	hidden := "hidden: shown"
	if !m.connShowHidden {
		hidden = "hidden: excluded"
	}
	filterLine := " " + styleMuted.Render("view: ") + view + styleMuted.Render("   search: ") + search + styleMuted.Render("   "+hidden)
	count := fmt.Sprintf("   %d of %d connection(s)", len(list), len(m.conns))
	if m.connLoading {
		count += "  loading…"
	}
	if lipgloss.Width(filterLine)+lipgloss.Width(count) <= w {
		filterLine += styleMuted.Render(count)
	}
	rows := []string{"", filterLine}
	if m.connErr != "" {
		rows = append(rows, m.indentedLines(m.connErr, 1, styleErr)...)
	}
	if banner := m.selectionBannerLines(); len(banner) > 0 {
		rows = append(rows, banner...)
	}
	switch {
	case m.layerErr != "":
		rows = append(rows, m.indentedLines("Organisation layer unavailable: "+m.layerErr, 2, styleWarn)...)
	case !m.layerStatus.Migrated:
		rows = append(rows, m.indentedLines("Organisation is not set up yet. M adds labels only; links, .active and the serving tunnel are not rewritten.", 2, styleMuted)...)
	case m.layerStatus.ReadOnly:
		rows = append(rows, m.indentedLines("Organisation is read-only; group and label edits are disabled.", 2, styleWarn)...)
	}
	if len(list) == 0 && m.connErr == "" {
		if m.connLayerGroup != "" || m.connFilter != "" {
			rows = append(rows, "", " "+styleMuted.Render("No connection matches this view. f clears the filters."))
		} else {
			rows = append(rows, "", " "+styleMuted.Render("No connections. Press 8 to import a link or an OpenVPN profile."))
		}
		return m.layoutRows(rows, h)
	}

	widths := m.connectionsTableWidths(w)
	header := m.connectionsRow(widths, "NAME", "PROTO", "ADDRESS", "ENGINE", "FLAGS", "HEALTH")
	rows = append(rows, " "+styleMuted.Render(clipLine(header, w-1)))

	visible := h - len(rows) - 2
	if visible < 3 {
		visible = 3
	}
	m.clampConnCursor()
	if m.connCursor < m.connOffset {
		m.connOffset = m.connCursor
	}
	if m.connCursor >= m.connOffset+visible {
		m.connOffset = m.connCursor - visible + 1
	}
	if m.connOffset < 0 {
		m.connOffset = 0
	}
	end := minInt(len(list), m.connOffset+visible)
	for i := m.connOffset; i < end; i++ {
		c := list[i]
		// "selected" is the persisted choice; "running" is the link carrying
		// traffic right now. Saving a selection does not apply it, so the two
		// markers must not mean the same thing.
		marker := "  "
		running := m.connectionRunning(c)
		switch {
		case running && c.Active:
			marker = styleOK.Render("▶ ")
		case running:
			marker = styleAccent.Render("▶ ")
		case c.Active:
			marker = styleOK.Render("● ")
		}
		health := styleMuted.Render("—")
		switch c.Health {
		case "ok":
			health = styleOK.Render("ok")
		case "failed":
			health = styleErr.Render("failed")
		}
		line := marker + m.connectionNameCell(c, widths.name) + " " +
			padTo(truncatePlain(strings.ToUpper(c.Protocol), widths.proto), widths.proto) + " " +
			padTo(truncatePlain(hostPort(c), widths.addr), widths.addr)
		if !widths.compact {
			line += " " + padTo(truncatePlain(c.Engine, widths.engine), widths.engine) + " " +
				padTo(truncatePlain(connectionFlags(c), widths.flags), widths.flags) + " " + health
		}
		rows = append(rows, m.highlightRow(i, line, w))
	}
	if end < len(list) {
		rows = append(rows, " "+styleMuted.Render(fmt.Sprintf("… %d more", len(list)-end)))
	}
	rows = append(rows, "")
	legend := "● selected   ▶ running"
	legendNote := "(a saves the selection; c applies it)"
	if lipgloss.Width(legend)+1+lipgloss.Width(legendNote) <= w {
		rows = append(rows, " "+styleMuted.Render(legend+"   "+legendNote))
	} else {
		rows = append(rows, " "+styleMuted.Render(legend))
		rows = append(rows, m.indentedLines(legendNote, 1, styleMuted)...)
	}
	if sel := m.selectedConnection(); sel != nil {
		cred := "credentials: none stored"
		if sel.CredentialsSaved {
			cred = "credentials: encrypted at rest"
		} else if sel.HasCredentials {
			cred = "credentials: session only"
		}
		if sel.Protocol == "openvpn" && !sel.RequiresAuth {
			// A cert-only OpenVPN profile needs no password. Saying "no
			// credentials" read as a missing requirement and sent the operator
			// looking for a username that the profile never uses.
			cred = "auth: certificate only (no username or password)"
		}
		extra := ""
		if sel.FromSubscription != "" {
			extra = "   source: " + sel.FromSubscription
		}
		if sel.RequiresAuth && !sel.HasCredentials {
			extra += "   " + styleWarn.Render("auth required")
		}
		if m.layerStatus.Migrated {
			extra += "   organisation: " + m.groupName(sel.LayerGroupID)
		}
		if sel.Hidden {
			extra += "   " + styleWarn.Render("hidden")
		}
		if sel.Orphaned {
			extra += "   " + styleWarn.Render("orphaned")
		}
		rows = append(rows, m.indentedLines(cred+extra, 1, styleMuted)...)
	}
	return m.layoutRows(rows, h)
}

// connectionTableWidths distributes the terminal width across the columns.
// Fixed widths pushed the address into the next column whenever a name was
// long or contained wide characters.
type connectionTableWidths struct {
	name, proto, addr, engine, flags, health int
	compact                                  bool
}

func (m *Menu) connectionsTableWidths(w int) connectionTableWidths {
	const (
		protoW  = 8
		engineW = 9
		flagsW  = 14
		healthW = 6
		markerW = 2
	)
	cw := connectionTableWidths{proto: protoW, engine: engineW, flags: flagsW, health: healthW}
	if w < 82 {
		cw.compact = true
		// A data row is marker(2) + name + " " + proto(8) + " " + addr, so the
		// flexible columns share w-12. Splitting w-4 instead pushed the address
		// past the right edge as soon as the terminal dropped below 80 columns.
		avail := w - (markerW + 1 + protoW + 1)
		if avail < 24 {
			avail = 24
		}
		cw.name = maxInt(10, avail*55/100)
		cw.addr = maxInt(10, avail-cw.name)
		return cw
	}
	fixed := 1 + markerW + (1 + protoW) + (1 + engineW) + (1 + flagsW) + (1 + healthW)
	avail := w - fixed
	if avail < 32 {
		avail = 32
	}
	cw.name = minInt(38, maxInt(16, avail*55/100))
	cw.addr = maxInt(16, avail-cw.name)
	return cw
}

// connectionsRow builds a header row with the same widths as the data rows.
func (m *Menu) connectionsRow(cw connectionTableWidths, name, proto, addr, engine, flags, health string) string {
	row := strings.Repeat(" ", 2) + padTo(name, cw.name) + " " + padTo(proto, cw.proto) + " " + padTo(addr, cw.addr)
	if cw.compact {
		return row
	}
	return row + " " + padTo(engine, cw.engine) + " " + padTo(flags, cw.flags) + " " + health
}

// connectionNameCell renders the group-qualified name. The prefix is styled
// only after the plain text has been truncated, so a long name can never be cut
// inside an escape sequence or shifted by a wide character.
func (m *Menu) connectionNameCell(c app.Connection, width int) string {
	group := ""
	if c.LayerGroup != "" {
		group = c.LayerGroup + "/"
	} else if c.Group != "" && c.Group != "default" && !m.layerStatus.Migrated {
		group = c.Group + "/"
	}
	text := truncatePlain(group+connectionName(c), width)
	if group != "" && strings.HasPrefix(text, group) {
		rest := text[len(group):]
		return styleMuted.Render(group) + padTo(rest, maxInt(0, width-lipgloss.Width(group)))
	}
	return padTo(text, width)
}

// connectionRunning reports whether the gateway is carrying traffic through
// this connection right now.
func (m *Menu) connectionRunning(c app.Connection) bool {
	if !m.status.Running || m.status.ActiveLink == "" || c.Remark != m.status.ActiveLink {
		return false
	}
	return m.status.ActiveGroup == "" || c.Group == m.status.ActiveGroup
}

func (m *Menu) highlightRow(idx int, line string, width int) string {
	if idx != m.connCursor {
		return " " + line
	}
	return styleActive.Render(" " + padTo(line, width-2) + " ")
}

func (m *Menu) selectedConnection() *app.Connection {
	list := m.filteredConnections()
	if m.connCursor >= 0 && m.connCursor < len(list) {
		return &list[m.connCursor]
	}
	return nil
}

func (m *Menu) connectionsKey(k tea.KeyMsg, key string) tea.Cmd {
	list := m.filteredConnections()
	switch key {
	case "up", "k":
		m.moveConn(-1)
	case "down", "j":
		m.moveConn(1)
	case "pgup":
		m.moveConn(-10)
	case "pgdown":
		m.moveConn(10)
	case "home":
		m.connCursor = 0
	case "end", "G":
		m.connCursor = maxInt(0, len(list)-1)
	case "enter":
		if c := m.selectedConnection(); c != nil {
			return m.loadDetail(c.ID)
		}
	case "/":
		m.promptInput("Search connections", "Name, address or group", m.connFilter, false, func(m *Menu, value string) tea.Cmd {
			m.connFilter = strings.TrimSpace(value)
			m.connOffset = 0
			m.connCursor = 0
			return m.loadConnections()
		})
	case "g":
		return m.filterGroupFlow()
	case "f":
		m.connFilter, m.connGroup, m.connLayerGroup = "", "", ""
		m.connOffset, m.connCursor = 0, 0
		return m.loadConnections()
	case "H":
		m.connShowHidden = !m.connShowHidden
		m.connOffset, m.connCursor = 0, 0
		return m.loadConnections()
	case "a":
		c := m.selectedConnection()
		if c == nil {
			return nil
		}
		id := c.ID
		return m.runAction("Select", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
			return svc.SetActive(ctx, id)
		})
	case "c":
		c := m.selectedConnection()
		if c == nil {
			return nil
		}
		id, label := c.ID, connectionName(*c)
		m.confirmAction("Connect through "+truncatePlain(label, 40)+"?",
			"The gateway restarts its tunnel stack to apply this connection. Current traffic through the gateway is interrupted briefly.",
			"Connect", false, func(m *Menu) tea.Cmd {
				return m.runAction("Connect", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
					return svc.Connect(ctx, id)
				})
			})
	case "u":
		if c := m.selectedConnection(); c != nil && !c.RequiresAuth {
			if c.Protocol == "openvpn" {
				m.setNotice(false, "This OpenVPN profile authenticates with certificates only; no username or password is needed.")
			} else {
				m.setNotice(false, "This connection keeps its credentials in the imported link; there is nothing to edit here.")
			}
			return nil
		}
		m.credentialFlow()
	case "e":
		c := m.selectedConnection()
		if c == nil {
			return nil
		}
		id := c.ID
		m.promptInput("Rename connection", "New display name", c.Remark, false, func(m *Menu, value string) tea.Cmd {
			name := strings.TrimSpace(value)
			if name == "" {
				m.setNotice(true, "The display name cannot be empty.")
				return nil
			}
			return m.runAction("Rename", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
				if err := svc.RenameConnection(ctx, id, name); err != nil {
					return app.ActionResult{}, err
				}
				return app.ActionResult{Message: fmt.Sprintf("Renamed to %q.", name)}, nil
			})
		})
	case "d":
		if c := m.selectedConnection(); c != nil {
			return m.displayNameFlow(*c)
		}
	case "h":
		if c := m.selectedConnection(); c != nil {
			return m.hideConnection(*c)
		}
	case "m":
		if c := m.selectedConnection(); c != nil {
			return m.moveConnectionFlow(*c)
		}
	case "x":
		if c := m.selectedConnection(); c != nil {
			return m.deleteConnectionFlow(*c)
		}
	case "N":
		return m.createGroupFlow()
	case "R":
		return m.renameGroupFlow()
	case "X":
		return m.deleteGroupFlow()
	case "[":
		return m.reorderGroup(-1)
	case "]":
		return m.reorderGroup(1)
	case "M":
		return m.migrationFlow()
	case "D":
		m.confirmAction("Disconnect the tunnel?",
			"This stops the active tunnel and its routing. The management service stays running so you can reconnect.",
			"Disconnect", true, func(m *Menu) tea.Cmd {
				return m.runAction("Disconnect", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
					return svc.Disconnect(ctx)
				})
			})
	case "n":
		m.goSection(secImport)
		m.importCursor = 0
		return m.reloadCurrent()
	}
	return nil
}

// filterGroupFlow narrows the visible list by organisation group. Before the
// layer exists the only grouping available is the legacy import bucket, so the
// same key keeps that prompt instead of pretending an organisation exists.
func (m *Menu) filterGroupFlow() tea.Cmd {
	if !m.layerStatus.Migrated {
		m.promptInput("Filter by group", "Import group name (empty = all)", m.connGroup, false, func(m *Menu, value string) tea.Cmd {
			m.connGroup = strings.TrimSpace(value)
			m.connOffset = 0
			m.connCursor = 0
			return m.loadConnections()
		})
		return nil
	}
	groups := nonEmptyGroups(m.groups)
	choices := []choice{{label: "All groups"}, {label: "Ungrouped"}}
	ids := []string{"", layerUngrouped}
	for _, g := range groups {
		choices = append(choices, choice{label: fmt.Sprintf("%s (%d)", g.Name, g.Count)})
		ids = append(ids, g.ID)
	}
	choices = append(choices, choice{label: "Cancel"})
	m.confirmChoice("Filter connections", "This filter only changes the list. It never switches the tunnel or the next start.", choices,
		func(m *Menu, idx int) tea.Cmd {
			if idx >= len(ids) {
				return nil
			}
			m.connLayerGroup = ids[idx]
			m.connCursor, m.connOffset = 0, 0
			return nil
		})
	return nil
}

func (m *Menu) credentialFlow() tea.Cmd {
	c := m.selectedConnection()
	if c == nil {
		return nil
	}
	id, label := c.ID, c.Remark
	m.promptInput("Credentials for "+truncatePlain(label, 40), "Username", "", false, func(m *Menu, user string) tea.Cmd {
		user = strings.TrimSpace(user)
		if user == "" {
			m.setNotice(true, "Username is required.")
			return nil
		}
		m.promptInput("Credentials for "+truncatePlain(label, 40), "Password", "", true, func(m *Menu, pass string) tea.Cmd {
			m.confirmChoice("Store credentials",
				"Save an encrypted copy (AES-256-GCM) under the profile directory?\nChoosing session-only keeps them in memory for this run and discards them when the gateway stops.",
				[]choice{{label: "Save securely"}, {label: "Session only"}, {label: "Cancel"}}, func(m *Menu, idx int) tea.Cmd {
					if idx == 2 {
						return nil
					}
					persist := idx == 0
					return m.runAction("Credentials", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
						if err := svc.SetCredentials(ctx, id, app.Credentials{Username: user, Password: pass}, persist); err != nil {
							return app.ActionResult{}, err
						}
						if persist {
							return app.ActionResult{Message: "Credentials saved (encrypted at rest)."}, nil
						}
						return app.ActionResult{Message: "Credentials stored for this run only."}, nil
					})
				})
			return nil
		})
		return nil
	})
	return nil
}

func ovpnNote(c *app.Connection) string {
	if c.Protocol == "openvpn" {
		return ", its packaged .ovpn file"
	}
	return ""
}

func hostPort(c app.Connection) string {
	return net.JoinHostPort(c.Address, strconv.Itoa(c.Port))
}

func connectionFlags(c app.Connection) string {
	var flags []string
	if c.TLS {
		flags = append(flags, "TLS")
	}
	if c.Reality {
		flags = append(flags, "REALITY")
	}
	if c.EncryptedVLESS {
		flags = append(flags, "VLESS-ENC")
	}
	if c.CDN {
		flags = append(flags, "CDN")
	}
	if c.RequiresAuth {
		if c.HasCredentials {
			flags = append(flags, "AUTH✓")
		} else {
			flags = append(flags, "AUTH?")
		}
	}
	return strings.Join(flags, " ")
}

func padTo(s string, width int) string {
	w := lipgloss.Width(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
}

func shortAge(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return formatDuration(time.Since(t)) + " ago"
}

// --- detail overlay ---

func (m *Menu) detailView(h int) string {
	d := m.detail
	if d == nil {
		return ""
	}
	w := m.contentWidth()
	state := styleMuted.Render("not active")
	if d.Active {
		state = styleOK.Render("active selection")
	}
	rows := []string{
		"",
		" " + styleTitle.Render(truncatePlain(connectionName(d.Connection), w-4)) + "  " + state,
		"",
		kv("ID", d.ID, 16),
		kv("Group", d.Group, 16),
	}
	if m.layerStatus.Migrated {
		organisation := m.groupName(d.LayerGroupID)
		if d.Hidden {
			organisation += " · hidden"
		}
		if d.Orphaned {
			organisation += " · orphaned"
		}
		rows = append(rows, kv("Organisation", organisation, 16))
	}
	rows = append(rows,
		kv("Protocol", d.Protocol+" ("+d.Engine+")", 16),
		kv("Server", hostPort(d.Connection), 16),
		kv("Transport", transportOf(d.Connection), 16),
		kv("Security", securityOf(d.Connection), 16),
		kv("Health", healthOf(d), 16),
		kv("Credentials", credentialOf(d), 16),
	)
	if d.FromSubscription != "" {
		rows = append(rows, kv("Subscription", d.FromSubscription, 16))
	}
	if d.OVPN {
		rows = append(rows, m.kvLines("OpenVPN file", d.OVPNPath, 16, lipgloss.NewStyle())...)
	}
	if len(d.Warnings) > 0 {
		rows = append(rows, "", " "+styleWarn.Render("Warnings"))
		for _, warning := range d.Warnings {
			rows = append(rows, m.indentedLines("• "+warning, 2, styleWarn)...)
		}
	}
	rows = append(rows, "", " "+styleMuted.Render("↑/↓ scroll · esc close"))
	visible := h - 1
	if m.detailScroll > len(rows)-3 {
		m.detailScroll = maxInt(0, len(rows)-3)
	}
	end := minInt(len(rows), m.detailScroll+visible)
	return m.layoutRows(rows[m.detailScroll:end], h)
}

func transportOf(c app.Connection) string {
	if c.Network == "" {
		return "tcp"
	}
	return c.Network
}

func securityOf(c app.Connection) string {
	var parts []string
	if c.TLS {
		parts = append(parts, "TLS")
	}
	if c.Reality {
		parts = append(parts, "REALITY")
	}
	if c.EncryptedVLESS {
		parts = append(parts, "VLESS Encryption")
	}
	if len(parts) == 0 {
		return "none / plain"
	}
	return strings.Join(parts, " · ")
}

func healthOf(d *app.ConnectionDetail) string {
	switch d.Health {
	case "ok":
		return "HTTPS capable"
	case "failed":
		return "HTTPS check failed"
	}
	return "unknown"
}

func credentialOf(d *app.ConnectionDetail) string {
	switch d.CredentialStore {
	case "saved":
		return "saved (AES-256-GCM)"
	case "session":
		return "session only"
	}
	if d.RequiresAuth {
		return styleWarn.Render("required, missing")
	}
	return "not required"
}

// --- import section ---

var importActions = []string{
	"Paste a proxy link (VLESS, VMess, Trojan, Shadowsocks, WireGuard, SSH)",
	"Import an OpenVPN profile from a file",
	"Paste an OpenVPN profile",
	"Add a subscription URL",
	"Import a subscription dump (plain or base64)",
}

func (m *Menu) importView(h int) string {
	w := m.contentWidth()
	rows := []string{""}
	rows = append(rows, mutedLines("Everything imported here is validated and stored through the shared application service.", w)...)
	rows = append(rows, "")
	for i, label := range importActions {
		text := truncatePlain(fmt.Sprintf("%d. %s", i+1, label), maxInt(8, w-4))
		line := "  " + text
		if i == m.importCursor {
			line = styleActive.Render("  " + padTo(text, w-3) + " ")
		}
		rows = append(rows, line)
	}
	if m.lastImport != "" {
		rows = append(rows, "")
		rows = append(rows, m.kvLines("Last import", m.lastImport, 12, styleOK)...)
	}
	return m.layoutRows(rows, h)
}

func (m *Menu) importKey(key string) tea.Cmd {
	switch key {
	case "up", "k":
		m.importCursor = clampInt(m.importCursor-1, 0, len(importActions)-1)
	case "down", "j":
		m.importCursor = clampInt(m.importCursor+1, 0, len(importActions)-1)
	case "enter":
		return m.startImport(m.importCursor)
	}
	return nil
}

func (m *Menu) startImport(idx int) tea.Cmd {
	if m.svc == nil {
		m.setNotice(true, "Application service is not available: %s", friendlyError(m.svcErr))
		return nil
	}
	switch idx {
	case 0:
		m.uriImportFlow()
	case 1:
		dir := defaultBrowseDir()
		m.pickFile("OpenVPN profile (.ovpn)", dir, ".ovpn", func(m *Menu, path string) tea.Cmd {
			return m.startOpenVPNWizard(app.OVPNSource{Path: path}, "")
		})
	case 2:
		m.promptText("Paste OpenVPN profile", "ctrl+s import · esc cancel", func(m *Menu, text string) tea.Cmd {
			if strings.TrimSpace(text) == "" {
				m.setNotice(true, "The profile is empty.")
				return nil
			}
			return m.startOpenVPNWizard(app.OVPNSource{Text: text}, "")
		})
	case 3:
		m.addSubscriptionFlow()
	case 4:
		m.promptText("Paste subscription dump", "plain links or base64 · ctrl+s preview · esc cancel", func(m *Menu, text string) tea.Cmd {
			if strings.TrimSpace(text) == "" {
				m.setNotice(true, "The dump is empty.")
				return nil
			}
			return m.previewSubscriptionText(text)
		})
	}
	return nil
}

func (m *Menu) uriImportFlow() tea.Cmd {
	m.promptText("Paste proxy link", "ctrl+s continue · esc cancel", func(m *Menu, uri string) tea.Cmd {
		uri = strings.TrimSpace(uri)
		if uri == "" {
			m.setNotice(true, "No link was provided.")
			return nil
		}
		m.promptInput("Import link", "Group (default: default)", "default", false, func(m *Menu, group string) tea.Cmd {
			group = strings.TrimSpace(group)
			if group == "" {
				group = "default"
			}
			m.confirmAction("Import this link?",
				"Group: "+group+"\n"+app.Redact(truncatePlain(uri, 120))+"\n\nIdentical links are rejected instead of duplicated.",
				"Import", false, func(m *Menu) tea.Cmd {
					return m.runAction("Import link", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
						res, err := svc.ImportURI(ctx, group, uri)
						if err != nil {
							return app.ActionResult{}, err
						}
						return app.ActionResult{Message: importResultMessage(res)}, nil
					})
				})
			return nil
		})
		return nil
	})
	return nil
}

func importResultMessage(res app.ImportResult) string {
	var parts []string
	if len(res.Created) > 0 {
		parts = append(parts, fmt.Sprintf("imported %d connection(s) into %s", len(res.Created), res.Group))
	}
	for _, s := range res.Skipped {
		parts = append(parts, fmt.Sprintf("skipped %s: %s", s.Name, s.Reason))
	}
	if len(parts) == 0 {
		parts = append(parts, "nothing to import")
	}
	return strings.Join(parts, "; ")
}

// --- subscriptions ---

func (m *Menu) subscriptionsView(h int) string {
	w := m.contentWidth()
	rows := []string{""}
	rows = append(rows, mutedLines(fmt.Sprintf("%d source(s) · URLs are shown redacted; tokens never reach a log or status surface. Removing a source is guarded like deleting a connection.", len(m.subs)), w)...)
	if m.subErr != "" {
		rows = append(rows, " "+styleErr.Render(truncatePlain(m.subErr, w-2)))
	}
	if m.subLoading {
		rows = append(rows, " "+styleMuted.Render("refreshing list…"))
	}
	if len(m.subs) == 0 {
		rows = append(rows, "", " "+styleMuted.Render("No sources yet. Press a to add one, or 8 to import a dump."))
		return m.layoutRows(rows, h)
	}
	rows = append(rows, "")
	visible := h - len(rows) - 3
	if visible < 3 {
		visible = 3
	}
	if m.subCursor < m.subOffset {
		m.subOffset = m.subCursor
	}
	if m.subCursor >= m.subOffset+visible {
		m.subOffset = m.subCursor - visible + 1
	}
	end := minInt(len(m.subs), m.subOffset+visible)
	for i := m.subOffset; i < end; i++ {
		s := m.subs[i]
		tail := fmt.Sprintf("%d links", s.LinkCount)
		if s.Refreshing {
			tail = "refreshing…"
		}
		// Leave one column for the leading space and one for the highlighted
		// row's right padding; shrink the group before the redacted URL so the
		// link count is never clipped.
		budget := w - 2
		groupW := 18
		urlW := budget - groupW - 4 - lipgloss.Width(tail)
		if urlW < 8 {
			groupW = maxInt(8, groupW-(8-urlW))
			urlW = maxInt(8, budget-groupW-4-lipgloss.Width(tail))
		}
		line := padTo(truncatePlain(s.Group, groupW), groupW) + "  " +
			padTo(truncatePlain(s.RedactedURL, urlW), urlW) + "  " + tail
		if i == m.subCursor {
			rows = append(rows, styleActive.Render(" "+padTo(line, w-2)+" "))
		} else {
			rows = append(rows, " "+line)
		}
		if s.LastError != "" && i == m.subCursor {
			rows = append(rows, "   "+styleErr.Render(truncatePlain(s.LastError, w-6)))
		}
	}
	rows = append(rows, "")
	rows = append(rows, mutedLines("enter details · a add · o organize · x remove source · r refresh · R refresh all · i import dump", w)...)
	return m.layoutRows(rows, h)
}

func (m *Menu) subscriptionsKey(k tea.KeyMsg, key string) tea.Cmd {
	switch key {
	case "up", "k":
		m.moveSub(-1)
	case "down", "j":
		m.moveSub(1)
	case "enter":
		if m.subCursor < len(m.subs) {
			s := m.subs[m.subCursor]
			m.showInfo("Subscription "+s.Group, m.subscriptionInfo(s))
		}
	case "a":
		m.addSubscriptionFlow()
	case "o":
		if m.subCursor >= 0 && m.subCursor < len(m.subs) {
			return m.organizeSourceFlow(m.subs[m.subCursor])
		}
	case "x":
		if m.subCursor < len(m.subs) {
			return m.deleteSourceFlow(m.subs[m.subCursor])
		}
	case "r":
		if m.busy != "" || m.subCursor >= len(m.subs) {
			return nil
		}
		s := m.subs[m.subCursor]
		return m.refreshSubscription(s)
	case "R":
		if m.busy != "" || len(m.subs) == 0 {
			return nil
		}
		subs := append([]app.Subscription(nil), m.subs...)
		return m.refreshAll(subs)
	case "i":
		m.promptText("Import subscription dump", "plain links or base64 · ctrl+s preview · esc cancel", func(m *Menu, text string) tea.Cmd {
			if strings.TrimSpace(text) == "" {
				m.setNotice(true, "The dump is empty.")
				return nil
			}
			return m.previewSubscriptionText(text)
		})
	}
	return nil
}

func (m *Menu) subscriptionInfo(s app.Subscription) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Import list:  %s\n", s.Group)
	fmt.Fprintf(&b, "Default group: %s\n", orDash(s.LayerGroup))
	if s.LayerGroupID == "" {
		fmt.Fprintf(&b, "o organizes this source (proposed: %s). Groups are not failover.\n", s.ProposedGroup)
	}
	fmt.Fprintf(&b, "URL:          %s\n", s.RedactedURL)
	fmt.Fprintf(&b, "Links:        %d\n", s.LinkCount)
	fmt.Fprintf(&b, "Last refresh: %s\n", orDash(s.LastRefresh))
	if s.LastError != "" {
		fmt.Fprintf(&b, "Last error:   %s\n", s.LastError)
	}
	if len(s.Connection) > 0 {
		fmt.Fprintf(&b, "Connections:  %s\n", strings.Join(s.Connection, ", "))
	}
	return b.String()
}

func (m *Menu) addSubscriptionFlow() tea.Cmd {
	m.promptInput("Add subscription", "https://panel.example/sub?token=…  (fetched and previewed before anything is stored)", "", false, func(m *Menu, url string) tea.Cmd {
		url = strings.TrimSpace(url)
		if url == "" {
			m.setNotice(true, "No subscription URL was provided.")
			return nil
		}
		return m.previewSubscriptionURL(url)
	})
	return nil
}

func (m *Menu) previewSubscriptionURL(rawURL string) tea.Cmd {
	if m.svc == nil || m.busy != "" {
		return nil
	}
	m.busy = "Fetching subscription preview"
	m.busySince = time.Now()
	svc := m.svc
	return tea.Batch(func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 130*time.Second)
		defer cancel()
		p, err := svc.PreviewSubscription(ctx, rawURL)
		return subPreviewMsg{preview: p, url: rawURL, err: err}
	}, spinnerTick())
}

func (m *Menu) previewSubscriptionText(text string) tea.Cmd {
	if m.svc == nil || m.busy != "" {
		return nil
	}
	m.busy = "Parsing subscription dump"
	m.busySince = time.Now()
	svc := m.svc
	return tea.Batch(func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		p, err := svc.PreviewSubscriptionText(ctx, text)
		return subPreviewMsg{preview: p, text: text, err: err}
	}, spinnerTick())
}

func (m *Menu) showSubscriptionPreview(msg subPreviewMsg) {
	p := msg.preview
	var b strings.Builder
	fmt.Fprintf(&b, "Proposed organisation group: %s\nSource: %s\nLinks: %d", p.Group, p.RedactedURL, p.Total)
	b.WriteString("\nOnly newly imported connections join this group. Groups are not failover.")
	if p.Duplicates > 0 {
		fmt.Fprintf(&b, "   (%d already installed and will be skipped)", p.Duplicates)
	}
	b.WriteString("\n")
	const shown = 12
	for i, l := range p.Links {
		if i >= shown {
			fmt.Fprintf(&b, "\n… %d more\n", len(p.Links)-i)
			break
		}
		fmt.Fprintf(&b, "\n• %s — %s %s:%d", orDash(l.Remark), strings.ToUpper(l.Protocol), l.Address, l.Port)
		var flags []string
		if l.TLS {
			flags = append(flags, "TLS")
		}
		if l.Reality {
			flags = append(flags, "REALITY")
		}
		if l.EncryptedVLESS {
			flags = append(flags, "VLESS-ENC")
		}
		if l.CDN {
			flags = append(flags, "CDN")
		}
		if len(flags) > 0 {
			fmt.Fprintf(&b, " [%s]", strings.Join(flags, " "))
		}
	}
	if p.Truncated {
		fmt.Fprintf(&b, "\n… preview limited to %d links", len(p.Links))
	}
	if msg.url != "" {
		m.confirmChoice("Preview subscription", b.String(),
			[]choice{{label: "Add and fetch links"}, {label: "Add without fetching"}, {label: "Cancel"}},
			func(m *Menu, idx int) tea.Cmd {
				if idx == 2 {
					return nil
				}
				return m.addSubscriptionConfirmed("", msg.url, idx == 0)
			})
		return
	}
	m.confirmChoice("Preview subscription dump", b.String(),
		[]choice{{label: "Import these links"}, {label: "Cancel"}},
		func(m *Menu, idx int) tea.Cmd {
			if idx != 0 {
				return nil
			}
			text := msg.text
			return m.runAction("Import subscription dump", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
				res, err := svc.ImportSubscriptionText(ctx, "", text)
				if err != nil {
					return app.ActionResult{}, err
				}
				return app.ActionResult{Message: importResultMessage(res)}, nil
			})
		})
}

func (m *Menu) addSubscriptionConfirmed(group, rawURL string, fetch bool) tea.Cmd {
	if m.svc == nil || m.busy != "" {
		return nil
	}
	m.busy = "Adding subscription"
	m.busySince = time.Now()
	svc := m.svc
	return tea.Batch(func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
		defer cancel()
		sub, err := svc.AddSubscription(ctx, group, rawURL)
		if err != nil {
			return doneMsg{label: "Add subscription", err: err}
		}
		if !fetch {
			return doneMsg{label: "Add subscription", result: app.ActionResult{
				Message: fmt.Sprintf("Subscription added to group %q. Press r to fetch links.", sub.Group),
			}}
		}
		refreshed, err := svc.RefreshSubscription(ctx, sub.Group, sub.URL, nil)
		if err != nil {
			return subAddedMsg{group: sub.Group, err: err}
		}
		return subAddedMsg{group: refreshed.Group, links: refreshed.LinkCount}
	}, spinnerTick())
}

func (m *Menu) refreshSubscription(s app.Subscription) tea.Cmd {
	if m.svc == nil {
		return nil
	}
	if m.busy != "" {
		return nil
	}
	m.busy = "Refreshing " + s.Group
	m.busySince = time.Now()
	svc := m.svc
	return tea.Batch(func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 130*time.Second)
		defer cancel()
		sub, err := svc.RefreshSubscription(ctx, s.Group, s.URL, nil)
		if err != nil {
			return doneMsg{label: "Refresh", err: err}
		}
		return doneMsg{label: "Refresh", result: app.ActionResult{Message: fmt.Sprintf("%s: %d links", sub.Group, sub.LinkCount)}}
	}, spinnerTick())
}

func (m *Menu) refreshAll(subs []app.Subscription) tea.Cmd {
	if m.svc == nil {
		return nil
	}
	m.busy = "Refreshing all subscriptions"
	m.busySince = time.Now()
	svc := m.svc
	return tea.Batch(func() tea.Msg {
		var ok, failed int
		var lastErr error
		for _, s := range subs {
			ctx, cancel := context.WithTimeout(context.Background(), 130*time.Second)
			_, err := svc.RefreshSubscription(ctx, s.Group, s.URL, nil)
			cancel()
			if err != nil {
				failed++
				lastErr = err
			} else {
				ok++
			}
		}
		if failed > 0 {
			return doneMsg{label: "Refresh all", err: fmt.Errorf("%d refreshed, %d failed; last: %v", ok, failed, lastErr)}
		}
		return doneMsg{label: "Refresh all", result: app.ActionResult{Message: fmt.Sprintf("Refreshed %d subscription(s).", ok)}}
	}, spinnerTick())
}

// --- gateway ---

func (m *Menu) gatewayView(h int) string {
	const labelW = 16
	state, stateStyle := m.displayState()
	mode := "proxy only"
	if m.status.GatewayMode {
		mode = "transparent TUN"
	}
	rows := []string{
		"",
		" " + stateStyle.Bold(true).Render("● "+state) + styleMuted.Render(fmt.Sprintf("   pid %d   uptime %s", m.status.PID, formatDuration(time.Duration(m.status.UptimeSec)*time.Second))),
		"",
		kv("Gateway mode", mode, labelW),
		kv("Running link", orDash(m.status.ActiveLink), labelW),
		kv("Selected link", orDash(m.status.SelectedLink), labelW),
		kv("Engine", orDash(m.status.Engine), labelW),
		kv("DNS mode", orDash(m.status.DNSMode), labelW),
	}
	rows = append(rows, m.kvRow("Listeners", fmt.Sprintf("api :%d  socks :%d  dns :%d", m.status.APIPort, m.status.SOCKSPort, m.status.DNSPort), labelW)...)
	rows = append(rows, m.kvRow("Recovery", fmt.Sprintf("%d engine restart · %d data-path · %d retries", m.status.Restarts, m.status.TunRestarts, m.status.Recovery), labelW)...)
	if row := m.healthProofRow(labelW); len(row) > 0 {
		rows = append(rows, row...)
	}
	if m.status.FallbackFrom != "" {
		rows = append(rows, m.kvLines("Fallback from", m.status.FallbackFrom, labelW, lipgloss.NewStyle())...)
		if m.status.FallbackError != "" {
			rows = append(rows, m.kvLines("Fallback cause", m.status.FallbackError, labelW, styleWarn)...)
		}
	}
	if m.status.LastError != "" {
		rows = append(rows, m.kvLines("Last error", m.status.LastError, labelW, styleErr)...)
	}
	rows = append(rows, "")
	rows = append(rows, mutedLines("Changing the active connection requires a gateway restart. 'a' in Connections only saves the selection; 'c' applies it now.", m.contentWidth())...)
	rows = append(rows, "")
	rows = append(rows, " "+styleTitle.Render("Engines"))
	if m.engineErr != "" {
		rows = append(rows, m.indentedLines(m.engineErr, 1, styleErr)...)
	}
	if len(m.engines) == 0 {
		rows = append(rows, m.indentedLines("No engine information available (gateway not running).", 1, styleMuted)...)
	}
	for _, e := range m.engines {
		ready := styleMuted.Render("missing")
		if e.Ready {
			ready = styleOK.Render("ready")
		}
		version := e.Version
		if version == "" {
			version = "unknown"
		}
		if m.contentWidth() < 60 {
			// The columns cannot fit side by side; keep every value readable
			// instead of clipping the version.
			state := "missing"
			if e.Ready {
				state = "ready"
			}
			rows = append(rows, m.kvRow(e.Name, version+" · "+e.Source+" · "+state, 12)...)
			continue
		}
		rows = append(rows, " "+styleAccent.Render(padTo(e.Name, 12))+" "+padTo(truncatePlain(version, 20), 20)+" "+padTo(e.Source, 10)+" "+ready)
	}
	rows = append(rows, "")
	if !m.status.Running {
		rows = append(rows, " "+styleWarn.Render("Gateway is not running.")+" "+styleMuted.Render("Start it with: sudo bypath run"))
	}
	return m.layoutRows(rows, h)
}

func (m *Menu) gatewayKey(key string) tea.Cmd {
	switch key {
	case "c":
		if m.status.ActiveID == "" {
			m.setNotice(true, "No active connection selected. Choose one in Connections (2).")
			return nil
		}
		id := m.status.ActiveID
		m.confirmAction("Connect through "+truncatePlain(m.status.ActiveLink, 40)+"?",
			"The gateway restarts its tunnel stack to apply the connection.",
			"Connect", false, func(m *Menu) tea.Cmd {
				return m.runAction("Connect", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
					return svc.Connect(ctx, id)
				})
			})
	case "d":
		m.confirmAction("Disconnect the tunnel?", "This stops the active tunnel and its routing. The management service stays running so you can reconnect.",
			"Disconnect", true, func(m *Menu) tea.Cmd {
				return m.runAction("Disconnect", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
					return svc.Disconnect(ctx)
				})
			})
	case "R":
		m.confirmAction("Restart the tunnel?", "Traffic through the gateway is interrupted while the tunnel restarts. The API process stays up.",
			"Restart", false, func(m *Menu) tea.Cmd {
				return m.runAction("Restart", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
					return svc.Restart(ctx)
				})
			})
	}
	return nil
}

// --- DNS ---

func (m *Menu) dnsView(h int) string {
	w := m.contentWidth()
	mode := m.settings.DNSMode
	if mode == "" {
		mode = m.status.DNSMode
	}
	if mode == "" {
		mode = "strict"
	}
	upstreams := "—"
	if len(m.settings.DNSUpstream) > 0 {
		upstreams = strings.Join(m.settings.DNSUpstream, ", ")
	}
	explain := "Strict: DNS for client traffic is resolved through the tunnel. If the tunnel is down, resolution fails rather than leaking to the local resolver."
	if mode == "local" {
		explain = "Local: DNS follows the host resolver. This is faster but not leak-protected; use strict for the transparent gateway."
	}
	rows := []string{
		"",
		" " + styleTitle.Render("DNS configuration"),
		"",
	}
	for _, row := range [][2]string{
		{"Mode", mode},
		{"Upstreams", upstreams},
		{"Local DNS port", strconv.Itoa(m.status.DNSPort)},
		{"Gateway mode", onOff(m.status.GatewayMode, "transparent TUN", "proxy only")},
		{"LAN interface", orDash(m.status.LANInterface)},
	} {
		rows = append(rows, m.kvRow(row[0], row[1], 16)...)
	}
	rows = append(rows, "")
	rows = append(rows, mutedLines(explain, w)...)
	rows = append(rows,
		"",
		"",
		" "+styleTitle.Render("Recent DNS activity (runtime log)"),
	)
	dnsLines := m.dnsLogLines(8)
	if len(dnsLines) == 0 {
		rows = append(rows, " "+styleMuted.Render("No DNS events in the recent log buffer."))
	}
	for _, entry := range dnsLines {
		head := " " + styleMuted.Render(entry.Time) + "  "
		indent := strings.Repeat(" ", lipgloss.Width(entry.Time)+3)
		for i, line := range wrapMessage(entry.Message, maxInt(10, w-1-lipgloss.Width(entry.Time)-2)) {
			if i == 0 {
				rows = append(rows, head+line)
				continue
			}
			rows = append(rows, indent+line)
		}
	}
	if m.logErr != "" {
		rows = append(rows, m.indentedLines(m.logErr, 2, styleErr)...)
	}
	return m.layoutRows(rows, h)
}

func (m *Menu) dnsLogLines(limit int) []app.LogEntry {
	var out []app.LogEntry
	for i := len(m.logs) - 1; i >= 0 && len(out) < limit; i-- {
		msg := strings.ToLower(m.logs[i].Message)
		if strings.Contains(msg, "dns") {
			out = append([]app.LogEntry{m.logs[i]}, out...)
		}
	}
	return out
}

func (m *Menu) dnsKey(key string) tea.Cmd {
	switch key {
	case "m":
		mode := m.settings.DNSMode
		if mode == "" {
			mode = "strict"
		}
		idx := 0
		if mode == "local" {
			idx = 1
		}
		m.confirmChoice("DNS mode", "Strict is fail-closed and recommended for the transparent gateway. Local follows the host resolver and can leak queries outside the tunnel.",
			[]choice{{label: "Strict (through tunnel)"}, {label: "Local resolver"}, {label: "Cancel"}}, func(m *Menu, choice int) tea.Cmd {
				if choice == 2 {
					return nil
				}
				mode := "strict"
				if choice == 1 {
					mode = "local"
				}
				return m.patchSettings("DNS mode", app.SettingsPatch{DNSMode: &mode})
			})
		m.overlay.choiceIdx = idx
	case "u":
		current := strings.Join(m.settings.DNSUpstream, ", ")
		m.promptInput("DNS upstreams", "Comma-separated IP addresses", current, false, func(m *Menu, value string) tea.Cmd {
			var list []string
			for _, part := range strings.Split(value, ",") {
				part = strings.TrimSpace(part)
				if part != "" {
					list = append(list, part)
				}
			}
			if len(list) == 0 {
				m.setNotice(true, "At least one DNS upstream is required.")
				return nil
			}
			return m.patchSettings("DNS upstreams", app.SettingsPatch{DNSUpstream: &list})
		})
	}
	return nil
}

// --- settings ---

type settingRow struct {
	label string
	value string
	kind  string
}

func (m *Menu) settingRows() []settingRow {
	s := m.settings
	token := "not set"
	if s.APITokenSet {
		token = "set (hidden)"
	}
	return []settingRow{
		{"Gateway mode", onOff(s.GatewayMode, "transparent TUN", "proxy only"), "toggle-gateway"},
		{"DNS mode", orDash(s.DNSMode), "choice-dns"},
		{"DNS upstreams", strings.Join(s.DNSUpstream, ", "), "text-upstream"},
		{"Internal API bind", orDash(s.Listen), "readonly-api"},
		{"SOCKS proxy endpoint", fmt.Sprintf("%s:%d", s.SOCKSListen, s.SOCKSPort), "readonly-proxy"},
		{"Native TUN", onOff(s.NativeTUN, "native device", "userspace stack"), "toggle-tun"},
		{"Preferred engine", orDash(s.PreferredEng), "choice-engine"},
		{"Health checks", onOff(s.HealthEnabled, "enabled", "disabled"), "toggle-health"},
		{"Health URL", orDash(s.HealthURL), "text-healthurl"},
		{"Health interval", orDash(s.HealthEvery), "text-healthevery"},
		{"Isolation mode", onOff(s.Isolation, "enabled", "disabled"), "toggle-isolation"},
		{"API token", token, "secret-token"},
		{"Back up configuration", "write a non-secret JSON backup", "action-backup"},
		{"Restore configuration", "load a backup and keep config.yaml.bak", "action-restore"},
	}
}

func (m *Menu) settingsView(h int) string {
	w := m.contentWidth()
	rows := []string{""}
	rows = append(rows, mutedLines("Configuration changes are validated and written atomically. Secrets are never displayed.", w)...)
	if m.settingsErr != "" {
		rows = append(rows, m.indentedLines(m.settingsErr, 1, styleErr)...)
	}
	rows = append(rows, "")
	// The label column shrinks with the window so the value keeps a usable
	// width instead of being cut to "proxy o…". Below 56 columns the labels no
	// longer fit side by side, so each value moves under its label and an item
	// costs two rows.
	labelW := minInt(26, maxInt(10, w/3))
	stacked := labelW < 16
	visible := h - len(rows) - 2
	if stacked {
		visible /= 2
	}
	if visible < 3 {
		visible = 3
	}
	if m.settingsCursor < m.settingsOffset {
		m.settingsOffset = m.settingsCursor
	}
	if m.settingsCursor >= m.settingsOffset+visible {
		m.settingsOffset = m.settingsCursor - visible + 1
	}
	list := m.settingRows()
	end := minInt(len(list), m.settingsOffset+visible)
	for i := m.settingsOffset; i < end; i++ {
		row := list[i]
		if stacked {
			label := truncatePlain(row.label, maxInt(10, w-2))
			line := "  " + styleLabel.Render(label)
			if i == m.settingsCursor {
				line = styleActive.Render("  " + padTo(label, w-3) + " ")
			}
			rows = append(rows, line)
			rows = append(rows, m.indentedLines(orDash(row.value), 4, styleMuted)...)
			continue
		}
		label := padTo(truncatePlain(row.label, labelW), labelW)
		value := truncatePlain(row.value, maxInt(8, w-labelW-4))
		line := " " + styleLabel.Render(label) + " " + value
		if i == m.settingsCursor {
			line = styleActive.Render(" " + padTo(label+" "+value, w-2) + " ")
		}
		rows = append(rows, line)
	}
	rows = append(rows, "")
	return m.layoutRows(rows, h)
}

// settingsOffset is kept in Menu through this field declared below.
func (m *Menu) settingsKey(k tea.KeyMsg, key string) tea.Cmd {
	switch key {
	case "up", "k":
		m.settingsCursor--
		m.clampSettingsCursor()
	case "down", "j":
		m.settingsCursor++
		m.clampSettingsCursor()
	case "enter":
		return m.editSetting(m.settingsCursor)
	}
	return nil
}

func (m *Menu) clampSettingsCursor() {
	m.settingsCursor = clampInt(m.settingsCursor, 0, len(m.settingRows())-1)
	if m.settingsOffset > m.settingsCursor {
		m.settingsOffset = m.settingsCursor
	}
	if m.settingsOffset < 0 {
		m.settingsOffset = 0
	}
}

func (m *Menu) editSetting(idx int) tea.Cmd {
	list := m.settingRows()
	if idx < 0 || idx >= len(list) {
		return nil
	}
	row := list[idx]
	s := m.settings
	switch row.kind {
	case "toggle-gateway":
		target := !s.GatewayMode
		m.confirmAction("Gateway mode",
			"Transparent TUN routes LAN client traffic through the tunnel. Proxy-only leaves host routing untouched.",
			onOff(target, "Enable transparent TUN", "Disable transparent TUN"), true, func(m *Menu) tea.Cmd {
				return m.patchSettings("Gateway mode", app.SettingsPatch{GatewayMode: &target})
			})
	case "choice-dns":
		m.dnsKey("m")
	case "text-upstream":
		m.dnsKey("u")
	case "readonly-api":
		m.setNotice(false, "Internal API access is separate from the proxy and the HTTPS panel. Proxy changes do not alter management access.")
	case "readonly-proxy":
		m.setNotice(false, "Proxy listener changes require staged configuration and a supervised service restart in Proxy Listening/Access.")
	case "toggle-tun":
		target := !s.NativeTUN
		m.confirmAction("Native TUN", "Use the kernel TUN device. Disabling falls back to the userspace stack and needs a tunnel restart.",
			onOff(target, "Enable native TUN", "Use userspace stack"), false, func(m *Menu) tea.Cmd {
				return m.patchSettings("Native TUN", app.SettingsPatch{NativeTUN: &target})
			})
	case "choice-engine":
		m.confirmChoice("Preferred engine", "Auto lets the profile decide. Forcing an engine affects every new tunnel.",
			[]choice{{label: "Auto"}, {label: "sing-box"}, {label: "xray"}, {label: "Cancel"}}, func(m *Menu, choice int) tea.Cmd {
				if choice == 3 {
					return nil
				}
				name := []string{"", "sing-box", "xray"}[choice]
				return m.patchSettings("Preferred engine", app.SettingsPatch{PreferredEng: &name})
			})
	case "toggle-health":
		target := !s.HealthEnabled
		return m.patchSettings("Health checks", app.SettingsPatch{HealthEnabled: &target})
	case "text-healthurl":
		m.promptInput("Health check URL", "https://…", s.HealthURL, false, func(m *Menu, value string) tea.Cmd {
			value = strings.TrimSpace(value)
			return m.patchSettings("Health URL", app.SettingsPatch{HealthURL: &value})
		})
	case "text-healthevery":
		m.promptInput("Health interval", "e.g. 30s", orDash(s.HealthEvery), false, func(m *Menu, value string) tea.Cmd {
			value = strings.TrimSpace(value)
			return m.patchSettings("Health interval", app.SettingsPatch{HealthEvery: &value})
		})
	case "toggle-isolation":
		target := !s.Isolation
		m.confirmAction("Isolation mode", "Runs each chain hop in its own network namespace. Requires kernel support and a tunnel restart.",
			onOff(target, "Enable isolation", "Disable isolation"), true, func(m *Menu) tea.Cmd {
				return m.patchSettings("Isolation mode", app.SettingsPatch{Isolation: &target})
			})
	case "secret-token":
		m.promptInput("API token", "New token (empty disables TCP management on a privileged daemon)", "", true, func(m *Menu, value string) tea.Cmd {
			value = strings.TrimSpace(value)
			if value == "" {
				m.confirmAction("Clear the API token?", "A privileged daemon refuses TCP API access without a token. The permissioned control socket and authenticated web panel remain available.",
					"Clear token", true, func(m *Menu) tea.Cmd {
						return m.patchSettings("API token", app.SettingsPatch{APIToken: &value})
					})
				return nil
			}
			return m.patchSettings("API token", app.SettingsPatch{APIToken: &value})
		})
	case "action-backup":
		m.backupFlow()
	case "action-restore":
		m.restoreFlow()
	}
	return nil
}

func (m *Menu) patchSettings(label string, patch app.SettingsPatch) tea.Cmd {
	return m.runAction(label, func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
		change, err := svc.UpdateSettings(ctx, patch)
		if err != nil {
			return app.ActionResult{}, err
		}
		msg := "Settings saved."
		if change.RestartRequired {
			msg = "Settings saved. Restart the gateway (Gateway section, R) to apply the tunnel-related change."
		}
		return app.ActionResult{Message: msg, RestartRequired: change.RestartRequired}, nil
	})
}

func (m *Menu) backupFlow() tea.Cmd {
	defaultPath := filepath.Join(mustGetwd(), "bypath-backup-"+time.Now().Format("20060102-150405")+".json")
	m.promptInput("Back up configuration", "Output file (configuration only; no credentials or tokens)", defaultPath, false, func(m *Menu, path string) tea.Cmd {
		path = expandHome(strings.TrimSpace(path))
		if path == "" {
			m.setNotice(true, "A file path is required.")
			return nil
		}
		if m.svc == nil || m.busy != "" {
			return nil
		}
		m.busy = "Writing backup"
		svc := m.svc
		return tea.Batch(func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			backup, err := svc.Backup(ctx, false)
			if err != nil {
				return doneMsg{label: "Backup", err: err}
			}
			data, err := jsonMarshal(backup)
			if err != nil {
				return doneMsg{label: "Backup", err: err}
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				return doneMsg{label: "Backup", err: err}
			}
			return doneMsg{label: "Backup", result: app.ActionResult{Message: "Backup written to " + path}}
		}, spinnerTick())
	})
	return nil
}

func (m *Menu) restoreFlow() tea.Cmd {
	m.pickFile("Restore configuration (.json)", mustGetwd(), ".json", func(m *Menu, path string) tea.Cmd {
		data, err := os.ReadFile(path)
		if err != nil {
			m.setNotice(true, "Cannot read backup: %s", err)
			return nil
		}
		if len(data) > 1<<20 {
			m.setNotice(true, "Backup file is larger than 1 MiB.")
			return nil
		}
		m.confirmAction("Restore this configuration?",
			"File: "+path+"\n\nThe current configuration is replaced and saved as config.yaml.bak first. Connections and credentials are not part of a backup.",
			"Restore", true, func(m *Menu) tea.Cmd {
				return m.runAction("Restore", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
					if err := svc.Restore(ctx, data); err != nil {
						return app.ActionResult{}, err
					}
					return app.ActionResult{Message: "Configuration restored. Restart the gateway to apply tunnel settings."}, nil
				})
			})
		return nil
	})
	return nil
}

// --- logs ---

func (m *Menu) filteredLogs() []app.LogEntry {
	if m.logFilter == "" {
		return m.logs
	}
	needle := strings.ToLower(m.logFilter)
	out := make([]app.LogEntry, 0, len(m.logs))
	for _, e := range m.logs {
		if strings.Contains(strings.ToLower(e.Message), needle) {
			out = append(out, e)
		}
	}
	return out
}

// wrapMessage wraps a log message while preserving its own line breaks: an
// engine error is often a heading plus its cause, and collapsing them into one
// paragraph destroys the structure the operator needs.
func wrapMessage(message string, width int) []string {
	var out []string
	for _, line := range strings.Split(message, "\n") {
		line = strings.TrimRight(line, " \t")
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, wrapPlain(line, width)...)
	}
	if len(out) == 0 {
		out = []string{""}
	}
	return out
}

func (m *Menu) logsView(h int) string {
	w := m.contentWidth()
	entries := m.filteredLogs()
	filter := m.logFilter
	if filter == "" {
		filter = "—"
	}
	follow := "off"
	if m.followLogs {
		follow = "on"
		m.logCursor = maxInt(0, len(entries)-1)
	}
	header := " " + styleMuted.Render(fmt.Sprintf("%d/%d entries · filter: %s · follow: %s", len(entries), len(m.logs), filter, follow))
	rows := []string{"", header}
	if m.logErr != "" {
		rows = append(rows, " "+styleErr.Render(truncatePlain(m.logErr, w-2)))
	}
	visible := h - 3
	if visible < 3 {
		visible = 3
	}
	if m.logCursor < m.logOffset {
		m.logOffset = m.logCursor
	}
	if m.logCursor >= m.logOffset+visible {
		m.logOffset = m.logCursor - visible + 1
	}
	end := minInt(len(entries), m.logOffset+visible)
	for i := m.logOffset; i < end; i++ {
		e := entries[i]
		levelName, levelStyle := "info ", styleMuted
		switch e.Level {
		case "warn":
			levelName, levelStyle = "warn ", styleWarn
		case "error":
			levelName, levelStyle = "error", styleErr
		}
		ts := e.Time
		if len(ts) >= 19 {
			ts = ts[11:19]
		}
		// On a narrow window the timestamp gives way to the message: the cause
		// of a failure is worth more than the second it happened.
		showTime := w >= 56
		timeCol := 0
		if showTime {
			timeCol = len(ts) + 1
		}
		levelCol := len(levelName) + 1
		indent := " " + strings.Repeat(" ", timeCol+levelCol)

		// Multi-line and long messages wrap under their own column instead of
		// being cut: a stack trace or a nested engine error is unreadable when
		// every line after the first disappears.
		msgWidth := maxInt(10, w-1-timeCol-levelCol)
		message := strings.ReplaceAll(e.Message, "\r", "")
		parts := wrapMessage(message, msgWidth)
		if len(parts) > 4 {
			parts = parts[:4]
			parts[3] = truncatePlain(parts[3]+" …", msgWidth)
		}
		for li, part := range parts {
			plainPrefix := indent
			if li == 0 {
				plainPrefix = " " + levelName + " "
				if showTime {
					plainPrefix = " " + ts + " " + levelName + " "
				}
			}
			if i == m.logCursor {
				rows = append(rows, styleActive.Render(padTo(plainPrefix+part, w-1)))
				continue
			}
			switch {
			case li > 0:
				rows = append(rows, indent+part)
			case showTime:
				rows = append(rows, " "+styleMuted.Render(ts)+" "+levelStyle.Render(levelName)+" "+part)
			default:
				rows = append(rows, " "+levelStyle.Render(levelName)+" "+part)
			}
		}
	}
	if len(entries) == 0 {
		rows = append(rows, "", " "+styleMuted.Render("No log entries match."))
	}
	return m.layoutRows(rows, h)
}

func (m *Menu) logsKey(k tea.KeyMsg, key string) tea.Cmd {
	entries := m.filteredLogs()
	switch key {
	case "up", "k":
		m.followLogs = false
		m.logCursor = clampInt(m.logCursor-1, 0, maxInt(0, len(entries)-1))
	case "down", "j":
		m.logCursor = clampInt(m.logCursor+1, 0, maxInt(0, len(entries)-1))
		if m.logCursor == len(entries)-1 {
			m.followLogs = true
		}
	case "pgup":
		m.followLogs = false
		m.logCursor = clampInt(m.logCursor-15, 0, maxInt(0, len(entries)-1))
	case "pgdown":
		m.logCursor = clampInt(m.logCursor+15, 0, maxInt(0, len(entries)-1))
	case "home", "g":
		m.followLogs = false
		m.logCursor = 0
	case "end", "G":
		m.followLogs = true
		m.logCursor = maxInt(0, len(entries)-1)
	case "f":
		m.followLogs = !m.followLogs
		if m.followLogs {
			m.logCursor = maxInt(0, len(entries)-1)
		}
	case "/":
		m.promptInput("Filter logs", "Substring (case-insensitive)", m.logFilter, false, func(m *Menu, value string) tea.Cmd {
			m.logFilter = strings.TrimSpace(value)
			m.logCursor = maxInt(0, len(m.filteredLogs())-1)
			return nil
		})
	case "c":
		m.logFilter = ""
	case "e":
		m.exportFlow()
	}
	return nil
}

func (m *Menu) exportFlow() tea.Cmd {
	defaultPath := filepath.Join(mustGetwd(), "bypath-logs-"+time.Now().Format("20060102-150405")+".log")
	m.promptInput("Export logs", "File path (entries are already redacted)", defaultPath, false, func(m *Menu, path string) tea.Cmd {
		path = expandHome(strings.TrimSpace(path))
		if path == "" {
			m.setNotice(true, "A file path is required.")
			return nil
		}
		entries := m.filteredLogs()
		if len(entries) == 0 {
			m.setNotice(true, "There are no entries to export.")
			return nil
		}
		if m.busy != "" {
			return nil
		}
		m.busy = "Exporting logs"
		return tea.Batch(func() tea.Msg {
			var b strings.Builder
			for _, e := range entries {
				fmt.Fprintf(&b, "%s %-5s %s\n", e.Time, e.Level, e.Message)
			}
			if err := os.WriteFile(path, []byte(b.String()), 0600); err != nil {
				return doneMsg{label: "Export logs", err: err}
			}
			return doneMsg{label: "Export logs", result: app.ActionResult{Message: fmt.Sprintf("Exported %d entries to %s", len(entries), path)}}
		}, spinnerTick())
	})
	return nil
}

// --- about ---

// aboutPaths is a seam for layout tests, whose captured frames must not embed
// the machine-specific runtime directory of the test process.
var aboutPaths = paths.Get

func (m *Menu) aboutView(h int) string {
	p := aboutPaths()
	const labelW = 12
	rows := []string{
		"",
		" " + styleTitle.Render("Bypath"),
		"",
	}
	rows = append(rows, m.kvRow("Version", orDash(m.status.Version), labelW)...)
	rows = append(rows, m.kvRow("Variant", strings.ToUpper(orDash(m.status.Variant))+"  (Full embeds engines; Lite manages them)", labelW)...)
	rows = append(rows, m.kvRow("Commit", orDash(m.status.Commit), labelW)...)
	rows = append(rows, m.kvRow("Build date", orDash(m.status.BuildDate), labelW)...)
	rows = append(rows, "", " "+styleTitle.Render("Installation"), "")
	rows = append(rows, m.kvRow("Config", p.ConfigFile, labelW)...)
	rows = append(rows, m.kvRow("Profiles", p.ProfileDir, labelW)...)
	rows = append(rows, m.kvRow("Runtime", p.TmpDir, labelW)...)
	rows = append(rows, m.kvRow("Logs", p.LogDir, labelW)...)
	rows = append(rows, m.kvRow("API listen", fmt.Sprintf("%s:%d", orDash(m.status.LANInterface), m.status.APIPort), labelW)...)
	rows = append(rows, "", " "+styleTitle.Render("Terminal keys"), "")
	rows = append(rows, mutedLines("1-9 jump to a section · tab/shift+tab cycle · esc back · q quit · ctrl+c quit anywhere", m.contentWidth())...)
	rows = append(rows, mutedLines("Lists: ↑/↓ move, enter open. Destructive actions always ask for confirmation.", m.contentWidth())...)
	return m.layoutRows(rows, h)
}

// --- misc ---

func onOff(v bool, yes, no string) string {
	if v {
		return yes
	}
	return no
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func jsonMarshal(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

func mustGetwd() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	return dir
}

func expandHome(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
