package tui

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/liberoute/bypath/internal/app"
)

// Routing is read-only in the terminal: it explains the effective policy the
// tunnel runs, and points at the panel or the CLI for edits. A second place to
// write routing rules is a second place to get them wrong.

type routingState struct {
	overview *app.RoutingOverview
	err      string
	gen      int
	filter   string
	cursor   int
	offset   int
}

type routingMsg struct {
	gen      int
	overview app.RoutingOverview
	err      error
}

func (m *Menu) loadRouting() tea.Cmd {
	if m.svc == nil {
		return nil
	}
	m.routing.gen++
	gen := m.routing.gen
	svc := m.svc
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
		defer cancel()
		overview, err := svc.RoutingOverview(ctx)
		return routingMsg{gen: gen, overview: overview, err: err}
	}
}

func (m *Menu) handleRouting(msg routingMsg) tea.Cmd {
	if msg.gen != m.routing.gen {
		return nil
	}
	if msg.err != nil {
		m.routing.err = friendlyError(msg.err)
		return nil
	}
	m.routing.err = ""
	m.routing.overview = &msg.overview
	m.clampRoutingCursor()
	return nil
}

func (m *Menu) routingRules() []app.RoutingRuleView {
	overview := m.routing.overview
	if overview == nil {
		return nil
	}
	filter := strings.ToLower(strings.TrimSpace(m.routing.filter))
	if filter == "" {
		return overview.Rules
	}
	out := make([]app.RoutingRuleView, 0, len(overview.Rules))
	for _, rule := range overview.Rules {
		haystack := strings.ToLower(strings.Join([]string{rule.Effect, rule.Match, rule.Source, rule.Scope, rule.Note}, " "))
		if strings.Contains(haystack, filter) {
			out = append(out, rule)
		}
	}
	return out
}

func (m *Menu) clampRoutingCursor() {
	rules := m.routingRules()
	m.routing.cursor = clampInt(m.routing.cursor, 0, maxInt(0, len(rules)-1))
}

func (m *Menu) routingView(h int) string {
	w := m.contentWidth()
	rows := []string{""}
	overview := m.routing.overview
	if m.routing.err != "" {
		rows = append(rows, m.indentedLines(m.routing.err, 1, styleErr)...)
	}
	if overview == nil {
		if m.routing.err == "" {
			rows = append(rows, " "+styleMuted.Render("loading the effective policy…"))
		}
		return m.layoutRows(rows, h)
	}

	mode := "Rules"
	if overview.Mode != "rules" {
		mode = "Legacy whitelist"
	}
	rows = append(rows, " "+styleTitle.Render("Effective routing policy")+" "+
		styleMuted.Render("read-only here · edit in the web panel or the CLI"))
	rows = append(rows, m.kvRow("Mode", mode+" · "+orDash(overview.Engine), 13)...)
	rows = append(rows, m.kvRow("Default", strings.ToUpper(orDash(overview.DefaultOutbound))+" · everything not matched above", 13)...)
	rows = append(rows, m.kvRow("DNS", orDash(overview.DNSMode)+" · "+onOff(overview.GatewayConnected, "gateway connected", "gateway not connected"), 13)...)
	rows = append(rows, m.kvRow("Revision", orDash(overview.Revision)+fmt.Sprintf(" · %d effective rule(s)", len(overview.Rules)), 13)...)
	if len(overview.Warnings) > 0 {
		rows = append(rows, "")
		for _, warning := range overview.Warnings {
			rows = append(rows, m.indentedLines("• "+warning, 1, styleWarn)...)
		}
	}

	filter := m.routing.filter
	if filter == "" {
		filter = "—"
	}
	rules := m.routingRules()
	rows = append(rows, "")
	rows = append(rows, mutedLines(fmt.Sprintf("filter: %s · %d of %d rule(s) · / filter · c clear", filter, len(rules), len(overview.Rules)), w)...)
	if len(rules) == 0 {
		rows = append(rows, "")
		rows = append(rows, mutedLines("No effective rule matches this filter.", w)...)
		return m.layoutRows(rows, h)
	}

	widths := m.routingWidths(w)
	header := " " + padTo("#", 2) + " " + padTo("EFFECT", 8) + " " + padTo("WHAT IT MATCHES", widths.match)
	if widths.source > 0 {
		header += " " + "SOURCE"
	}
	rows = append(rows, styleMuted.Render(clipLine(header, w-1)))

	visible := h - len(rows) - 2
	if visible < 3 {
		visible = 3
	}
	m.clampRoutingCursor()
	if m.routing.cursor < m.routing.offset {
		m.routing.offset = m.routing.cursor
	}
	if m.routing.cursor >= m.routing.offset+visible {
		m.routing.offset = m.routing.cursor - visible + 1
	}
	if m.routing.offset < 0 {
		m.routing.offset = 0
	}
	end := minInt(len(rules), m.routing.offset+visible)
	for i := m.routing.offset; i < end; i++ {
		line := m.routingRuleLine(rules[i], widths)
		if i == m.routing.cursor {
			rows = append(rows, styleActive.Render(" "+padTo(line, w-2)+" "))
			continue
		}
		rows = append(rows, " "+line)
	}
	if end < len(rules) {
		rows = append(rows, " "+styleMuted.Render(fmt.Sprintf("… %d more", len(rules)-end)))
	}

	assets := overview.Assets
	geo := fmt.Sprintf("geoip: %s · geosite: %s", assetState(assets.GeoIPPresent), assetState(assets.GeoSitePresent))
	rows = append(rows, "")
	rows = append(rows, mutedLines(geo, w)...)
	legacy := "not present"
	if overview.Legacy.Present {
		legacy = "present, in use"
		if overview.Legacy.Ignored {
			legacy = "present, ignored"
		}
	}
	line := fmt.Sprintf("legacy whitelist: %s · local DNS groups: %d", legacy, len(overview.LocalDNS))
	rows = append(rows, mutedLines(line, w)...)
	return m.layoutRows(rows, h)
}

type routingTableWidths struct {
	match  int
	source int
}

func (m *Menu) routingWidths(w int) routingTableWidths {
	// 1 leading + 2 position + 1 + 8 effect + 1 before the match column.
	fixed := 13
	widths := routingTableWidths{}
	if w >= 76 {
		widths.source = 22
		fixed++ // separating space
	}
	widths.match = maxInt(12, w-fixed-widths.source)
	return widths
}

func (m *Menu) routingRuleLine(rule app.RoutingRuleView, widths routingTableWidths) string {
	effect := strings.ToUpper(orDash(rule.Effect))
	effectStyle := styleOK
	switch effect {
	case "DIRECT":
		effectStyle = styleAccent
	case "BLOCK", "DENY", "REJECT":
		effectStyle = styleErr
	case "INACTIVE":
		effectStyle = styleMuted
	}
	match := truncatePlain(orDash(rule.Match), widths.match)
	line := padTo(fmt.Sprintf("%d", rule.Position), 2) + " " + effectStyle.Render(padTo(effect, 8)) + " " + padTo(match, widths.match)
	if widths.source > 0 {
		source := rule.Source
		if source == "" {
			source = rule.Scope
		}
		line += " " + styleMuted.Render(truncatePlain(orDash(source), widths.source))
	}
	return line
}

func assetState(present bool) string {
	if present {
		return "installed"
	}
	return "missing"
}

func (m *Menu) routingKey(k tea.KeyMsg, key string) tea.Cmd {
	rules := m.routingRules()
	switch key {
	case "up", "k":
		m.routing.cursor = clampInt(m.routing.cursor-1, 0, maxInt(0, len(rules)-1))
	case "down", "j":
		m.routing.cursor = clampInt(m.routing.cursor+1, 0, maxInt(0, len(rules)-1))
	case "pgup":
		m.routing.cursor = clampInt(m.routing.cursor-10, 0, maxInt(0, len(rules)-1))
	case "pgdown":
		m.routing.cursor = clampInt(m.routing.cursor+10, 0, maxInt(0, len(rules)-1))
	case "home":
		m.routing.cursor = 0
	case "end":
		m.routing.cursor = maxInt(0, len(rules)-1)
	case "enter":
		if m.routing.cursor < len(rules) {
			m.showInfo("Routing rule", routingRuleText(rules[m.routing.cursor]))
		}
	case "/":
		m.promptInput("Filter routing rules", "Effect, match, source or note", m.routing.filter, false, func(m *Menu, value string) tea.Cmd {
			m.routing.filter = strings.TrimSpace(value)
			m.routing.cursor, m.routing.offset = 0, 0
			return nil
		})
	case "c":
		m.routing.filter = ""
		m.routing.cursor, m.routing.offset = 0, 0
	case "r":
		return m.loadRouting()
	}
	return nil
}

func routingRuleText(rule app.RoutingRuleView) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Position: %d\n", rule.Position)
	fmt.Fprintf(&b, "Effect:   %s\n", strings.ToUpper(orDash(rule.Effect)))
	fmt.Fprintf(&b, "Matches:  %s\n", orDash(rule.Match))
	fmt.Fprintf(&b, "Source:   %s\n", orDash(rule.Source))
	if rule.Scope != "" && rule.Scope != rule.Source {
		fmt.Fprintf(&b, "Scope:    %s\n", rule.Scope)
	}
	fmt.Fprintf(&b, "Kind:     %s\n", orDash(rule.Kind))
	fmt.Fprintf(&b, "Outbound: %s\n", orDash(rule.Outbound))
	if rule.Note != "" {
		fmt.Fprintf(&b, "Note:     %s\n", rule.Note)
	}
	if rule.Skipped {
		b.WriteString("\nThis rule is skipped by the engine; traffic falls through to the rules below it.\n")
	}
	return b.String()
}
