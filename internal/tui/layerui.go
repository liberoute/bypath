package tui

import (
	"context"
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/layer"
)

// layerUngrouped is the filter sentinel for connections that belong to no
// organisation group. It can never collide with a real group id ("g_…").
const layerUngrouped = "__none"

type layerMsg struct {
	gen    int
	status layer.Status
	plan   *layer.MigrationPlan
	groups []layer.GroupView
	err    error
}

func (m *Menu) loadLayer() tea.Cmd {
	if m.svc == nil {
		return nil
	}
	m.layerGen++
	gen := m.layerGen
	svc := m.svc
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
		defer cancel()
		st, err := svc.LayerStatus(ctx)
		if err != nil {
			return layerMsg{gen: gen, err: err}
		}
		msg := layerMsg{gen: gen, status: st}
		if !st.Migrated {
			if plan, perr := svc.LayerPlan(ctx); perr == nil {
				msg.plan = &plan
			}
			return msg
		}
		groups, gerr := svc.LayerGroups(ctx)
		if gerr != nil {
			msg.err = gerr
			return msg
		}
		msg.groups = groups
		return msg
	}
}

func (m *Menu) handleLayer(msg layerMsg) tea.Cmd {
	if msg.gen != m.layerGen {
		return nil
	}
	m.layerErr = friendlyError(msg.err)
	m.layerStatus = msg.status
	m.layerPlan = msg.plan
	if msg.groups != nil || msg.status.Migrated {
		m.groups = msg.groups
	}
	if m.connLayerGroup != "" && m.connLayerGroup != layerUngrouped && !m.groupExists(m.connLayerGroup) {
		m.connLayerGroup = ""
	}
	if m.migrationPending && msg.plan != nil {
		m.migrationPending = false
		m.showMigrationPrompt(msg.plan)
	}
	return nil
}

func (m *Menu) groupExists(id string) bool {
	for _, g := range m.groups {
		if g.ID == id {
			return true
		}
	}
	return false
}

func (m *Menu) groupName(id string) string {
	if id == "" {
		return "Ungrouped"
	}
	for _, g := range m.groups {
		if g.ID == id {
			return g.Name
		}
	}
	return id
}

func (m *Menu) layerReady() bool {
	return m.svc != nil && m.layerStatus.Migrated
}

func (m *Menu) layerWritable() bool {
	return m.layerReady() && !m.layerStatus.ReadOnly
}

// organisationSummary is the one-line Overview answer: is organisation in use,
// and is anything degraded?
func (m *Menu) organisationSummary() string {
	if m.layerErr != "" {
		return styleWarn.Render("unavailable — " + m.layerErr)
	}
	if !m.layerStatus.Migrated {
		return styleMuted.Render("not created yet — press M in Connections")
	}
	parts := []string{fmt.Sprintf("%d group(s)", len(nonEmptyGroups(m.groups)))}
	if m.layerStatus.Hidden > 0 {
		parts = append(parts, fmt.Sprintf("%d hidden", m.layerStatus.Hidden))
	}
	if m.layerStatus.Orphaned > 0 {
		parts = append(parts, fmt.Sprintf("%d orphaned", m.layerStatus.Orphaned))
	}
	out := strings.Join(parts, " · ")
	if m.layerStatus.ReadOnly {
		out += " · " + styleWarn.Render("read-only")
	}
	return out
}

func nonEmptyGroups(groups []layer.GroupView) []layer.GroupView {
	out := make([]layer.GroupView, 0, len(groups))
	for _, g := range groups {
		if g.ID != "" {
			out = append(out, g)
		}
	}
	return out
}

// selectionBannerLines renders the reconciliation between the saved next start
// and the link actually serving. It is read-only: the only way to change the
// saved choice is "a" in Connections, and that never switches the tunnel.
func (m *Menu) selectionBannerLines() []string {
	sel := m.status.Selection
	switch sel.State {
	case "", app.SelectionOK:
		return nil
	case app.SelectionDiff:
		text := fmt.Sprintf("Serving %s · next start %s — a restart will use the saved choice.",
			orDash(sel.ServingRemark), orDash(sel.SelectedRemark))
		return m.indentedLines(text, 2, styleWarn)
	case app.SelectionDangling:
		text := sel.Message
		if text == "" {
			text = "The saved next-start connection no longer exists; the next start would be chosen unpredictably."
		}
		return m.indentedLines(text, 2, styleErr)
	case app.SelectionAuto:
		chosen := sel.SelectedRemark
		if chosen == "" {
			chosen = "a connection"
		}
		text := fmt.Sprintf("Bypath chose %s automatically; choose one to keep the next start predictable.", chosen)
		return m.indentedLines(text, 2, styleAccent)
	case app.SelectionUnset:
		text := sel.Message
		if text == "" {
			text = "Next start is not set — Bypath will choose a connection by itself."
		}
		return m.indentedLines(text, 2, styleWarn)
	default:
		text := sel.Message
		if text == "" {
			text = "The saved next start could not be reconciled with the gateway."
		}
		return m.indentedLines(text, 2, styleWarn)
	}
}

// migrationFlow opens the layer plan before anything is written. A plan is
// fetched on entry so the confirmation can state how many connections are
// affected.
func (m *Menu) migrationFlow() tea.Cmd {
	if m.svc == nil {
		return nil
	}
	if m.layerStatus.Migrated {
		m.setNotice(false, "The organisation layer already exists.")
		return nil
	}
	if m.layerPlan != nil {
		m.showMigrationPrompt(m.layerPlan)
		return nil
	}
	m.migrationPending = true
	return m.loadLayer()
}

func (m *Menu) showMigrationPrompt(plan *layer.MigrationPlan) {
	detail := fmt.Sprintf("This adds sidecar labels for %d connection(s) in %d import list(s). Links, .active and the serving tunnel are not rewritten.",
		len(plan.Entries), len(plan.Buckets))
	if len(plan.Warnings) > 0 {
		detail += "\n\n" + strings.Join(plan.Warnings, "\n")
	}
	m.confirmAction("Create the organisation layer", detail, "Create layer", false, func(m *Menu) tea.Cmd {
		return m.runAction("Create layer", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
			if _, err := svc.LayerMigrate(ctx, false); err != nil {
				return app.ActionResult{}, err
			}
			return app.ActionResult{Message: "Organisation layer created. Import lists and the next start are unchanged."}, nil
		})
	})
}

// stableID is the identity layer operations use. Before migration entries have
// no stable id, so the legacy id is the only accepted handle.
func stableID(c app.Connection) string {
	if c.StableID != "" {
		return c.StableID
	}
	return c.ID
}

func (m *Menu) createGroupFlow() tea.Cmd {
	if !m.layerWritable() {
		m.layerEditNotice()
		return nil
	}
	m.promptInput("New group", "Group name", "", false, func(m *Menu, value string) tea.Cmd {
		name := strings.TrimSpace(value)
		if name == "" {
			m.setNotice(true, "A group name is required.")
			return nil
		}
		return m.runAction("Create group", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
			g, err := svc.CreateLayerGroup(ctx, name)
			if err != nil {
				return app.ActionResult{}, err
			}
			return app.ActionResult{Message: fmt.Sprintf("Group %q created.", g.Name)}, nil
		})
	})
	return nil
}

func (m *Menu) renameGroupFlow() tea.Cmd {
	if !m.layerWritable() {
		m.layerEditNotice()
		return nil
	}
	groups := nonEmptyGroups(m.groups)
	if len(groups) == 0 {
		m.setNotice(true, "There are no groups to rename. Press N to create one.")
		return nil
	}
	choices := make([]choice, 0, len(groups)+1)
	for _, g := range groups {
		choices = append(choices, choice{label: g.Name + fmt.Sprintf(" (%d)", g.Count)})
	}
	choices = append(choices, choice{label: "Cancel"})
	m.confirmChoice("Rename which group?", "Renaming a group only changes its label. Its connections and the tunnel stay as they are.", choices,
		func(m *Menu, idx int) tea.Cmd {
			if idx >= len(groups) {
				return nil
			}
			g := groups[idx]
			m.promptInput("Rename group", "New name", g.Name, false, func(m *Menu, value string) tea.Cmd {
				name := strings.TrimSpace(value)
				if name == "" {
					m.setNotice(true, "A group name is required.")
					return nil
				}
				return m.runAction("Rename group", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
					if err := svc.RenameLayerGroup(ctx, g.ID, name); err != nil {
						return app.ActionResult{}, err
					}
					return app.ActionResult{Message: fmt.Sprintf("Group renamed to %q.", name)}, nil
				})
			})
			return nil
		})
	return nil
}

func (m *Menu) deleteGroupFlow() tea.Cmd {
	if !m.layerWritable() {
		m.layerEditNotice()
		return nil
	}
	groups := nonEmptyGroups(m.groups)
	if len(groups) == 0 {
		m.setNotice(true, "There are no groups to delete.")
		return nil
	}
	choices := make([]choice, 0, len(groups)+1)
	for _, g := range groups {
		choices = append(choices, choice{label: g.Name + fmt.Sprintf(" (%d)", g.Count)})
	}
	choices = append(choices, choice{label: "Cancel"})
	m.confirmChoice("Delete which group?", "Only the group label is removed; its connections stay in your list and keep working.", choices,
		func(m *Menu, idx int) tea.Cmd {
			if idx >= len(groups) {
				return nil
			}
			g := groups[idx]
			m.confirmAction("Delete group "+truncatePlain(g.Name, 30)+"?",
				fmt.Sprintf("%d connection(s) become ungrouped. Nothing is deleted and the tunnel is not switched.", g.Count),
				"Delete group", true, func(m *Menu) tea.Cmd {
					return m.runAction("Delete group", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
						if err := svc.DeleteLayerGroup(ctx, g.ID, false, app.DeleteOptions{}); err != nil {
							return app.ActionResult{}, err
						}
						return app.ActionResult{Message: "Group deleted. Its connections are ungrouped."}, nil
					})
				})
			return nil
		})
	return nil
}

// reorderGroup moves the active group filter one position. Reordering is a
// display preference; it is never failover order.
func (m *Menu) reorderGroup(delta int) tea.Cmd {
	if !m.layerWritable() {
		m.layerEditNotice()
		return nil
	}
	if m.connLayerGroup == "" || m.connLayerGroup == layerUngrouped {
		m.setNotice(true, "Filter one group first (g), then use [ or ] to reorder it.")
		return nil
	}
	groups := nonEmptyGroups(m.groups)
	idx := -1
	for i, g := range groups {
		if g.ID == m.connLayerGroup {
			idx = i
			break
		}
	}
	if idx < 0 {
		m.setNotice(true, "The filtered group no longer exists.")
		return nil
	}
	next := idx + delta
	if next < 0 || next >= len(groups) {
		return nil
	}
	ordered := append([]layer.GroupView(nil), groups...)
	ordered[idx], ordered[next] = ordered[next], ordered[idx]
	ids := make([]string, 0, len(ordered))
	for _, g := range ordered {
		ids = append(ids, g.ID)
	}
	return m.runAction("Reorder groups", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
		if err := svc.ReorderLayerGroups(ctx, ids); err != nil {
			return app.ActionResult{}, err
		}
		return app.ActionResult{Message: "Group order saved. It is a display order, not failover."}, nil
	})
}

func (m *Menu) layerEditNotice() {
	if m.layerErr != "" {
		m.setNotice(true, "Organisation layer unavailable: %s", m.layerErr)
		return
	}
	if !m.layerStatus.Migrated {
		m.setNotice(true, "Create the organisation layer first (M in Connections); it only adds labels.")
		return
	}
	m.setNotice(true, "The organisation layer is read-only; connection edits are disabled to protect it.")
}

func (m *Menu) moveConnectionFlow(c app.Connection) tea.Cmd {
	if !m.layerWritable() {
		m.layerEditNotice()
		return nil
	}
	choices := []choice{{label: "Ungrouped"}}
	for _, g := range nonEmptyGroups(m.groups) {
		choices = append(choices, choice{label: g.Name})
	}
	choices = append(choices, choice{label: "Cancel"})
	m.confirmChoice("Move "+truncatePlain(connectionName(c), 30), "Moving changes the organisation label only. It does not connect, disconnect or change the next start.", choices,
		func(m *Menu, idx int) tea.Cmd {
			if idx == len(choices)-1 {
				return nil
			}
			groupID := ""
			if idx > 0 {
				groupID = nonEmptyGroups(m.groups)[idx-1].ID
			}
			id := stableID(c)
			return m.runAction("Move", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
				if err := svc.MoveLayerConnections(ctx, []string{id}, groupID); err != nil {
					return app.ActionResult{}, err
				}
				return app.ActionResult{Message: "Connection moved."}, nil
			})
		})
	return nil
}

func connectionName(c app.Connection) string {
	if c.DisplayName != "" {
		return c.DisplayName
	}
	return c.Remark
}

func (m *Menu) displayNameFlow(c app.Connection) tea.Cmd {
	if !m.layerWritable() {
		m.layerEditNotice()
		return nil
	}
	m.promptInput("Display name", "Name shown in the panel and TUI (empty clears it)", c.DisplayName, false, func(m *Menu, value string) tea.Cmd {
		name := strings.TrimSpace(value)
		id := stableID(c)
		return m.runAction("Display name", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
			if err := svc.SetDisplayName(ctx, id, name); err != nil {
				return app.ActionResult{}, err
			}
			return app.ActionResult{Message: "Display name saved. The stored link is unchanged."}, nil
		})
	})
	return nil
}

func (m *Menu) hideConnection(c app.Connection) tea.Cmd {
	if !m.layerWritable() {
		m.layerEditNotice()
		return nil
	}
	id := stableID(c)
	hidden := !c.Hidden
	return m.runAction("Hide", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
		if err := svc.HideConnections(ctx, []string{id}, hidden); err != nil {
			return app.ActionResult{}, err
		}
		if hidden {
			return app.ActionResult{Message: "Connection hidden from the list."}, nil
		}
		return app.ActionResult{Message: "Connection shown in the list."}, nil
	})
}

// --- guarded delete ---

type connDeletePlanMsg struct {
	conn   app.Connection
	impact app.DeleteImpact
	err    error
}

func (m *Menu) deleteConnectionFlow(c app.Connection) tea.Cmd {
	if m.svc == nil {
		return nil
	}
	id := c.ID
	svc := m.svc
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
		defer cancel()
		impact, err := svc.ConnectionDeletePlan(ctx, id)
		return connDeletePlanMsg{conn: c, impact: impact, err: err}
	}
}

func (m *Menu) handleConnDeletePlan(msg connDeletePlanMsg) tea.Cmd {
	if msg.err != nil {
		m.setNotice(true, "Could not plan the delete: %s", friendlyError(msg.err))
		return nil
	}
	impact := msg.impact
	label := truncatePlain(connectionName(msg.conn), 40)
	if impact.Serving {
		m.setNotice(true, "%s is serving traffic. Switch to another connection before deleting it.", label)
		return nil
	}
	if impact.Allowed {
		m.confirmAction("Delete "+label+"?",
			"The stored profile"+ovpnNote(&msg.conn)+" and any saved credentials are removed. This cannot be undone.",
			"Delete", true, func(m *Menu) tea.Cmd {
				return m.deleteConnectionWith(msg.conn, app.DeleteOptions{})
			})
		return nil
	}
	// The connection is the saved next start: the operator must either name a
	// replacement or acknowledge that the next start becomes unset.
	m.confirmChoice("Delete the next-start connection?",
		impact.Message+"\n\nThe serving tunnel is not affected. Only the saved next start is.",
		[]choice{{label: "Choose a replacement connection"}, {label: "Delete and leave the next start unset", danger: true}, {label: "Cancel"}},
		func(m *Menu, idx int) tea.Cmd {
			switch idx {
			case 0:
				m.replacementPrompt(msg.conn)
			case 1:
				return m.deleteConnectionWith(msg.conn, app.DeleteOptions{AcknowledgeUnset: true})
			}
			return nil
		})
	return nil
}

func (m *Menu) replacementPrompt(deleting app.Connection) {
	m.promptInput("Replacement for the next start", "Name, display name or id of another connection", "", false, func(m *Menu, value string) tea.Cmd {
		needle := strings.ToLower(strings.TrimSpace(value))
		if needle == "" {
			m.setNotice(true, "Name a replacement, or choose to leave the next start unset.")
			return nil
		}
		for _, c := range m.conns {
			if c.ID == deleting.ID {
				continue
			}
			if strings.ToLower(c.ID) == needle || strings.ToLower(c.Remark) == needle || strings.ToLower(c.DisplayName) == needle {
				return m.deleteConnectionWith(deleting, app.DeleteOptions{ReplaceWithID: c.ID})
			}
		}
		m.setNotice(true, "No other connection matches %q. The next start was not changed.", value)
		return nil
	})
}

func (m *Menu) deleteConnectionWith(c app.Connection, opts app.DeleteOptions) tea.Cmd {
	id := c.ID
	return m.runAction("Delete", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
		if err := svc.DeleteConnectionWithOptions(ctx, id, opts); err != nil {
			return app.ActionResult{}, err
		}
		return app.ActionResult{Message: "Connection deleted."}, nil
	})
}

// --- source delete plan ---

type sourceDeletePlanMsg struct {
	sub    app.Subscription
	impact app.SourceDeleteImpact
	err    error
}

func (m *Menu) deleteSourceFlow(s app.Subscription) tea.Cmd {
	if m.svc == nil {
		return nil
	}
	svc := m.svc
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
		defer cancel()
		impact, err := svc.SourceDeletePlan(ctx, s.Group, s.URL)
		return sourceDeletePlanMsg{sub: s, impact: impact, err: err}
	}
}

func (m *Menu) handleSourceDeletePlan(msg sourceDeletePlanMsg) tea.Cmd {
	if msg.err != nil {
		m.setNotice(true, "Could not plan the source delete: %s", friendlyError(msg.err))
		return nil
	}
	impact := msg.impact
	detail := fmt.Sprintf("%s\n%s\n\nThis removes %d connection(s) it contributed.", impact.RedactedURL, impact.Message, impact.ConnectionCount)
	if impact.Serving {
		m.confirmChoice("Source contains the serving connection", detail+"\n\nDeleting is refused while it serves traffic. Switch first.",
			[]choice{{label: "Close"}}, func(m *Menu, _ int) tea.Cmd { return nil })
		return nil
	}
	if impact.Allowed {
		m.confirmAction("Remove source "+truncatePlain(msg.sub.Group, 30)+"?", detail, "Remove source", true,
			func(m *Menu) tea.Cmd {
				return m.removeSource(msg.sub, app.DeleteOptions{})
			})
		return nil
	}
	m.confirmChoice("Source contains the next-start selection", detail,
		[]choice{{label: "Remove and leave the next start unset", danger: true}, {label: "Cancel"}},
		func(m *Menu, idx int) tea.Cmd {
			if idx == 0 {
				return m.removeSource(msg.sub, app.DeleteOptions{AcknowledgeUnset: true})
			}
			return nil
		})
	return nil
}

func (m *Menu) removeSource(s app.Subscription, opts app.DeleteOptions) tea.Cmd {
	return m.runAction("Remove source", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
		if err := svc.RemoveSubscriptionWithOptions(ctx, s.Group, s.URL, opts); err != nil {
			return app.ActionResult{}, err
		}
		return app.ActionResult{Message: "Source removed with the connections it contributed."}, nil
	})
}
