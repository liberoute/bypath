package tui

import (
	"context"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/liberoute/bypath/internal/app"
)

func (m *Menu) organizeSourceFlow(sub app.Subscription) tea.Cmd {
	if m.svc == nil || m.busy != "" {
		return nil
	}
	if m.layerStatus.ReadOnly {
		m.setNotice(true, "Organisation is read-only.")
		return nil
	}
	if sub.LayerGroupID != "" {
		m.setNotice(false, "This source already has default group %q.", sub.LayerGroup)
		return nil
	}
	name := sub.ProposedGroup
	if name == "" {
		name = sub.Group
	}
	m.confirmAction("Organize source into a group?",
		fmt.Sprintf("Proposed group: %s\n\nThis adds organisation labels only. Import lists and .active stay byte-for-byte unchanged. Independently moved connections stay where you put them. A group is not failover.", name),
		"Organize", false, func(m *Menu) tea.Cmd {
			return m.runAction("Organize source", func(ctx context.Context, svc app.Contract) (app.ActionResult, error) {
				out, err := svc.OrganizeSubscription(ctx, sub.Group, sub.URL, "")
				if err != nil {
					return app.ActionResult{}, err
				}
				return app.ActionResult{Message: fmt.Sprintf("Default group %q created. The tunnel and next start are unchanged.", out.LayerGroup)}, nil
			})
		})
	return nil
}
