package app

import (
	"context"
	"fmt"

	"github.com/liberoute/bypath/internal/credential"
	"github.com/liberoute/bypath/internal/layer"
	"github.com/liberoute/bypath/internal/profile"
)

// Selection states from SELECTION_AND_ACTIVE_CONTRACT.md §3.
const (
	SelectionOK       = "S-OK"
	SelectionDiff     = "S-DIFF"
	SelectionUnset    = "S-UNSET"
	SelectionDangling = "S-DANGLING"
	SelectionAuto     = "S-AUTO"
)

// SelectionInfo is the read-only reconciliation of .active and the live gateway.
type SelectionInfo struct {
	State          string `json:"state"`
	SelectedID     string `json:"selected_id,omitempty"`
	SelectedBucket string `json:"selected_bucket,omitempty"`
	SelectedRemark string `json:"selected_remark,omitempty"`
	ServingID      string `json:"serving_id,omitempty"`
	ServingRemark  string `json:"serving_remark,omitempty"`
	AutoChosen     bool   `json:"auto_chosen,omitempty"`
	Message        string `json:"message,omitempty"`
}

// DeleteImpact is the pre-flight description of a destructive change.
type DeleteImpact struct {
	ID                  string        `json:"id"`
	StableID            string        `json:"stable_id,omitempty"`
	Serving             bool          `json:"serving"`
	Selected            bool          `json:"selected"`
	Allowed             bool          `json:"allowed"`
	RequiresReplacement bool          `json:"requires_replacement"`
	RequiresAcknowledge bool          `json:"requires_acknowledge"`
	Message             string        `json:"message,omitempty"`
	Selection           SelectionInfo `json:"selection"`
}

// DeleteOptions carries the user's explicit decision for a guarded delete.
type DeleteOptions struct {
	// ReplaceWithID names an existing connection that is selected before the
	// delete. It is the default choice when the deleted item is the next-start
	// selection.
	ReplaceWithID string `json:"replace_with_id,omitempty"`
	// AcknowledgeUnset allows leaving the next start unset (S-UNSET wording).
	AcknowledgeUnset bool `json:"acknowledge_unset,omitempty"`
}

// SourceDeleteImpact is the pre-flight description of deleting a subscription.
type SourceDeleteImpact struct {
	Group               string        `json:"group"`
	URL                 string        `json:"url"`
	RedactedURL         string        `json:"redacted_url"`
	StableIDs           []string      `json:"stable_ids"`
	ConnectionCount     int           `json:"connection_count"`
	Serving             bool          `json:"serving"`
	Selected            bool          `json:"selected"`
	Allowed             bool          `json:"allowed"`
	RequiresReplacement bool          `json:"requires_replacement"`
	RequiresAcknowledge bool          `json:"requires_acknowledge"`
	Message             string        `json:"message,omitempty"`
	Selection           SelectionInfo `json:"selection"`
}

// attachLayer opens the sidecar and refreshes its index when a migration has
// already completed. A layer error never blocks the gateway: the legacy view
// remains usable and the error is surfaced in Status.
func (s *Local) attachLayer() {
	if s.profiles == nil {
		return
	}
	lay := layer.Open(s.profiles.Directory())
	s.layer = lay
	if lay.Migrated() {
		if _, err := lay.Index(s.profiles); err != nil {
			s.setLayerError(err)
		}
	}
}

func (s *Local) setLayerError(err error) {
	s.layerMu.Lock()
	defer s.layerMu.Unlock()
	if err == nil {
		s.layerErr = ""
		return
	}
	s.layerErr = err.Error()
}

func (s *Local) layerWarning() string {
	s.layerMu.RLock()
	defer s.layerMu.RUnlock()
	return s.layerErr
}

// Layer exposes the organisation layer.
func (s *Local) Layer() *layer.Manager { return s.layer }

// LayerStatus returns the sidecar summary.
func (s *Local) LayerStatus(ctx context.Context) (layer.Status, error) {
	if s.layer == nil {
		return layer.Status{}, errorf(CodeUnavailable, "organisation layer is not available")
	}
	return s.layer.Status(), nil
}

// LayerPlan returns the dry-run migration plan without writing.
func (s *Local) LayerPlan(ctx context.Context) (layer.MigrationPlan, error) {
	if s.layer == nil {
		return layer.MigrationPlan{}, errorf(CodeUnavailable, "organisation layer is not available")
	}
	return s.layer.Plan(s.profiles)
}

// LayerMigrate performs (or previews) the first-run migration.
func (s *Local) LayerMigrate(ctx context.Context, dryRun bool) (layer.MigrationPlan, error) {
	if s.layer == nil {
		return layer.MigrationPlan{}, errorf(CodeUnavailable, "organisation layer is not available")
	}
	plan, err := s.layer.Migrate(s.profiles, dryRun)
	if err != nil {
		return plan, asAppError(err, CodeInternal, "migrating the organisation layer")
	}
	return plan, nil
}

// LayerRollback restores the migration backup and archives the sidecar.
func (s *Local) LayerRollback(ctx context.Context, confirm bool) (layer.RollbackReport, error) {
	if s.layer == nil {
		return layer.RollbackReport{}, errorf(CodeUnavailable, "organisation layer is not available")
	}
	rep, err := s.layer.Rollback(confirm)
	if err != nil {
		return rep, asAppError(err, CodeInternal, "rolling back the organisation layer")
	}
	if rep.Restored {
		s.layer = layer.Open(s.profiles.Directory())
	}
	return rep, nil
}

// LayerGroups returns user groups, plus a virtual Ungrouped view.
func (s *Local) LayerGroups(ctx context.Context) ([]layer.GroupView, error) {
	if s.layer == nil {
		return nil, errorf(CodeUnavailable, "organisation layer is not available")
	}
	groups := s.layer.Groups()
	grouped := map[string]bool{}
	for _, g := range groups {
		for _, id := range g.MemberIDs {
			grouped[id] = true
		}
	}
	ungrouped := 0
	for _, e := range s.layer.Entries() {
		if !grouped[e.ID] {
			ungrouped++
		}
	}
	groups = append(groups, layer.GroupView{Group: layer.Group{ID: "", Name: "Ungrouped"}, Count: ungrouped})
	return groups, nil
}

// CreateLayerGroup creates an organisational group.
func (s *Local) CreateLayerGroup(ctx context.Context, name string) (layer.Group, error) {
	if s.layer == nil {
		return layer.Group{}, errorf(CodeUnavailable, "organisation layer is not available")
	}
	g, err := s.layer.CreateGroup(name)
	if err != nil {
		return g, asAppError(err, CodeInvalid, "creating group")
	}
	return g, nil
}

// RenameLayerGroup renames a group without touching links or .active.
func (s *Local) RenameLayerGroup(ctx context.Context, id, name string) error {
	if s.layer == nil {
		return errorf(CodeUnavailable, "organisation layer is not available")
	}
	return asAppError(s.layer.RenameGroup(id, name), CodeInvalid, "renaming group")
}

// ReorderLayerGroups sets group display order.
func (s *Local) ReorderLayerGroups(ctx context.Context, ids []string) error {
	if s.layer == nil {
		return errorf(CodeUnavailable, "organisation layer is not available")
	}
	return asAppError(s.layer.ReorderGroups(ids), CodeInvalid, "reordering groups")
}

// DeleteLayerGroup removes a group. With deleteMembers it deletes every member
// after the same serving/selection guard as a single delete.
func (s *Local) DeleteLayerGroup(ctx context.Context, id string, deleteMembers bool, opts DeleteOptions) error {
	if s.layer == nil {
		return errorf(CodeUnavailable, "organisation layer is not available")
	}
	s.switchMu.Lock()
	defer s.switchMu.Unlock()

	var members []string
	found := false
	for _, g := range s.layer.Groups() {
		if g.ID == id {
			members = append(members, g.MemberIDs...)
			found = true
			break
		}
	}
	if !found {
		return errorf(CodeNotFound, "group %q not found", id)
	}
	// Guard before touching anything, so a refused delete changes nothing.
	if deleteMembers {
		if err := s.guardBulkDelete(members, opts); err != nil {
			return err
		}
	}
	if _, err := s.layer.DeleteGroup(id, false); err != nil {
		return asAppError(err, CodeInvalid, "deleting group")
	}
	if !deleteMembers || len(members) == 0 {
		return nil
	}
	var deleted []string
	for _, memberID := range members {
		link, g, _, ferr := s.findLinkAny(memberID)
		if ferr != nil {
			// The index knows the entry but its bucket link is already gone.
			deleted = append(deleted, memberID)
			continue
		}
		if derr := s.deleteLinkLocked(link, g); derr != nil {
			if len(deleted) > 0 {
				_ = s.layer.Forget(deleted)
			}
			return derr
		}
		deleted = append(deleted, memberID)
	}
	return s.layer.Forget(deleted)
}

// MoveLayerConnections moves connections between user groups.
func (s *Local) MoveLayerConnections(ctx context.Context, ids []string, groupID string) error {
	if s.layer == nil {
		return errorf(CodeUnavailable, "organisation layer is not available")
	}
	stableIDs, err := s.resolveStableIDs(ids)
	if err != nil {
		return err
	}
	return asAppError(s.layer.Move(stableIDs, groupID), CodeInvalid, "moving connections")
}

// resolveStableIDs accepts either a stable id or a legacy group:remark id and
// returns stable ids.
func (s *Local) resolveStableIDs(ids []string) ([]string, error) {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if s.layer != nil {
			if _, ok := s.layer.EntryByID(id); ok {
				out = append(out, id)
				continue
			}
		}
		_, _, stable, err := s.findLinkAny(id)
		if err != nil {
			return nil, err
		}
		if stable == "" {
			return nil, errorf(CodeNotFound, "connection %q has no stable identity; run the layer migration first", id)
		}
		out = append(out, stable)
	}
	return out, nil
}

// SetDisplayName stores a display override without touching bucket remarks or
// .active.
func (s *Local) SetDisplayName(ctx context.Context, id, name string) error {
	if s.layer == nil {
		return errorf(CodeUnavailable, "organisation layer is not available")
	}
	link, g, stable, err := s.findLinkAny(id)
	if err != nil {
		return err
	}
	if stable == "" {
		if e, ok := s.layer.EntryForLink(g.Name, link.Remark); ok {
			stable = e.ID
		} else {
			return errorf(CodeNotFound, "connection has no stable identity; run the layer migration first")
		}
	}
	return asAppError(s.layer.SetDisplayName(stable, name), CodeInvalid, "setting display name")
}

// HideConnections hides entries in the product view. The serving and selected
// connections cannot be hidden.
func (s *Local) HideConnections(ctx context.Context, ids []string, hidden bool) error {
	if s.layer == nil {
		return errorf(CodeUnavailable, "organisation layer is not available")
	}
	stableIDs, err := s.resolveStableIDs(ids)
	if err != nil {
		return err
	}
	sel := s.selectionInfo()
	for _, id := range stableIDs {
		if sel.ServingID != "" && id == sel.ServingID {
			return &Error{Code: CodeConflict, Message: "the serving connection cannot be hidden", Hint: "switch to another connection first"}
		}
		if sel.SelectedID != "" && id == sel.SelectedID {
			return &Error{Code: CodeConflict, Message: "the next-start connection cannot be hidden", Hint: "choose a different next-start connection first"}
		}
	}
	if hidden {
		return asAppError(s.layer.Hide(stableIDs), CodeInvalid, "hiding connections")
	}
	return asAppError(s.layer.Unhide(stableIDs), CodeInvalid, "unhiding connections")
}

// selectionInfo reconciles .active with the live gateway.
func (s *Local) selectionInfo() SelectionInfo {
	info := SelectionInfo{State: SelectionOK}
	bucket, remark, ok := layer.ReadActivePair(s.profiles.Directory())
	if !ok {
		info.State = SelectionUnset
		info.Message = "Next start is not set — Bypath will choose a connection by itself on the next start."
	}
	var selected *profile.Link
	if ok {
		if g, err := s.profiles.GetGroup(bucket); err == nil {
			for _, l := range g.Links {
				if l.Remark == remark {
					selected = l
					break
				}
			}
		}
		if selected == nil {
			info.State = SelectionDangling
			info.SelectedBucket = bucket
			info.SelectedRemark = remark
			info.Message = "The saved next-start connection no longer exists. On the next start Bypath will choose a connection unpredictably from your import lists."
		} else {
			info.SelectedBucket = bucket
			info.SelectedRemark = remark
			info.SelectedID = s.stableIDFor(selected)
			if info.SelectedID == "" {
				info.SelectedID = ConnectionID(selected.Group, selected.Remark)
			}
		}
	}
	if s.runtime != nil {
		rs := s.runtime.Status()
		if rs.ActiveLink != "" {
			info.ServingRemark = rs.ActiveLink
			if l := s.findServingLink(rs.ActiveGroup, rs.ActiveLink); l != nil {
				info.ServingID = s.stableIDFor(l)
				if info.ServingID == "" {
					info.ServingID = ConnectionID(l.Group, l.Remark)
				}
			}
		}
	}
	if info.State == SelectionOK && info.ServingID != "" && info.SelectedID != "" && info.ServingID != info.SelectedID {
		info.State = SelectionDiff
		info.Message = fmt.Sprintf("Serving %s · Next start: %s", info.ServingRemark, info.SelectedRemark)
	}
	if info.State == SelectionOK && info.SelectedID != "" {
		lastID, _ := s.layerLastSelection()
		if lastID != "" && lastID != info.SelectedID {
			info.State = SelectionAuto
			info.AutoChosen = true
			info.Message = fmt.Sprintf("Bypath chose %q automatically because nothing valid was selected.", info.SelectedRemark)
		}
	}
	if info.State == SelectionUnset {
		info.SelectedID = ""
	}
	return info
}

func (s *Local) layerLastSelection() (string, string) {
	if s.layer == nil {
		return "", ""
	}
	return s.layer.LastSelection()
}

// stableIDFor returns the layer id for a link, or "" when the layer is not
// migrated.
func (s *Local) stableIDFor(link *profile.Link) string {
	if s.layer == nil || link == nil {
		return ""
	}
	if e, ok := s.layer.EntryForLink(link.Group, link.Remark); ok {
		return e.ID
	}
	return ""
}

func (s *Local) findServingLink(group, remark string) *profile.Link {
	if group != "" {
		if g, err := s.profiles.GetGroup(group); err == nil {
			for _, l := range g.Links {
				if l.Remark == remark {
					return l
				}
			}
		}
	}
	return s.findLinkByRemark(remark)
}

// findLinkAny accepts a stable layer id or the legacy group:remark id.
func (s *Local) findLinkAny(id string) (*profile.Link, *profile.Group, string, error) {
	if s.layer != nil {
		if e, ok := s.layer.EntryByID(id); ok {
			g, err := s.profiles.GetGroup(e.Bucket)
			if err != nil {
				return nil, nil, "", errorf(CodeNotFound, "connection %q no longer exists", id)
			}
			for _, l := range g.Links {
				if l.Remark == e.Remark {
					return l, g, e.ID, nil
				}
			}
			return nil, nil, "", errorf(CodeNotFound, "connection %q no longer exists", id)
		}
	}
	link, g, err := s.findLink(id)
	if err != nil {
		return nil, nil, "", err
	}
	return link, g, s.stableIDFor(link), nil
}

// ConnectionDeletePlan describes what deleting one connection would affect.
func (s *Local) ConnectionDeletePlan(ctx context.Context, id string) (DeleteImpact, error) {
	link, g, stable, err := s.findLinkAny(id)
	if err != nil {
		return DeleteImpact{}, err
	}
	sel := s.selectionInfo()
	impact := DeleteImpact{ID: id, StableID: stable, Selection: sel}
	impact.Serving = s.isServing(link, g)
	impact.Selected = s.isSelected(link, g)
	switch {
	case impact.Serving:
		impact.Message = "This connection is serving traffic. Switch to another connection first."
	case impact.Selected:
		impact.RequiresReplacement = true
		impact.RequiresAcknowledge = true
		impact.Message = "This connection is the next-start selection. Choose a replacement, or leave the next start unset."
	default:
		impact.Allowed = true
	}
	return impact, nil
}

// DeleteConnection refuses a serving connection and requires an explicit
// decision for the selected (next-start) connection. The existing signature is
// the strict form used by every legacy caller.
func (s *Local) DeleteConnection(ctx context.Context, id string) error {
	return s.DeleteConnectionWithOptions(ctx, id, DeleteOptions{})
}

// DeleteConnectionWithOptions applies the guard under the switch lock.
func (s *Local) DeleteConnectionWithOptions(ctx context.Context, id string, opts DeleteOptions) error {
	s.switchMu.Lock()
	defer s.switchMu.Unlock()
	link, g, stable, err := s.findLinkAny(id)
	if err != nil {
		return err
	}
	impact := s.impactLocked(link, g, opts)
	if impact.Serving {
		return &Error{Code: CodeConflict, Message: "the serving connection cannot be deleted", Hint: "switch to another connection first"}
	}
	if impact.Selected && !opts.AcknowledgeUnset && opts.ReplaceWithID == "" {
		return &Error{Code: CodeConflict, Message: "this connection is the next-start selection", Hint: "choose a replacement or acknowledge leaving the next start unset"}
	}
	if impact.Selected && opts.ReplaceWithID != "" {
		if perr := s.applyReplacementLocked(opts.ReplaceWithID, id); perr != nil {
			return perr
		}
	}
	if derr := s.deleteLinkLocked(link, g); derr != nil {
		return derr
	}
	if stable != "" {
		_ = s.layer.Forget([]string{stable})
	}
	return nil
}

func (s *Local) impactLocked(link *profile.Link, g *profile.Group, opts DeleteOptions) DeleteImpact {
	impact := DeleteImpact{StableID: s.stableIDFor(link), Selection: s.selectionInfo()}
	impact.Serving = s.isServing(link, g)
	impact.Selected = s.isSelected(link, g)
	return impact
}

func (s *Local) isServing(link *profile.Link, g *profile.Group) bool {
	if s.runtime == nil {
		return false
	}
	rs := s.runtime.Status()
	return rs.ActiveLink != "" && rs.ActiveLink == link.Remark && (rs.ActiveGroup == "" || rs.ActiveGroup == g.Name)
}

func (s *Local) isSelected(link *profile.Link, g *profile.Group) bool {
	bucket, remark, ok := layer.ReadActivePair(s.profiles.Directory())
	return ok && bucket == g.Name && remark == link.Remark
}

// applyReplacementLocked selects an existing connection before a delete. This
// invokes the legacy SetActiveLink, which is the only writer of .active.
func (s *Local) applyReplacementLocked(replacementID, deletingID string) error {
	if replacementID == deletingID {
		return errorf(CodeInvalid, "the replacement must be a different connection")
	}
	link, _, stable, err := s.findLinkAny(replacementID)
	if err != nil {
		return err
	}
	s.profiles.SetActiveLink(link)
	if s.layer != nil && stable != "" {
		_ = s.layer.RecordSelection(stable)
	}
	return nil
}

func (s *Local) deleteLinkLocked(link *profile.Link, g *profile.Group) error {
	key := credential.KeyFor(link)
	if err := s.profiles.RemoveLink(g.Name, link.Remark); err != nil {
		return asAppError(err, CodeInternal, "removing connection")
	}
	if err := s.profiles.ClearActiveIf(g.Name, link.Remark); err != nil {
		return asAppError(err, CodeInternal, "clearing active selection")
	}
	s.cleanupOVPNArtifacts(link)
	_ = s.creds.DeleteSaved(key)
	_ = s.creds.DeleteSession(key)
	return nil
}

// guardBulkDelete applies the serving/selected guard to a set of connections.
func (s *Local) guardBulkDelete(ids []string, opts DeleteOptions) error {
	for _, id := range ids {
		link, g, _, err := s.findLinkAny(id)
		if err != nil {
			continue
		}
		if s.isServing(link, g) {
			return &Error{Code: CodeConflict, Message: "the serving connection cannot be deleted", Hint: "switch to another connection first"}
		}
	}
	sel := s.selectionInfo()
	if sel.ServingID != "" && contains(ids, sel.ServingID) {
		return &Error{Code: CodeConflict, Message: "the serving connection cannot be deleted", Hint: "switch to another connection first"}
	}
	if sel.SelectedID != "" && contains(ids, sel.SelectedID) {
		if opts.ReplaceWithID != "" && !contains(ids, opts.ReplaceWithID) {
			return s.applyReplacementLocked(opts.ReplaceWithID, sel.SelectedID)
		}
		if !opts.AcknowledgeUnset {
			return &Error{Code: CodeConflict, Message: "the next-start selection is inside this deletion", Hint: "choose a replacement or acknowledge leaving the next start unset"}
		}
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// SourceDeletePlan describes what removing a subscription would affect.
func (s *Local) SourceDeletePlan(ctx context.Context, group, rawURL string) (SourceDeleteImpact, error) {
	g, err := s.profiles.GetGroup(group)
	if err != nil {
		return SourceDeleteImpact{}, errorf(CodeNotFound, "group %q not found", group)
	}
	sourceID := profile.SourceIDFor(rawURL)
	sel := s.selectionInfo()
	impact := SourceDeleteImpact{Group: group, URL: rawURL, RedactedURL: redactURL(rawURL), Selection: sel}
	var links []*profile.Link
	for _, l := range g.Links {
		if l.SourceID == sourceID {
			links = append(links, l)
		}
	}
	impact.ConnectionCount = len(links)
	for _, l := range links {
		if id := s.stableIDFor(l); id != "" {
			impact.StableIDs = append(impact.StableIDs, id)
		}
		if s.isServing(l, g) {
			impact.Serving = true
		}
		if s.isSelected(l, g) {
			impact.Selected = true
		}
	}
	switch {
	case impact.Serving:
		impact.Message = "This subscription contains the serving connection. Switch to another connection first."
	case impact.Selected:
		impact.RequiresReplacement = true
		impact.RequiresAcknowledge = true
		impact.Message = "This subscription contains the next-start selection. Choose a replacement outside it, or leave the next start unset."
	default:
		impact.Allowed = true
	}
	return impact, nil
}

// RemoveSubscription is the strict form: it refuses a serving source and needs
// an explicit decision when the source contains the next-start selection.
func (s *Local) RemoveSubscription(ctx context.Context, group, rawURL string) error {
	return s.RemoveSubscriptionWithOptions(ctx, group, rawURL, DeleteOptions{})
}

// RemoveSubscriptionWithOptions applies the guard under the switch lock.
func (s *Local) RemoveSubscriptionWithOptions(ctx context.Context, group, rawURL string, opts DeleteOptions) error {
	s.switchMu.Lock()
	defer s.switchMu.Unlock()
	impact, err := s.SourceDeletePlan(ctx, group, rawURL)
	if err != nil {
		return err
	}
	if impact.Serving {
		return &Error{Code: CodeConflict, Message: "the subscription containing the serving connection cannot be deleted", Hint: "switch to another connection first"}
	}
	if impact.Selected {
		if opts.ReplaceWithID != "" && !contains(impact.StableIDs, opts.ReplaceWithID) {
			if perr := s.applyReplacementLocked(opts.ReplaceWithID, impact.Selection.SelectedID); perr != nil {
				return perr
			}
		} else if !opts.AcknowledgeUnset {
			return &Error{Code: CodeConflict, Message: "this subscription contains the next-start selection", Hint: "choose a replacement or acknowledge leaving the next start unset"}
		}
	}
	g, err := s.profiles.GetGroup(group)
	if err != nil {
		return errorf(CodeNotFound, "group %q not found", group)
	}
	var removed []*profile.Link
	sourceID := profile.SourceIDFor(rawURL)
	for _, l := range g.Links {
		if l.SourceID == sourceID {
			removed = append(removed, l)
		}
	}
	if err := s.profiles.DropSubscription(group, rawURL); err != nil {
		return &Error{Code: CodeNotFound, Message: err.Error(), Err: err}
	}
	var ids []string
	for _, l := range removed {
		if id := s.stableIDFor(l); id != "" {
			ids = append(ids, id)
		}
		s.cleanupOVPNArtifacts(l)
		key := credential.KeyFor(l)
		_ = s.creds.DeleteSaved(key)
		_ = s.creds.DeleteSession(key)
	}
	if s.layer != nil && len(ids) > 0 {
		_ = s.layer.Forget(ids)
	}
	return nil
}

func (s *Local) indexLayer() {
	if s.layer != nil && s.layer.Migrated() {
		if _, err := s.layer.Index(s.profiles); err != nil {
			s.setLayerError(err)
			return
		}
		s.setLayerError(nil)
	}
}

// maybeRecordSelection records a user-initiated selection for S-AUTO detection.
func (s *Local) maybeRecordSelection(link *profile.Link) {
	if s.layer == nil || link == nil {
		return
	}
	if id := s.stableIDFor(link); id != "" {
		_ = s.layer.RecordSelection(id)
	}
}

func (s *Local) layerName(id string) string {
	if s.layer == nil {
		return ""
	}
	return s.layer.GroupName(id)
}

// SplitStableID is a small helper for callers that need the bucket/remark pair
// behind a stable id.
func (s *Local) SplitStableID(id string) (bucket, remark string, ok bool) {
	if s.layer == nil {
		return "", "", false
	}
	e, found := s.layer.EntryByID(id)
	if !found {
		return "", "", false
	}
	return e.Bucket, e.Remark, true
}
