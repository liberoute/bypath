package layer

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/liberoute/bypath/internal/profile"
)

// Status is the read-only summary shown by the API, CLI and UIs.
type Status struct {
	Migrated        bool     `json:"migrated"`
	ReadOnly        bool     `json:"read_only"`
	Corrupt         []string `json:"corrupt,omitempty"`
	Groups          int      `json:"groups"`
	Entries         int      `json:"entries"`
	Orphaned        int      `json:"orphaned"`
	Hidden          int      `json:"hidden"`
	LastSelectionID string   `json:"last_selection_id,omitempty"`
	LastSelectionAt string   `json:"last_selection_at,omitempty"`
}

// GroupView is a group plus its resolved members.
type GroupView struct {
	Group
	Count int `json:"count"`
}

// EntryView is the non-secret identity shown to frontends.
type EntryView struct {
	ID                 string `json:"id"`
	Bucket             string `json:"bucket"`
	Remark             string `json:"remark"`
	DisplayName        string `json:"display_name,omitempty"`
	Protocol           string `json:"protocol"`
	Address            string `json:"address"`
	Port               int    `json:"port"`
	SourceID           string `json:"source_id"`
	GroupID            string `json:"group_id,omitempty"`
	Orphaned           bool   `json:"orphaned"`
	Hidden             bool   `json:"hidden"`
	CredentialsChanged bool   `json:"credentials_changed,omitempty"`
	MatchedByRemark    bool   `json:"matched_by_remark,omitempty"`
	AmbiguousIdentity  bool   `json:"ambiguous_identity,omitempty"`
	LastSeen           string `json:"last_seen"`
}

// Status returns a copy of the layer summary.
func (m *Manager) Status() Status {
	var st Status
	_ = m.read(func() error {
		st.Migrated = m.migrated != nil
		st.ReadOnly = m.readOnly
		st.Corrupt = append(st.Corrupt, m.corrupt...)
		st.Groups = len(m.groups.Groups)
		st.Entries = len(m.ids.Entries)
		for _, e := range m.ids.Entries {
			if e.Orphaned {
				st.Orphaned++
			}
			if e.Hidden {
				st.Hidden++
			}
		}
		st.LastSelectionID = m.selection.ID
		st.LastSelectionAt = m.selection.At
		return nil
	})
	return st
}

// Groups returns every group in display order.
func (m *Manager) Groups() []GroupView {
	var out []GroupView
	_ = m.read(func() error {
		gs := make([]Group, len(m.groups.Groups))
		copy(gs, m.groups.Groups)
		sort.SliceStable(gs, func(i, j int) bool {
			if gs[i].Order != gs[j].Order {
				return gs[i].Order < gs[j].Order
			}
			return gs[i].Name < gs[j].Name
		})
		for _, g := range gs {
			out = append(out, GroupView{Group: g, Count: len(g.MemberIDs)})
		}
		return nil
	})
	return out
}

// Entries returns every indexed connection.
func (m *Manager) Entries() []EntryView {
	var out []EntryView
	_ = m.read(func() error {
		groupOf := m.groupOfLocked()
		for _, e := range m.ids.Entries {
			view := EntryView{
				ID: e.ID, Bucket: e.Bucket, Remark: e.Remark,
				Protocol: e.Protocol, Address: e.Address, Port: e.Port,
				SourceID: e.SourceID, Orphaned: e.Orphaned, Hidden: e.Hidden,
				CredentialsChanged: e.CredentialsChange, MatchedByRemark: e.MatchedByRemark,
				AmbiguousIdentity: e.AmbiguousIdentity, LastSeen: e.LastSeen,
			}
			view.DisplayName = m.names.Names[e.ID]
			view.GroupID = groupOf[e.ID]
			out = append(out, view)
		}
		sort.SliceStable(out, func(i, j int) bool {
			if out[i].GroupID != out[j].GroupID {
				return out[i].GroupID < out[j].GroupID
			}
			return out[i].Remark < out[j].Remark
		})
		return nil
	})
	return out
}

// EntryByID returns one entry.
func (m *Manager) EntryByID(id string) (Entry, bool) {
	var out Entry
	var ok bool
	_ = m.read(func() error {
		for _, e := range m.ids.Entries {
			if e.ID == id {
				out, ok = e, true
				return nil
			}
		}
		return nil
	})
	return out, ok
}

// EntryForLink resolves the stable id of a bucket link.
func (m *Manager) EntryForLink(bucket, remark string) (Entry, bool) {
	var out Entry
	var ok bool
	_ = m.read(func() error {
		for _, e := range m.ids.Entries {
			if e.Bucket == bucket && e.Remark == remark {
				out, ok = e, true
				return nil
			}
		}
		return nil
	})
	return out, ok
}

// DisplayName returns the product display override, or "" when none is set.
func (m *Manager) DisplayName(id string) string {
	var name string
	_ = m.read(func() error {
		name = m.names.Names[id]
		return nil
	})
	return name
}

// MarkOrphaned flags entries the provider no longer returns but that are still
// stored locally. A later successful index pass clears the flag for every
// entry it sees, so a re-appearing connection simply becomes current again.
func (m *Manager) MarkOrphaned(ids []string, orphaned bool) error {
	if len(ids) == 0 {
		return nil
	}
	return m.withLock(func() error {
		changed := false
		for _, id := range ids {
			e, ok := m.entryByIDLocked(id)
			if !ok {
				continue
			}
			if e.Orphaned != orphaned {
				e.Orphaned = orphaned
				if orphaned {
					e.OrphanedAt = now()
				} else {
					e.OrphanedAt = ""
				}
				changed = true
			}
		}
		if !changed {
			return nil
		}
		m.ids.seal()
		return m.save(IDsFile, &m.ids)
	})
}

// GroupName resolves a group id to its current name.
func (m *Manager) GroupName(id string) string {
	var name string
	_ = m.read(func() error {
		for _, g := range m.groups.Groups {
			if g.ID == id {
				name = g.Name
				return nil
			}
		}
		return nil
	})
	return name
}

// GroupForMember returns the group id that contains a connection, or "".
func (m *Manager) GroupForMember(id string) string {
	var gid string
	_ = m.read(func() error {
		gid = m.groupOfLocked()[id]
		return nil
	})
	return gid
}

func (m *Manager) groupOfLocked() map[string]string {
	out := make(map[string]string, len(m.ids.Entries))
	for _, g := range m.groups.Groups {
		for _, id := range g.MemberIDs {
			out[id] = g.ID
		}
	}
	return out
}

// CreateGroup adds an empty group.
func (m *Manager) CreateGroup(name string) (Group, error) {
	var created Group
	err := m.withLock(func() error {
		name = strings.TrimSpace(name)
		if err := validGroupName(name); err != nil {
			return err
		}
		for _, g := range m.groups.Groups {
			if strings.EqualFold(g.Name, name) {
				return fmt.Errorf("group %q already exists", name)
			}
		}
		order := 0
		for _, g := range m.groups.Groups {
			if g.Order >= order {
				order = g.Order + 1
			}
		}
		created = Group{ID: newID("g_", 8), Name: name, Order: order, MemberIDs: []string{}, CreatedAt: now()}
		m.groups.Groups = append(m.groups.Groups, created)
		m.groups.seal()
		return m.save(GroupsFile, &m.groups)
	})
	return created, err
}

// RenameGroup changes a group's display name. It never touches links or .active.
func (m *Manager) RenameGroup(id, name string) error {
	return m.withLock(func() error {
		name = strings.TrimSpace(name)
		if err := validGroupName(name); err != nil {
			return err
		}
		for _, g := range m.groups.Groups {
			if g.ID != id && strings.EqualFold(g.Name, name) {
				return fmt.Errorf("group %q already exists", name)
			}
		}
		for i := range m.groups.Groups {
			if m.groups.Groups[i].ID == id {
				m.groups.Groups[i].Name = name
				m.groups.seal()
				return m.save(GroupsFile, &m.groups)
			}
		}
		return fmt.Errorf("group %q not found", id)
	})
}

// ReorderGroups sets the order from the supplied id list. Groups not named are
// kept after the listed ones in their existing relative order.
func (m *Manager) ReorderGroups(ids []string) error {
	return m.withLock(func() error {
		rank := map[string]int{}
		for i, id := range ids {
			rank[id] = i
		}
		sort.SliceStable(m.groups.Groups, func(i, j int) bool {
			ri, iok := rank[m.groups.Groups[i].ID]
			rj, jok := rank[m.groups.Groups[j].ID]
			if iok && jok {
				return ri < rj
			}
			if iok != jok {
				return iok
			}
			return m.groups.Groups[i].Order < m.groups.Groups[j].Order
		})
		for i := range m.groups.Groups {
			m.groups.Groups[i].Order = i
		}
		m.groups.seal()
		return m.save(GroupsFile, &m.groups)
	})
}

// DeleteGroup removes a group. Members are left ungrouped; the caller decides
// whether to delete the connections themselves (after the serving guard).
func (m *Manager) DeleteGroup(id string, deleteMembers bool) ([]string, error) {
	var members []string
	err := m.withLock(func() error {
		for i, g := range m.groups.Groups {
			if g.ID != id {
				continue
			}
			members = append(members, g.MemberIDs...)
			m.groups.Groups = append(m.groups.Groups[:i], m.groups.Groups[i+1:]...)
			m.groups.seal()
			_ = writeSnapshot(m.dir, "group-deleted", g)
			if err := m.save(GroupsFile, &m.groups); err != nil {
				return err
			}
			if deleteMembers {
				return m.forgetLocked(members)
			}
			return nil
		}
		return fmt.Errorf("group %q not found", id)
	})
	return members, err
}

// Move assigns connections to one group, or to Ungrouped when groupID is empty.
func (m *Manager) Move(ids []string, groupID string) error {
	return m.withLock(func() error {
		return m.sourceTransactionLocked(func() error {
			if groupID != "" {
				found := false
				for _, g := range m.groups.Groups {
					if g.ID == groupID {
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("group %q not found", groupID)
				}
			}
			wanted := map[string]bool{}
			if m.groups.MembershipOverrides == nil {
				m.groups.MembershipOverrides = map[string]bool{}
			}
			for _, id := range ids {
				if _, ok := m.entryByIDLocked(id); !ok {
					return fmt.Errorf("connection %q not found", id)
				}
				wanted[id] = true
				m.groups.MembershipOverrides[id] = true
			}
			for i := range m.groups.Groups {
				g := &m.groups.Groups[i]
				kept := g.MemberIDs[:0]
				for _, id := range g.MemberIDs {
					if !wanted[id] {
						kept = append(kept, id)
					}
				}
				g.MemberIDs = kept
			}
			if groupID != "" {
				for i := range m.groups.Groups {
					if m.groups.Groups[i].ID == groupID {
						for _, id := range ids {
							m.groups.Groups[i].MemberIDs = appendUnique(m.groups.Groups[i].MemberIDs, id)
						}
						break
					}
				}
			}
			m.groups.seal()
			return m.save(GroupsFile, &m.groups)
		})
	})
}

// SetDisplayName stores an override that never touches the bucket remark or
// .active, so a rename can never invalidate the persisted selection.
func (m *Manager) SetDisplayName(id, name string) error {
	return m.withLock(func() error {
		name = strings.TrimSpace(name)
		if utf8.RuneCountInString(name) > 64 {
			return fmt.Errorf("display name must be 1-64 characters")
		}
		if _, ok := m.entryByIDLocked(id); !ok {
			return fmt.Errorf("connection %q not found", id)
		}
		if name == "" {
			delete(m.names.Names, id)
		} else {
			m.names.Names[id] = name
		}
		m.names.seal()
		return m.save(NamesFile, &m.names)
	})
}

// Hide adds tombstones and marks the entries hidden.
func (m *Manager) Hide(ids []string) error {
	return m.withLock(func() error {
		for _, id := range ids {
			e, ok := m.entryByIDLocked(id)
			if !ok {
				return fmt.Errorf("connection %q not found", id)
			}
			m.addHiddenLocked(*e)
			m.setHiddenLocked(id, true)
		}
		m.hidden.seal()
		if err := m.save(HiddenFile, &m.hidden); err != nil {
			return err
		}
		m.ids.seal()
		return m.save(IDsFile, &m.ids)
	})
}

// Unhide removes tombstones matching the entry and un-hides it.
func (m *Manager) Unhide(ids []string) error {
	return m.withLock(func() error {
		for _, id := range ids {
			e, ok := m.entryByIDLocked(id)
			if !ok {
				return fmt.Errorf("connection %q not found", id)
			}
			m.removeHiddenLocked(*e)
			m.setHiddenLocked(id, false)
		}
		m.hidden.seal()
		if err := m.save(HiddenFile, &m.hidden); err != nil {
			return err
		}
		m.ids.seal()
		return m.save(IDsFile, &m.ids)
	})
}

// RecordSelection remembers an explicit user selection.
func (m *Manager) RecordSelection(id string) error {
	return m.withLock(func() error {
		m.selection = SelectionRecord{SchemaVersion: SchemaVersion, MinReader: MinReader, ID: id, At: now()}
		m.selection.seal()
		return m.save(SelectionFile, &m.selection)
	})
}

// LastSelection returns the last recorded user selection.
func (m *Manager) LastSelection() (string, string) {
	var id, at string
	_ = m.read(func() error {
		id, at = m.selection.ID, m.selection.At
		return nil
	})
	return id, at
}

// Forget removes index entries and overrides for deleted connections.
func (m *Manager) Forget(ids []string) error {
	return m.withLock(func() error { return m.forgetLocked(ids) })
}

func (m *Manager) forgetLocked(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
		if e, ok := m.entryByIDLocked(id); ok {
			m.removeHiddenLocked(*e)
		}
		delete(m.names.Names, id)
	}
	kept := m.ids.Entries[:0]
	for _, e := range m.ids.Entries {
		if !drop[e.ID] {
			kept = append(kept, e)
		}
	}
	m.ids.Entries = kept
	for i := range m.groups.Groups {
		g := &m.groups.Groups[i]
		out := g.MemberIDs[:0]
		for _, id := range g.MemberIDs {
			if !drop[id] {
				out = append(out, id)
			}
		}
		g.MemberIDs = out
	}
	m.ids.seal()
	if err := m.save(IDsFile, &m.ids); err != nil {
		return err
	}
	m.names.seal()
	if err := m.save(NamesFile, &m.names); err != nil {
		return err
	}
	m.hidden.seal()
	if err := m.save(HiddenFile, &m.hidden); err != nil {
		return err
	}
	m.groups.seal()
	return m.save(GroupsFile, &m.groups)
}

func (m *Manager) entryByIDLocked(id string) (*Entry, bool) {
	for i := range m.ids.Entries {
		if m.ids.Entries[i].ID == id {
			return &m.ids.Entries[i], true
		}
	}
	return nil, false
}

func (m *Manager) setHiddenLocked(id string, hidden bool) {
	if e, ok := m.entryByIDLocked(id); ok {
		e.Hidden = hidden
	}
}

func (m *Manager) addHiddenLocked(e Entry) {
	for _, r := range m.hidden.Records {
		if r.SourceID == e.SourceID && (r.RawHash == e.RawHash || (r.Transport == e.Transport && r.Transport != "")) {
			return
		}
	}
	m.hidden.Records = append(m.hidden.Records, HiddenRecord{
		SourceID: e.SourceID, RawHash: e.RawHash, Transport: e.Transport, HiddenAt: now(),
	})
}

func (m *Manager) removeHiddenLocked(e Entry) {
	kept := m.hidden.Records[:0]
	for _, r := range m.hidden.Records {
		if r.SourceID == e.SourceID && (r.RawHash == e.RawHash || (r.Transport == e.Transport && r.Transport != "")) {
			continue
		}
		kept = append(kept, r)
	}
	m.hidden.Records = kept
}

func (m *Manager) isHiddenLocked(e *Entry) bool {
	for _, r := range m.hidden.Records {
		if r.SourceID != e.SourceID {
			continue
		}
		if r.RawHash == e.RawHash || (r.Transport != "" && r.Transport == e.Transport) {
			return true
		}
	}
	return false
}

func appendUnique(list []string, id string) []string {
	for _, existing := range list {
		if existing == id {
			return list
		}
	}
	return append(list, id)
}

func validGroupName(name string) error {
	if utf8.RuneCountInString(name) < 1 || utf8.RuneCountInString(name) > 64 {
		return fmt.Errorf("group name must be 1-64 characters")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("group name contains a control character")
		}
	}
	if strings.TrimSpace(name) != name {
		return fmt.Errorf("group name must not start or end with whitespace")
	}
	return nil
}

// SnapshotLinks copies bucket links in deterministic bucket order.
func SnapshotLinks(mgr *profile.Manager) ([]Item, error) {
	if mgr == nil {
		return nil, fmt.Errorf("no profile manager")
	}
	var items []Item
	for _, bucket := range SortBuckets(mgr.ListGroups()) {
		g, err := mgr.GetGroup(bucket)
		if err != nil {
			continue
		}
		for i, l := range g.Links {
			items = append(items, ItemFromLink(l, bucket, i))
		}
	}
	return items, nil
}
