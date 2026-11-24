package layer

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/liberoute/bypath/internal/profile"
)

func sourceGroupKey(bucket, source string) string { return bucket + "\x00" + source }

// SourceGroup returns the default organisation for a source, not its runtime bucket.
func (m *Manager) SourceGroup(bucket, source string) (Group, bool) {
	var out Group
	var found bool
	_ = m.read(func() error {
		id := m.groups.SourceGroups[sourceGroupKey(bucket, source)]
		for _, g := range m.groups.Groups {
			if g.ID == id {
				out, found = g, true
				break
			}
		}
		return nil
	})
	return out, found
}

// ApplySource serialises migration, ownership and indexing with all layer edits.
// mutate is a caller-owned bucket import/refresh; it must not call layer methods.
// On failure every sidecar generation is restored, including .bak files. Bucket
// rollback belongs to the caller. The verified migration backup is retained.
func (m *Manager) ApplySource(mgr *profile.Manager, bucket, source, name string, organize bool, orphaned []string, mutate func() error) (Group, error) {
	var group Group
	err := m.withLock(func() error {
		if len(m.corrupt) != 0 {
			return ErrCorrupt
		}
		if name != "" {
			if err := validGroupName(name); err != nil {
				return err
			}
		}
		return m.sourceTransactionLocked(func() error {
			items, err := SnapshotLinks(mgr)
			if err != nil {
				return err
			}
			if err := m.migrateLocked(mgr, items, &MigrationPlan{}); err != nil {
				return err
			}
			key := sourceGroupKey(bucket, source)
			gid, bound := m.groups.SourceGroups[key]
			for _, g := range m.groups.Groups {
				if g.ID == gid {
					group = g
					break
				}
			}
			// A deleted default stays deleted through refresh. Only an explicit
			// Organize action may create another group.
			if name != "" && (!bound || (organize && group.ID == "")) {
				group = m.createSourceGroupLocked(bucket, source, name)
				if m.groups.SourceGroups == nil {
					m.groups.SourceGroups = map[string]string{}
				}
				m.groups.SourceGroups[key] = group.ID
				if organize {
					members := m.groupOfLocked()
					for _, e := range m.ids.Entries {
						if e.Bucket != bucket || e.SourceID != source || m.groups.MembershipOverrides[e.ID] {
							continue
						}
						// Migration bucket labels are not independent user moves.
						automatic := false
						for _, g := range m.groups.Groups {
							if g.ID == members[e.ID] && g.Auto && g.Name == bucket {
								automatic = true
							}
						}
						if members[e.ID] == "" || automatic {
							if automatic {
								for i := range m.groups.Groups {
									g := &m.groups.Groups[i]
									kept := make([]string, 0, len(g.MemberIDs))
									for _, id := range g.MemberIDs {
										if id != e.ID {
											kept = append(kept, id)
										}
									}
									g.MemberIDs = kept
								}
							}
							m.addSourceMemberLocked(group.ID, e.ID)
						}
					}
				}
			}
			if mutate != nil {
				if err := mutate(); err != nil {
					return err
				}
			}
			items, err = SnapshotLinks(mgr)
			if err != nil {
				return err
			}
			if _, err := m.indexLocked(items); err != nil {
				return err
			}
			for _, remark := range orphaned {
				if e, ok := m.entryForBucketRemarkLocked(bucket, remark); ok {
					if ep, ok := m.entryByIDLocked(e.ID); ok {
						ep.Orphaned = true
						ep.OrphanedAt = now()
					}
				}
			}
			m.ids.seal()
			if err := m.save(IDsFile, &m.ids); err != nil {
				return err
			}
			m.groups.seal()
			if err := m.save(GroupsFile, &m.groups); err != nil {
				return err
			}
			return nil
		})
	})
	return group, err
}

func (m *Manager) addSourceMemberLocked(groupID, id string) {
	for i := range m.groups.Groups {
		if m.groups.Groups[i].ID == groupID {
			m.groups.Groups[i].MemberIDs = appendUnique(m.groups.Groups[i].MemberIDs, id)
			return
		}
	}
}

func (m *Manager) createSourceGroupLocked(bucket, source, name string) Group {
	// Reuse the migration's bucket label only when it belongs exclusively to
	// this source and has not already been claimed by another source.
	for _, g := range m.groups.Groups {
		if !g.Auto || g.Name != name || name != bucket {
			continue
		}
		claimed := false
		for _, id := range m.groups.SourceGroups {
			if id == g.ID {
				claimed = true
			}
		}
		for _, id := range g.MemberIDs {
			if e, ok := m.entryByIDLocked(id); !ok || e.SourceID != source {
				claimed = true
			}
		}
		if !claimed {
			return g
		}
	}
	base := name
	for n := 2; ; n++ {
		collision := false
		for _, g := range m.groups.Groups {
			if strings.EqualFold(g.Name, name) {
				collision = true
				break
			}
		}
		if !collision {
			break
		}
		suffix := fmt.Sprintf(" (%d)", n)
		runes := []rune(base)
		if len(runes) > 64-len(suffix) {
			runes = runes[:64-len(suffix)]
		}
		name = string(runes) + suffix
	}
	order := 0
	for _, g := range m.groups.Groups {
		if g.Order >= order {
			order = g.Order + 1
		}
	}
	g := Group{ID: newID("g_", 8), Name: name, Order: order, MemberIDs: []string{}, CreatedAt: now()}
	m.groups.Groups = append(m.groups.Groups, g)
	return g
}

type sourceFileSnapshot struct {
	name   string
	data   []byte
	mode   os.FileMode
	exists bool
}

func (m *Manager) sourceTransactionLocked(fn func() error) error {
	var files []sourceFileSnapshot
	for _, name := range []string{GroupsFile, IDsFile, MigratedFile} {
		for _, name := range []string{name, name + ".bak"} {
			path := filepath.Join(m.dir, name)
			info, err := os.Lstat(path)
			if os.IsNotExist(err) {
				files = append(files, sourceFileSnapshot{name: name})
				continue
			}
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("layer file %s is not a regular file", name)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files = append(files, sourceFileSnapshot{name: name, data: data, mode: info.Mode(), exists: true})
		}
	}
	state, err := jsonMarshalIndent(struct {
		Groups   GroupsDoc
		IDs      IDsDoc
		Migrated *MigratedRecord
	}{m.groups, m.ids, m.migrated})
	if err != nil {
		return err
	}
	if err := fn(); err != nil {
		var rollback []error
		for _, f := range files {
			path := filepath.Join(m.dir, f.name)
			if !f.exists {
				if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
					rollback = append(rollback, e)
				}
				continue
			}
			if data, e := os.ReadFile(path); e == nil && bytes.Equal(data, f.data) {
				continue
			}
			if e := restoreSourceFile(path, f.data, f.mode); e != nil {
				rollback = append(rollback, e)
			}
		}
		var saved struct {
			Groups   GroupsDoc
			IDs      IDsDoc
			Migrated *MigratedRecord
		}
		_ = jsonUnmarshal(state, &saved)
		m.groups, m.ids, m.migrated = saved.Groups, saved.IDs, saved.Migrated
		if len(rollback) != 0 {
			m.readOnly = true
			return errors.Join(err, fmt.Errorf("source sidecar rollback failed: %w", errors.Join(rollback...)))
		}
		return err
	}
	return nil
}

func restoreSourceFile(path string, data []byte, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil && info.IsDir() {
		// Only an empty obstacle may be removed; never recursively delete data.
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".source-rollback-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(mode.Perm()); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}
