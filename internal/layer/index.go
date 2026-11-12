package layer

import (
	"fmt"
	"strings"

	"github.com/liberoute/bypath/internal/profile"
)

// IndexReport describes what one index pass changed.
type IndexReport struct {
	Total               int `json:"total"`
	Added               int `json:"added"`
	Matched             int `json:"matched"`
	CredentialRotations int `json:"credential_rotations"`
	MatchedByRemark     int `json:"matched_by_remark"`
	Ambiguous           int `json:"ambiguous"`
	Orphaned            int `json:"orphaned"`
	Hidden              int `json:"hidden"`
}

// Index rebuilds ids.json from the live buckets. Matching is source-scoped and
// uses T1 (raw URI), T2 (single credential rotation) and T3 (single remark).
// It never writes bucket files or .active.
func (m *Manager) Index(mgr *profile.Manager) (IndexReport, error) {
	items, err := SnapshotLinks(mgr)
	if err != nil {
		return IndexReport{}, err
	}
	var report IndexReport
	err = m.withLock(func() error {
		if m.migrated == nil {
			return ErrNotMigrated
		}
		var ierr error
		report, ierr = m.indexLocked(items)
		return ierr
	})
	return report, err
}

// indexLocked applies matching and persists ids/groups when they changed.
func (m *Manager) indexLocked(items []Item) (IndexReport, error) {
	existing := make([]Entry, len(m.ids.Entries))
	copy(existing, m.ids.Entries)
	res := MatchEntries(existing, items)

	entries := make([]Entry, 0, len(res.Matches)+len(res.Orphaned))
	report := IndexReport{Total: len(items), Ambiguous: res.Ambiguous}
	today := now()
	for _, match := range res.Matches {
		if match.Entry != nil {
			e := *match.Entry
			fillEntry(&e, match.Item, today)
			e.Orphaned = false
			e.OrphanedAt = ""
			e.CredentialsChange = match.CredentialsChanged
			e.MatchedByRemark = match.MatchedByRemark
			e.AmbiguousIdentity = false
			e.Hidden = m.isHiddenLocked(&e)
			report.Matched++
			if match.CredentialsChanged {
				report.CredentialRotations++
			}
			if match.MatchedByRemark {
				report.MatchedByRemark++
			}
			entries = append(entries, e)
			continue
		}
		e := Entry{
			ID:                newID("c_", 10),
			FirstSeen:         today,
			LastSeen:          today,
			DupCount:          match.Item.DupCount,
			AmbiguousIdentity: match.Ambiguous,
		}
		fillEntry(&e, match.Item, today)
		e.Hidden = m.isHiddenLocked(&e)
		report.Added++
		entries = append(entries, e)
	}
	for _, old := range res.Orphaned {
		e := old
		if !e.Orphaned {
			e.Orphaned = true
			e.OrphanedAt = today
		}
		e.CredentialsChange = false
		e.MatchedByRemark = false
		report.Orphaned++
		entries = append(entries, e)
	}
	// Keep hidden tombstones authoritative even for entries that only changed
	// their raw identity through a rotation.
	for i := range entries {
		if m.isHiddenLocked(&entries[i]) {
			entries[i].Hidden = true
		}
		if entries[i].Hidden {
			report.Hidden++
		}
	}
	m.ids.Entries = entries

	// New ids join the auto-created group of their bucket when one exists.
	members := m.groupOfLocked()
	changedGroups := false
	for _, match := range res.Matches {
		if match.Entry != nil {
			continue
		}
		id := ""
		for _, e := range entries {
			if e.Bucket == match.Item.Bucket && e.Remark == match.Item.ID.Remark && e.RawHash == match.Item.ID.RawHash {
				id = e.ID
				break
			}
		}
		if id == "" || members[id] != "" {
			continue
		}
		sourceGroup, bound := m.groups.SourceGroups[sourceGroupKey(match.Item.Bucket, match.Item.ID.SourceID)]
		for gi := range m.groups.Groups {
			g := &m.groups.Groups[gi]
			if (bound && g.ID == sourceGroup) || (!bound && g.Name == match.Item.Bucket) {
				m.groups.Groups[gi].MemberIDs = appendUnique(m.groups.Groups[gi].MemberIDs, id)
				members[id] = m.groups.Groups[gi].ID
				changedGroups = true
				break
			}
		}
	}

	oldChecksum := m.ids.Checksum
	m.ids.seal()
	if m.ids.Checksum != oldChecksum || len(m.ids.Entries) != len(existing) {
		if err := m.save(IDsFile, &m.ids); err != nil {
			return report, err
		}
	}
	if changedGroups {
		m.groups.seal()
		if err := m.save(GroupsFile, &m.groups); err != nil {
			return report, err
		}
	}
	return report, nil
}

func fillEntry(e *Entry, item Item, at string) {
	e.SourceID = item.ID.SourceID
	e.Protocol = item.ID.Protocol
	e.Address = item.ID.Address
	e.Port = item.ID.Port
	e.Transport = item.ID.Transport
	e.SecretHash = item.ID.SecretHash
	e.RawHash = item.ID.RawHash
	e.Bucket = item.Bucket
	e.Remark = item.ID.Remark
	e.LastSeen = at
	if e.FirstSeen == "" {
		e.FirstSeen = at
	}
	if item.DupCount > 0 {
		e.DupCount = item.DupCount
	}
}

// PlanEntry is one connection a migration would index.
type PlanEntry struct {
	Bucket   string `json:"bucket"`
	Remark   string `json:"remark"`
	Protocol string `json:"protocol"`
	Group    string `json:"group"`
}

// MigrationPlan is the read-only description of a first-run migration.
type MigrationPlan struct {
	AlreadyMigrated  bool         `json:"already_migrated"`
	DryRun           bool         `json:"dry_run"`
	Buckets          []BucketPlan `json:"buckets"`
	Entries          []PlanEntry  `json:"entries"`
	SelectedBucket   string       `json:"selected_bucket,omitempty"`
	SelectedRemark   string       `json:"selected_remark,omitempty"`
	SelectedResolved bool         `json:"selected_resolved"`
	BackupDir        string       `json:"backup_dir,omitempty"`
	ManifestHash     string       `json:"manifest_hash,omitempty"`
	Warnings         []string     `json:"warnings,omitempty"`
}

// BucketPlan summarises one profile bucket.
type BucketPlan struct {
	Name  string `json:"name"`
	Links int    `json:"links"`
}

// Plan returns the migration plan without writing anything.
func (m *Manager) Plan(mgr *profile.Manager) (MigrationPlan, error) {
	plan := MigrationPlan{DryRun: true}
	if m.Migrated() {
		plan.AlreadyMigrated = true
		return plan, nil
	}
	if mgr == nil {
		return plan, fmt.Errorf("no profile manager")
	}
	for _, bucket := range SortBuckets(mgr.ListGroups()) {
		g, err := mgr.GetGroup(bucket)
		if err != nil {
			continue
		}
		plan.Buckets = append(plan.Buckets, BucketPlan{Name: bucket, Links: len(g.Links)})
		for _, l := range g.Links {
			plan.Entries = append(plan.Entries, PlanEntry{Bucket: bucket, Remark: l.Remark, Protocol: l.Protocol, Group: bucket})
		}
	}
	if bucket, remark, ok := ReadActivePair(m.profilesDir); ok {
		plan.SelectedBucket, plan.SelectedRemark = bucket, remark
		plan.SelectedResolved = selectionResolves(mgr, bucket, remark)
		if !plan.SelectedResolved {
			plan.Warnings = append(plan.Warnings, "the saved next-start connection does not resolve; migration will not repair it")
		}
	}
	return plan, nil
}

// Migrate performs the first-run migration. With dryRun it returns the plan and
// writes nothing. It is idempotent: a completed migration is verified, not
// repeated.
func (m *Manager) Migrate(mgr *profile.Manager, dryRun bool) (MigrationPlan, error) {
	if dryRun {
		return m.Plan(mgr)
	}
	plan, err := m.Plan(mgr)
	if err != nil {
		return plan, err
	}
	if plan.AlreadyMigrated {
		if err := m.VerifyBackup(); err != nil {
			return plan, err
		}
		return plan, nil
	}
	if mgr == nil {
		return plan, fmt.Errorf("no profile manager")
	}
	items, err := SnapshotLinks(mgr)
	if err != nil {
		return plan, err
	}
	err = m.withLock(func() error { return m.migrateLocked(mgr, items, &plan) })
	if err != nil {
		return plan, err
	}
	plan.AlreadyMigrated = true
	return plan, nil
}

func (m *Manager) migrateLocked(mgr *profile.Manager, items []Item, plan *MigrationPlan) error {
	if m.migrated != nil {
		return nil
	}
	// 1. Backup the whole profile directory (excluding .layer) and verify it.
	backupDir, manifestHash, err := BackupProfiles(m.profilesDir)
	if err != nil {
		return err
	}
	plan.BackupDir, plan.ManifestHash = backupDir, manifestHash
	// 2. Index every link.
	m.ids.Entries = nil
	report, err := m.indexLocked(items)
	if err != nil {
		return err
	}
	if report.Total != len(items) {
		return fmt.Errorf("migration indexed %d of %d links", report.Total, len(items))
	}
	// 3. Create one group per bucket in file order.
	m.groups.Groups = nil
	order := 0
	for _, bucket := range SortBuckets(mgr.ListGroups()) {
		g, err := mgr.GetGroup(bucket)
		if err != nil {
			continue
		}
		group := Group{ID: newID("g_", 8), Name: bucket, Order: order, CreatedAt: now(), Auto: true, MemberIDs: []string{}}
		order++
		for _, l := range g.Links {
			if e, ok := m.entryForBucketRemarkLocked(bucket, l.Remark); ok {
				group.MemberIDs = appendUnique(group.MemberIDs, e.ID)
			}
		}
		m.groups.Groups = append(m.groups.Groups, group)
	}
	// 4. Mirror the selection (never write .active).
	var selectedID string
	if bucket, remark, ok := ReadActivePair(m.profilesDir); ok {
		if e, ok := m.entryForBucketRemarkLocked(bucket, remark); ok {
			selectedID = e.ID
		}
	}
	if err := m.save(IDsFile, &m.ids); err != nil {
		return err
	}
	m.groups.seal()
	if err := m.save(GroupsFile, &m.groups); err != nil {
		return err
	}
	rec := MigratedRecord{
		SchemaVersion: SchemaVersion, MinReader: MinReader,
		MigratedAt: now(), ManifestHash: manifestHash, BackupDir: backupDir, SelectedID: selectedID,
	}
	rec.seal()
	if err := m.save(MigratedFile, &rec); err != nil {
		return err
	}
	m.migrated = &rec
	return nil
}

func (m *Manager) entryForBucketRemarkLocked(bucket, remark string) (Entry, bool) {
	for _, e := range m.ids.Entries {
		if e.Bucket == bucket && e.Remark == remark {
			return e, true
		}
	}
	return Entry{}, false
}

func selectionResolves(mgr *profile.Manager, bucket, remark string) bool {
	if mgr == nil {
		return false
	}
	g, err := mgr.GetGroup(bucket)
	if err != nil {
		return false
	}
	for _, l := range g.Links {
		if strings.TrimSpace(l.Remark) == remark {
			return true
		}
	}
	return false
}

// RollbackReport describes a rollback attempt.
type RollbackReport struct {
	BackupDir         string   `json:"backup_dir,omitempty"`
	ChangedFiles      []string `json:"changed_files,omitempty"`
	MissingFiles      []string `json:"missing_files,omitempty"`
	Restored          bool     `json:"restored"`
	SelectionResolves bool     `json:"selection_resolves"`
	LayerArchived     string   `json:"layer_archived,omitempty"`
}

// Rollback restores bucket files that changed since migration and archives the
// layer. Without confirm it only reports. .active is restored only if it was
// part of the backup and changed, because it is legacy-owned.
func (m *Manager) Rollback(confirm bool) (RollbackReport, error) {
	var report RollbackReport
	err := m.withLock(func() error {
		if m.migrated == nil {
			return ErrNotMigrated
		}
		report.BackupDir = m.migrated.BackupDir
		changed, missing, err := compareBackup(m.migrated.BackupDir)
		if err != nil {
			return err
		}
		report.ChangedFiles, report.MissingFiles = changed, missing
		if !confirm {
			return nil
		}
		if len(missing) > 0 {
			return fmt.Errorf("backup is incomplete (%d files missing); refusing to roll back", len(missing))
		}
		if err := restoreChanged(m.migrated.BackupDir, changed); err != nil {
			return err
		}
		report.Restored = true
		report.SelectionResolves = activeResolves(m.profilesDir)
		archive := m.dir + ".rolled-back-" + timestampSlug()
		if err := osRename(m.dir, archive); err != nil {
			return fmt.Errorf("archiving layer directory: %w", err)
		}
		report.LayerArchived = archive
		return nil
	})
	return report, err
}

// VerifyBackup re-hashes the migration backup against its manifest.
func (m *Manager) VerifyBackup() error {
	if err := m.ensureLoaded(); err != nil {
		return err
	}
	if m.migrated == nil {
		return ErrNotMigrated
	}
	_, missing, err := compareBackup(m.migrated.BackupDir)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("migration backup is missing %d files", len(missing))
	}
	return nil
}
