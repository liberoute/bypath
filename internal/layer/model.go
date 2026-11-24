// Package layer implements the versioned organisation sidecar that lives under
// profiles/.layer/. It is an index over the legacy profile buckets and .active:
// it never opens .active for writing itself, never moves links between bucket
// files, and never touches the running gateway.
package layer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// SchemaVersion is the major schema this build writes. MinReader is the oldest
// major that can still read it. A newer major makes this build read-only.
const (
	SchemaVersion = 1
	MinReader     = 1
)

// File names inside profiles/.layer/.
const (
	GroupsFile    = "groups.json"
	IDsFile       = "ids.json"
	HiddenFile    = "hidden.json"
	NamesFile     = "names.json"
	SelectionFile = "selection.json"
	MigratedFile  = "MIGRATED"
	BackupDir     = "backup"
	TestsDir      = "tests"
	TargetsFile   = "targets.json"
	UsageFile     = "usage.json"
)

// DirName is the sidecar directory. It must be a directory: profile.Manager
// loads every top-level *.json as a bucket, so a top-level groups.json would be
// mis-read as a profile bucket by older binaries.
const DirName = ".layer"

// Group is a user-created organisational group. It has no runtime meaning:
// nothing here changes routing, .active or the gateway.
type Group struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Order     int      `json:"order"`
	MemberIDs []string `json:"member_ids"`
	CreatedAt string   `json:"created_at"`
	// Auto marks a group created by the first migration from a profile bucket.
	Auto bool `json:"auto,omitempty"`
}

// GroupsDoc is the content of groups.json.
type GroupsDoc struct {
	SchemaVersion       int               `json:"schema_version"`
	MinReader           int               `json:"min_reader"`
	Checksum            string            `json:"checksum"`
	Groups              []Group           `json:"groups"`
	SourceGroups        map[string]string `json:"source_groups,omitempty"`
	MembershipOverrides map[string]bool   `json:"membership_overrides,omitempty"`
}

// Entry is the stable identity of one connection. Secret-bearing values are
// never stored; SecretHash is a one-way digest used only for rotation matching.
type Entry struct {
	ID         string `json:"id"`
	SourceID   string `json:"source_id"`
	Protocol   string `json:"protocol"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	Transport  string `json:"transport"`
	SecretHash string `json:"secret_hash"`
	RawHash    string `json:"raw_hash"`
	Bucket     string `json:"bucket"`
	Remark     string `json:"remark"`
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`

	Orphaned          bool   `json:"orphaned,omitempty"`
	OrphanedAt        string `json:"orphaned_at,omitempty"`
	CredentialsChange bool   `json:"credentials_changed,omitempty"`
	MatchedByRemark   bool   `json:"matched_by_remark,omitempty"`
	AmbiguousIdentity bool   `json:"ambiguous_identity,omitempty"`
	Hidden            bool   `json:"hidden,omitempty"`
	DupCount          int    `json:"dup_count,omitempty"`
}

// IDsDoc is the content of ids.json.
type IDsDoc struct {
	SchemaVersion int     `json:"schema_version"`
	MinReader     int     `json:"min_reader"`
	Checksum      string  `json:"checksum"`
	Entries       []Entry `json:"entries"`
}

// HiddenRecord is a tombstone keyed both by exact identity and by the
// transport tuple, so a hidden entry stays hidden after a credential rotation
// and a provider refresh.
type HiddenRecord struct {
	SourceID  string `json:"source_id"`
	RawHash   string `json:"raw_hash"`
	Transport string `json:"transport"`
	HiddenAt  string `json:"hidden_at"`
}

// HiddenDoc is the content of hidden.json.
type HiddenDoc struct {
	SchemaVersion int            `json:"schema_version"`
	MinReader     int            `json:"min_reader"`
	Checksum      string         `json:"checksum"`
	Records       []HiddenRecord `json:"records"`
}

// NamesDoc stores display-name overrides keyed by stable connection id. The
// provider remark in the bucket file and .active are never touched.
type NamesDoc struct {
	SchemaVersion int               `json:"schema_version"`
	MinReader     int               `json:"min_reader"`
	Checksum      string            `json:"checksum"`
	Names         map[string]string `json:"names"`
}

// SelectionRecord remembers the last selection a *user* made, so the layer can
// distinguish an explicit choice from the gateway's own auto-pick.
type SelectionRecord struct {
	SchemaVersion int    `json:"schema_version"`
	MinReader     int    `json:"min_reader"`
	Checksum      string `json:"checksum"`
	ID            string `json:"id,omitempty"`
	At            string `json:"at,omitempty"`
}

// MigratedRecord is written last and makes migration re-runnable.
type MigratedRecord struct {
	SchemaVersion int    `json:"schema_version"`
	MinReader     int    `json:"min_reader"`
	Checksum      string `json:"checksum"`
	MigratedAt    string `json:"migrated_at"`
	ManifestHash  string `json:"manifest_hash"`
	BackupDir     string `json:"backup_dir"`
	// SelectedID mirrors the .active selection at migration time. It is a
	// cache, not a selection record: .active stays authoritative.
	SelectedID string `json:"selected_id,omitempty"`
}

// Target is one configured speed/latency target (M3).
type Target struct {
	ID            string   `json:"id"`
	URL           string   `json:"url"`
	Label         string   `json:"label"`
	ValidatedAt   string   `json:"validated_at,omitempty"`
	SupportsRange bool     `json:"supports_range"`
	LastStatus    string   `json:"last_status,omitempty"`
	LastIPs       []string `json:"last_ips,omitempty"`
	LastVerdict   string   `json:"last_verdict,omitempty"`
	AddedAt       string   `json:"added_at"`
}

// TargetsDoc is the content of targets.json.
type TargetsDoc struct {
	SchemaVersion int      `json:"schema_version"`
	MinReader     int      `json:"min_reader"`
	Checksum      string   `json:"checksum"`
	Targets       []Target `json:"targets"`
}

// UsageDoc counts speed-test bytes per UTC month.
type UsageDoc struct {
	SchemaVersion int              `json:"schema_version"`
	MinReader     int              `json:"min_reader"`
	Checksum      string           `json:"checksum"`
	Months        map[string]int64 `json:"months"`
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

func newID(prefix string, n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is not recoverable; fall back to time-based bytes
		// so the caller still gets a unique-looking id rather than an empty one.
		ts := sha256.Sum256([]byte(time.Now().Format(time.RFC3339Nano)))
		copy(b, ts[:])
	}
	return prefix + hex.EncodeToString(b)
}

func checksum(v interface{}) string {
	data, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Canonical payloads for checksumming: the same struct with Checksum cleared.
// Marshalling a struct with a zero Checksum would include the field, so each
// document exposes an explicit payload instead.

type groupsPayload struct {
	SchemaVersion       int               `json:"schema_version"`
	MinReader           int               `json:"min_reader"`
	Groups              []Group           `json:"groups"`
	SourceGroups        map[string]string `json:"source_groups,omitempty"`
	MembershipOverrides map[string]bool   `json:"membership_overrides,omitempty"`
}

func (d *GroupsDoc) payload() groupsPayload {
	return groupsPayload{SchemaVersion: d.SchemaVersion, MinReader: d.MinReader, Groups: d.Groups, SourceGroups: d.SourceGroups, MembershipOverrides: d.MembershipOverrides}
}

func (d *GroupsDoc) seal() { d.Checksum = checksum(d.payload()) }
func (d *GroupsDoc) valid() bool {
	return d.SchemaVersion > 0 && d.Checksum != "" && d.Checksum == checksum(d.payload())
}

type idsPayload struct {
	SchemaVersion int     `json:"schema_version"`
	MinReader     int     `json:"min_reader"`
	Entries       []Entry `json:"entries"`
}

func (d *IDsDoc) payload() idsPayload {
	return idsPayload{SchemaVersion: d.SchemaVersion, MinReader: d.MinReader, Entries: d.Entries}
}
func (d *IDsDoc) seal() { d.Checksum = checksum(d.payload()) }
func (d *IDsDoc) valid() bool {
	return d.SchemaVersion > 0 && d.Checksum != "" && d.Checksum == checksum(d.payload())
}

type hiddenPayload struct {
	SchemaVersion int            `json:"schema_version"`
	MinReader     int            `json:"min_reader"`
	Records       []HiddenRecord `json:"records"`
}

func (d *HiddenDoc) payload() hiddenPayload {
	return hiddenPayload{SchemaVersion: d.SchemaVersion, MinReader: d.MinReader, Records: d.Records}
}
func (d *HiddenDoc) seal() { d.Checksum = checksum(d.payload()) }
func (d *HiddenDoc) valid() bool {
	return d.SchemaVersion > 0 && d.Checksum != "" && d.Checksum == checksum(d.payload())
}

type namesPayload struct {
	SchemaVersion int               `json:"schema_version"`
	MinReader     int               `json:"min_reader"`
	Names         map[string]string `json:"names"`
}

func (d *NamesDoc) payload() namesPayload {
	return namesPayload{SchemaVersion: d.SchemaVersion, MinReader: d.MinReader, Names: d.Names}
}
func (d *NamesDoc) seal() { d.Checksum = checksum(d.payload()) }
func (d *NamesDoc) valid() bool {
	return d.SchemaVersion > 0 && d.Checksum != "" && d.Checksum == checksum(d.payload())
}

type selectionPayload struct {
	SchemaVersion int    `json:"schema_version"`
	MinReader     int    `json:"min_reader"`
	ID            string `json:"id,omitempty"`
	At            string `json:"at,omitempty"`
}

func (d *SelectionRecord) payload() selectionPayload {
	return selectionPayload{SchemaVersion: d.SchemaVersion, MinReader: d.MinReader, ID: d.ID, At: d.At}
}
func (d *SelectionRecord) seal() { d.Checksum = checksum(d.payload()) }
func (d *SelectionRecord) valid() bool {
	return d.SchemaVersion > 0 && d.Checksum != "" && d.Checksum == checksum(d.payload())
}

type migratedPayload struct {
	SchemaVersion int    `json:"schema_version"`
	MinReader     int    `json:"min_reader"`
	MigratedAt    string `json:"migrated_at"`
	ManifestHash  string `json:"manifest_hash"`
	BackupDir     string `json:"backup_dir"`
	SelectedID    string `json:"selected_id,omitempty"`
}

func (d *MigratedRecord) payload() migratedPayload {
	return migratedPayload{SchemaVersion: d.SchemaVersion, MinReader: d.MinReader, MigratedAt: d.MigratedAt, ManifestHash: d.ManifestHash, BackupDir: d.BackupDir, SelectedID: d.SelectedID}
}
func (d *MigratedRecord) seal() { d.Checksum = checksum(d.payload()) }
func (d *MigratedRecord) valid() bool {
	return d.SchemaVersion > 0 && d.Checksum != "" && d.Checksum == checksum(d.payload())
}

type targetsPayload struct {
	SchemaVersion int      `json:"schema_version"`
	MinReader     int      `json:"min_reader"`
	Targets       []Target `json:"targets"`
}

func (d *TargetsDoc) payload() targetsPayload {
	return targetsPayload{SchemaVersion: d.SchemaVersion, MinReader: d.MinReader, Targets: d.Targets}
}
func (d *TargetsDoc) seal() { d.Checksum = checksum(d.payload()) }
func (d *TargetsDoc) valid() bool {
	return d.SchemaVersion > 0 && d.Checksum != "" && d.Checksum == checksum(d.payload())
}

type usagePayload struct {
	SchemaVersion int              `json:"schema_version"`
	MinReader     int              `json:"min_reader"`
	Months        map[string]int64 `json:"months"`
}

func (d *UsageDoc) payload() usagePayload {
	return usagePayload{SchemaVersion: d.SchemaVersion, MinReader: d.MinReader, Months: d.Months}
}
func (d *UsageDoc) seal() { d.Checksum = checksum(d.payload()) }
func (d *UsageDoc) valid() bool {
	return d.SchemaVersion > 0 && d.Checksum != "" && d.Checksum == checksum(d.payload())
}
