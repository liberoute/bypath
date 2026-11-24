package layer

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ErrCorrupt marks a layer file whose checksum and backup both fail to verify.
var ErrCorrupt = errors.New("layer state is corrupt")

// ErrNotMigrated is returned by operations that need a migration first.
var ErrNotMigrated = errors.New("organisation layer has not been migrated yet")

// ErrReadOnly is returned when a newer major schema is on disk.
var ErrReadOnly = errors.New("organisation layer was written by a newer Bypath version")

// Manager owns profiles/.layer/. All mutations take an in-process mutex and a
// cross-process advisory lock; readers see one consistent generation.
type Manager struct {
	profilesDir string
	dir         string

	mu       sync.Mutex
	loaded   bool
	readOnly bool
	corrupt  []string

	groups    GroupsDoc
	ids       IDsDoc
	hidden    HiddenDoc
	names     NamesDoc
	selection SelectionRecord
	migrated  *MigratedRecord
}

// Open attaches to the layer directory of a profiles directory. It performs no
// writes: a missing .layer/ simply means "not migrated".
func Open(profilesDir string) *Manager {
	return &Manager{
		profilesDir: profilesDir,
		dir:         filepath.Join(profilesDir, DirName),
	}
}

// Dir is the sidecar directory path.
func (m *Manager) Dir() string { return m.dir }

// ProfilesDir is the legacy profile directory path.
func (m *Manager) ProfilesDir() string { return m.profilesDir }

func (m *Manager) ensureLoaded() error {
	if m.loaded {
		return nil
	}
	// Open is read-only: do not create .layer/ here. Only a real write (save or
	// migration) creates the directory.
	g := GroupsDoc{SchemaVersion: SchemaVersion, MinReader: MinReader, Groups: []Group{}}
	switch found, err := m.loadDoc(GroupsFile, &g, g.valid); {
	case err != nil:
		m.corrupt = append(m.corrupt, GroupsFile)
	case !found:
		g.seal()
		m.groups = g
	default:
		if g.SchemaVersion > SchemaVersion {
			m.readOnly = true
		}
		m.groups = g
	}
	ids := IDsDoc{SchemaVersion: SchemaVersion, MinReader: MinReader, Entries: []Entry{}}
	if found, err := m.loadDoc(IDsFile, &ids, ids.valid); err != nil {
		m.corrupt = append(m.corrupt, IDsFile)
	} else if !found {
		ids.seal()
		m.ids = ids
	} else {
		if ids.SchemaVersion > SchemaVersion {
			m.readOnly = true
		}
		m.ids = ids
	}
	hidden := HiddenDoc{SchemaVersion: SchemaVersion, MinReader: MinReader, Records: []HiddenRecord{}}
	if found, err := m.loadDoc(HiddenFile, &hidden, hidden.valid); err != nil {
		m.corrupt = append(m.corrupt, HiddenFile)
	} else if !found {
		hidden.seal()
		m.hidden = hidden
	} else {
		m.hidden = hidden
	}
	names := NamesDoc{SchemaVersion: SchemaVersion, MinReader: MinReader, Names: map[string]string{}}
	if found, err := m.loadDoc(NamesFile, &names, names.valid); err != nil {
		m.corrupt = append(m.corrupt, NamesFile)
	} else if !found {
		names.seal()
		m.names = names
	} else {
		if names.Names == nil {
			names.Names = map[string]string{}
		}
		m.names = names
	}
	sel := SelectionRecord{SchemaVersion: SchemaVersion, MinReader: MinReader}
	if _, err := m.loadDoc(SelectionFile, &sel, sel.valid); err == nil {
		m.selection = sel
	}
	if rec, err := m.readMigrated(); err == nil {
		m.migrated = rec
	}
	m.loaded = true
	return nil
}

// loadDoc reads a document and verifies its checksum, falling back to .bak.
// found=false means the file does not exist (a valid, empty state).
func (m *Manager) loadDoc(name string, dst interface{}, valid func() bool) (bool, error) {
	path := filepath.Join(m.dir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if jsonUnmarshal(data, dst) == nil && valid() {
		return true, nil
	}
	// Checksum mismatch: fall back to the previous generation.
	bak := path + ".bak"
	bdata, berr := os.ReadFile(bak)
	if berr == nil {
		// Reset the destination before the second decode.
		zeroDoc(dst)
		if jsonUnmarshal(bdata, dst) == nil && valid() {
			return true, nil
		}
	}
	return true, ErrCorrupt
}

// zeroDoc clears a decoded document so a failed decode cannot leak partial
// fields into the fallback decode.
func zeroDoc(dst interface{}) {
	switch d := dst.(type) {
	case *GroupsDoc:
		*d = GroupsDoc{}
	case *IDsDoc:
		*d = IDsDoc{}
	case *HiddenDoc:
		*d = HiddenDoc{}
	case *NamesDoc:
		*d = NamesDoc{}
	case *SelectionRecord:
		*d = SelectionRecord{}
	case *TargetsDoc:
		*d = TargetsDoc{}
	case *UsageDoc:
		*d = UsageDoc{}
	}
}

func (m *Manager) readMigrated() (*MigratedRecord, error) {
	path := filepath.Join(m.dir, MigratedFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec MigratedRecord
	if err := jsonUnmarshal(data, &rec); err != nil {
		return nil, err
	}
	if !rec.valid() {
		return nil, ErrCorrupt
	}
	return &rec, nil
}

// Migrated reports whether the first-run migration completed.
func (m *Manager) Migrated() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureLoaded(); err != nil {
		return false
	}
	return m.migrated != nil
}

// ReadOnly reports whether a newer schema was found.
func (m *Manager) ReadOnly() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.ensureLoaded()
	return m.readOnly
}

// CorruptFiles lists files that failed checksum and backup verification.
func (m *Manager) CorruptFiles() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	_ = m.ensureLoaded()
	out := make([]string, len(m.corrupt))
	copy(out, m.corrupt)
	return out
}

// save writes one generation atomically: temp file, fsync, previous file to
// .bak, rename, fsync directory.
func (m *Manager) save(name string, v interface{}) error {
	if m.readOnly {
		return ErrReadOnly
	}
	if err := os.MkdirAll(m.dir, 0700); err != nil {
		return fmt.Errorf("creating layer directory: %w", err)
	}
	data, err := jsonMarshalIndent(v)
	if err != nil {
		return err
	}
	path := filepath.Join(m.dir, name)
	tmp, err := os.CreateTemp(m.dir, "."+name+".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		tmp.Close()
		os.Remove(tmpName)
	}
	if err := tmp.Chmod(0600); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if _, err := os.Stat(path); err == nil {
		if err := copyFile(path, path+".bak"); err != nil {
			os.Remove(tmpName)
			return err
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return syncDir(m.dir)
}

// withLock serialises a mutation across processes. The daemon is normally the
// only writer, but the CLI can act on the same directory when no daemon is
// running, so the lock is still required for web + CLI parity tests.
func (m *Manager) withLock(fn func() error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureLoaded(); err != nil {
		return err
	}
	if m.readOnly {
		return ErrReadOnly
	}
	unlock, err := acquireLock(filepath.Join(m.dir, "lock"))
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

func (m *Manager) read(fn func() error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureLoaded(); err != nil {
		return err
	}
	return fn()
}

// acquireLock creates profiles/.layer/lock exclusively. A lock older than 60
// seconds is considered abandoned (a crashed writer) and is broken.
func acquireLock(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			fmt.Fprintf(f, "%d %s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
			f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		info, statErr := os.Stat(path)
		if statErr == nil && time.Since(info.ModTime()) > 60*time.Second {
			_ = os.Remove(path)
			continue
		}
		return nil, fmt.Errorf("organisation layer is locked by another writer (%s)", path)
	}
	return nil, fmt.Errorf("could not acquire the organisation layer lock")
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		// Some platforms (notably Windows) cannot fsync a directory handle.
		if strings.Contains(strings.ToLower(err.Error()), "invalid") || strings.Contains(strings.ToLower(err.Error()), "access") {
			return nil
		}
		return err
	}
	return nil
}
