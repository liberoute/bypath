package layer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// maxTargets mirrors the design limit; the app enforces it too so a direct
// layer caller cannot exceed it.
const maxTargets = 10

type targetsDoc struct {
	Targets []json.RawMessage `json:"targets"`
}

// Targets returns the stored target documents, oldest first.
func (m *Manager) Targets() ([]json.RawMessage, error) {
	var out []json.RawMessage
	err := m.read(func() error {
		data, err := os.ReadFile(filepath.Join(m.dir, TargetsFile))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		var doc targetsDoc
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil
		}
		out = doc.Targets
		return nil
	})
	return out, err
}

// SaveTargets replaces the registry atomically.
func (m *Manager) SaveTargets(items []json.RawMessage) error {
	if len(items) > maxTargets {
		return fmt.Errorf("at most %d speed targets", maxTargets)
	}
	return m.withLock(func() error {
		return m.save(TargetsFile, targetsDoc{Targets: items})
	})
}

// Usage is the persisted monthly byte counter.
type Usage struct {
	Month     string `json:"month"`
	Bytes     int64  `json:"bytes"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// Usage reads the counter. A missing or corrupt file reads as a zero counter:
// accounting must never block a test on its own state.
func (m *Manager) Usage() (Usage, error) {
	var out Usage
	err := m.read(func() error {
		data, err := os.ReadFile(filepath.Join(m.dir, UsageFile))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		var doc Usage
		if err := json.Unmarshal(data, &doc); err != nil {
			return nil
		}
		out = doc
		return nil
	})
	return out, err
}

// AddUsage adds counted bytes to the given month, rolling the counter when the
// stored month differs.
func (m *Manager) AddUsage(month string, delta int64) (Usage, error) {
	var out Usage
	err := m.withLock(func() error {
		doc := Usage{Month: month}
		if data, err := os.ReadFile(filepath.Join(m.dir, UsageFile)); err == nil {
			var stored Usage
			if json.Unmarshal(data, &stored) == nil && stored.Month == month {
				doc = stored
			}
		}
		doc.Month = month
		doc.Bytes += delta
		doc.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		out = doc
		return m.save(UsageFile, doc)
	})
	return out, err
}
