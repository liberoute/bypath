package layer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// maxStoredResults bounds the per-connection history. Results are derived
// measurements, never profile state, so trimming the oldest is safe.
const maxStoredResults = 10

// TestResultsFile is one connection's result history inside TestsDir.
type TestResultsFile struct {
	ConnectionID string            `json:"connection_id"`
	Results      []json.RawMessage `json:"results"`
}

func testResultsName(connectionID string) string {
	sum := sha256.Sum256([]byte(connectionID))
	return hex.EncodeToString(sum[:16]) + ".json"
}

// SaveTestResult appends one measurement to the connection's history and keeps
// the newest maxStoredResults entries. The file is written atomically; a
// corrupt or missing file simply starts a new history.
func (m *Manager) SaveTestResult(connectionID string, result json.RawMessage) error {
	if connectionID == "" {
		return fmt.Errorf("empty connection id")
	}
	return m.withLock(func() error {
		dir := filepath.Join(m.dir, TestsDir)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		path := filepath.Join(dir, testResultsName(connectionID))
		doc := TestResultsFile{ConnectionID: connectionID}
		if data, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(data, &doc)
			doc.ConnectionID = connectionID
		}
		doc.Results = append(doc.Results, append(json.RawMessage(nil), result...))
		if len(doc.Results) > maxStoredResults {
			doc.Results = doc.Results[len(doc.Results)-maxStoredResults:]
		}
		data, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return err
		}
		tmp, err := os.CreateTemp(dir, ".result-*.tmp")
		if err != nil {
			return err
		}
		name := tmp.Name()
		cleanup := func() {
			tmp.Close()
			os.Remove(name)
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
			os.Remove(name)
			return err
		}
		if err := os.Rename(name, path); err != nil {
			os.Remove(name)
			return err
		}
		return syncDir(dir)
	})
}

// TestResults returns the stored results for one connection, oldest first.
func (m *Manager) TestResults(connectionID string) ([]json.RawMessage, error) {
	var out []json.RawMessage
	err := m.read(func() error {
		path := filepath.Join(m.dir, TestsDir, testResultsName(connectionID))
		data, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		var doc TestResultsFile
		if err := json.Unmarshal(data, &doc); err != nil {
			// Results are replaceable measurements; a corrupt history is
			// reported as empty rather than failing every reader.
			return nil
		}
		out = doc.Results
		return nil
	})
	return out, err
}

// ClearTestResults removes one connection's history. It is used when the
// connection itself is deleted, so derived data cannot outlive its subject.
func (m *Manager) ClearTestResults(connectionID string) error {
	return m.withLock(func() error {
		err := os.Remove(filepath.Join(m.dir, TestsDir, testResultsName(connectionID)))
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	})
}
