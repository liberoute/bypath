// Package credential stores username/password credentials for profiles.
//
// Two storage classes exist and are reported to the user as different things:
//
//   - Saved: AES-256-GCM encrypted records under the profile directory. The
//     master key is a random 32-byte file with owner-only permissions. This is
//     encryption at rest, not merely a permission bit: copying the record file
//     without the master key does not reveal the password.
//   - Session: in-memory only. A 0700 runtime directory holds a short-lived
//     copy so a TUI import can hand credentials to a gateway that is starting;
//     Stop removes it. Session credentials never enter config or group JSON.
//
// File permissions still protect the master key itself; that limitation is
// documented rather than described as equivalent to the encryption.
package credential

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/securefile"
)

// Credentials is one username/password pair. It must never be logged.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// KeyFor returns a stable, non-reversible identifier for a link's credential
// record. Renaming the display name or moving the link between groups keeps the
// same record; changing the server or URI produces a different one.
func KeyFor(link *profile.Link) string {
	if link == nil {
		return ""
	}
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%d\n%s\n%s", link.Protocol, link.Address, link.Port, link.RawURI, link.OVPNPath)
	return hex.EncodeToString(h.Sum(nil))
}

type envelope struct {
	Version   int    `json:"v"`
	Algorithm string `json:"alg"`
	Nonce     string `json:"nonce"`
	Data      string `json:"data"`
}

const (
	envelopeVersion = 1
	algorithm       = "aes-256-gcm"
	masterKeySize   = 32
)

// Store holds saved and session credentials. It is safe for concurrent use.
type Store struct {
	persistentDir string
	sessionDir    string

	mu      sync.RWMutex
	session map[string]Credentials

	keyOnce sync.Once
	key     []byte
	keyErr  error
}

// Open creates a store. Directories are created lazily on first write, so a
// read-only installation can still read previously saved records.
func Open(persistentDir, sessionDir string) *Store {
	s := &Store{
		persistentDir: persistentDir,
		sessionDir:    sessionDir,
		session:       make(map[string]Credentials),
	}
	s.loadSessionFiles()
	return s
}

var defaultStore atomic.Pointer[Store]

// SetDefault installs the process-wide store used by config generation.
func SetDefault(s *Store) { defaultStore.Store(s) }

// Default returns the process-wide store, or nil when none was installed.
func Default() *Store { return defaultStore.Load() }

// Lookup resolves credentials for a link from the default store.
func Lookup(link *profile.Link) (Credentials, bool) {
	s := Default()
	if s == nil {
		return Credentials{}, false
	}
	return s.Lookup(KeyFor(link))
}

// Lookup returns session credentials first, then saved credentials.
func (s *Store) Lookup(key string) (Credentials, bool) {
	if s == nil || key == "" {
		return Credentials{}, false
	}
	if c, ok := s.LookupSession(key); ok {
		return c, true
	}
	return s.LookupSaved(key)
}

// LookupSession returns credentials held for the current run only.
func (s *Store) LookupSession(key string) (Credentials, bool) {
	if s == nil || key == "" {
		return Credentials{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.session[key]
	return c, ok && c.Username != ""
}

// LookupSaved decrypts a persisted record.
func (s *Store) LookupSaved(key string) (Credentials, bool) {
	if s == nil || key == "" {
		return Credentials{}, false
	}
	data, err := os.ReadFile(s.recordPath(key))
	if err != nil {
		return Credentials{}, false
	}
	plain, err := s.decrypt(key, data)
	if err != nil {
		return Credentials{}, false
	}
	var c Credentials
	if err := json.Unmarshal(plain, &c); err != nil || c.Username == "" {
		return Credentials{}, false
	}
	return c, true
}

// HasSaved reports whether an encrypted record exists for key.
func (s *Store) HasSaved(key string) bool {
	if s == nil || key == "" {
		return false
	}
	_, err := os.Stat(s.recordPath(key))
	return err == nil
}

// Save encrypts credentials to the profile directory and removes any session
// copy so exactly one storage class describes the state.
func (s *Store) Save(key string, c Credentials) error {
	if s == nil || key == "" {
		return errors.New("credential: empty key")
	}
	if strings.TrimSpace(c.Username) == "" {
		return errors.New("credential: empty username")
	}
	plain, err := json.Marshal(c)
	if err != nil {
		return err
	}
	enc, err := s.encrypt(key, plain)
	if err != nil {
		return err
	}
	if err := securefile.MkdirAll(s.persistentDir); err != nil {
		return fmt.Errorf("credential: creating store directory: %w", err)
	}
	if err := securefile.WriteFile(s.recordPath(key), enc); err != nil {
		return fmt.Errorf("credential: writing record: %w", err)
	}
	return s.DeleteSession(key)
}

// DeleteSaved removes the encrypted record. A missing record is not an error.
func (s *Store) DeleteSaved(key string) error {
	if s == nil || key == "" {
		return nil
	}
	err := os.Remove(s.recordPath(key))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// SetSession keeps credentials for this run only. They are also written to the
// volatile runtime directory so a gateway starting after the import can read
// them; Stop clears both.
func (s *Store) SetSession(key string, c Credentials) error {
	if s == nil || key == "" {
		return errors.New("credential: empty key")
	}
	s.mu.Lock()
	s.session[key] = c
	s.mu.Unlock()

	if s.sessionDir == "" {
		return nil
	}
	if strings.TrimSpace(c.Username) == "" {
		return nil
	}
	if err := securefile.MkdirAll(s.sessionDir); err != nil {
		return fmt.Errorf("credential: creating session directory: %w", err)
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := securefile.WriteFile(s.sessionPath(key), data); err != nil {
		return fmt.Errorf("credential: writing session record: %w", err)
	}
	return nil
}

// DeleteSession forgets session credentials for key.
func (s *Store) DeleteSession(key string) error {
	if s == nil || key == "" {
		return nil
	}
	s.mu.Lock()
	delete(s.session, key)
	s.mu.Unlock()
	if s.sessionDir == "" {
		return nil
	}
	err := os.Remove(s.sessionPath(key))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// ClearSession removes every session credential, including volatile files. It
// is called when the gateway stops so a "do not save" choice cannot outlive the
// connection it was entered for.
func (s *Store) ClearSession() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	for key := range s.session {
		delete(s.session, key)
	}
	s.mu.Unlock()
	return ClearSessionDir(s.sessionDir)
}

// ClearSessionDir removes every session credential file in dir. It also covers
// a crashed or killed daemon, whose last run never reached ClearSession: those
// secrets must not be reloaded by the next run.
func ClearSessionDir(dir string) error {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	var failed []error
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		if err := os.Remove(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			failed = append(failed, err)
		}
	}
	return errors.Join(failed...)
}

// SessionCount reports how many session credentials are held.
func (s *Store) SessionCount() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.session)
}

func (s *Store) loadSessionFiles() {
	if s.sessionDir == "" {
		return
	}
	entries, err := os.ReadDir(s.sessionDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.sessionDir, e.Name()))
		if err != nil {
			continue
		}
		var c Credentials
		if err := json.Unmarshal(data, &c); err != nil || c.Username == "" {
			continue
		}
		s.session[strings.TrimSuffix(e.Name(), ".json")] = c
	}
}

func (s *Store) recordPath(key string) string {
	return filepath.Join(s.persistentDir, key+".cred")
}

func (s *Store) sessionPath(key string) string {
	return filepath.Join(s.sessionDir, key+".json")
}

func (s *Store) encrypt(key string, plain []byte) ([]byte, error) {
	master, err := s.masterKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, plain, additionalData(key))
	return json.Marshal(envelope{
		Version:   envelopeVersion,
		Algorithm: algorithm,
		Nonce:     base64.StdEncoding.EncodeToString(nonce),
		Data:      base64.StdEncoding.EncodeToString(sealed),
	})
}

func (s *Store) decrypt(key string, data []byte) ([]byte, error) {
	var env envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, err
	}
	if env.Version != envelopeVersion || env.Algorithm != algorithm {
		return nil, errors.New("credential: unsupported record format")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, err
	}
	sealed, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		return nil, err
	}
	master, err := s.masterKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, sealed, additionalData(key))
}

func additionalData(key string) []byte {
	return []byte("bypath-credentials-v1:" + key)
}

// masterKey lazily loads or creates the 32-byte encryption key.
func (s *Store) masterKey() ([]byte, error) {
	s.keyOnce.Do(func() {
		path := filepath.Join(s.persistentDir, "master.key")
		if data, err := os.ReadFile(path); err == nil {
			if len(data) != masterKeySize {
				s.keyErr = errors.New("credential: master key has an unexpected size")
				return
			}
			s.key = data
			return
		}
		if err := securefile.MkdirAll(s.persistentDir); err != nil {
			s.keyErr = fmt.Errorf("credential: creating store directory: %w", err)
			return
		}
		key := make([]byte, masterKeySize)
		if _, err := rand.Read(key); err != nil {
			s.keyErr = fmt.Errorf("credential: generating master key: %w", err)
			return
		}
		if err := securefile.WriteFileExclusive(path, key); err != nil {
			// Another process won the race; read its key instead of failing.
			if data, readErr := os.ReadFile(path); readErr == nil && len(data) == masterKeySize {
				s.key = data
				return
			}
			s.keyErr = fmt.Errorf("credential: writing master key: %w", err)
			return
		}
		s.key = key
	})
	return s.key, s.keyErr
}
