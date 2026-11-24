package serviceop

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"gopkg.in/yaml.v3"
)

var checkPath = securePath

func CheckRootPath(path string, dir bool) error { return securePath(path, dir) }

const StateDir = "/var/lib/bypath/service-operation"
const Budget = 6 * time.Minute

var ErrUnsupported = errors.New("service operations require the root installed bypath.service systemd daemon")
var ErrBusy = errors.New("a service operation is already pending")
var ErrNotFound = errors.New("operation not found")

type Operation struct {
	ID               string `json:"id"`
	State            string `json:"state"`
	Message          string `json:"message"`
	OldEndpoint      string `json:"old_endpoint"`
	ProposedEndpoint string `json:"proposed_endpoint"`
}

type Job struct {
	Operation
	Created        time.Time
	Boot           string
	ConfigPath     string
	ActivePath     string
	OldConfig      []byte
	OldActive      []byte
	ActiveExists   bool
	ProposedConfig []byte
	ServingID      string
	SelectedID     string
	DaemonPID      int
	Executable     string
	ControlSocket  string
	Recovering     bool
}

// Backend hooks are intentionally not request fields. Only the daemon binds them.
type Backend struct {
	Authorize func(context.Context, string) (int, string, error)
	Launch    func(context.Context, string) error
	Restart   func(context.Context) error
	Verify    func(context.Context, Job, bool) error
	BootID    func() string
}

type Manager struct {
	Dir     string
	Backend Backend
	mu      sync.Mutex
}

func New() *Manager { return &Manager{Dir: StateDir, Backend: platformBackend()} }
func (m *Manager) Supported(ctx context.Context, path string) (bool, string) {
	if m.Backend.Authorize == nil {
		return false, ErrUnsupported.Error()
	}
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, _, err := m.Backend.Authorize(c, path); err != nil {
		return false, err.Error()
	}
	return true, ""
}
func Endpoint(s config.ServerConfig) string {
	return fmt.Sprintf("%s:%d", s.SOCKSListenAddress(), s.SOCKSPort)
}
func Pending(state string) bool { return state == "queued" || state == "restarting" }
func (m *Manager) load() (Job, error) {
	var j Job
	if err := checkPath(m.Dir, true); err != nil {
		return j, err
	}
	if err := privatePath(m.Dir); err != nil {
		return j, err
	}
	path := filepath.Join(m.Dir, "job.json")
	if err := checkPath(path, false); err != nil {
		return j, err
	}
	if err := privatePath(path); err != nil {
		return j, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return j, err
	}
	err = json.Unmarshal(b, &j)
	return j, err
}
func (m *Manager) save(j Job) error {
	if err := os.MkdirAll(m.Dir, 0700); err != nil {
		return err
	}
	if err := checkPath(m.Dir, true); err != nil {
		return err
	}
	if err := privatePath(m.Dir); err != nil {
		return err
	}
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return AtomicWrite(filepath.Join(m.Dir, "job.json"), b)
}
func (m *Manager) Get(id string) (Operation, error) {
	if len(id) != 32 {
		return Operation{}, ErrNotFound
	}
	if _, err := hex.DecodeString(id); err != nil {
		return Operation{}, ErrNotFound
	}
	j, err := m.load()
	if err != nil || j.ID != id {
		return Operation{}, ErrNotFound
	}
	return j.Operation, nil
}
func (m *Manager) Busy() bool { j, err := m.load(); return err == nil && Pending(j.State) }
func (m *Manager) Queue(ctx context.Context, cfgPath, activePath, socket, serving, selected string, proposed *config.Config) (Operation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pid, exe, err := m.Backend.Authorize(ctx, cfgPath)
	if err != nil {
		return Operation{}, err
	}
	if m.Busy() {
		return Operation{}, ErrBusy
	}
	if err = checkPath(cfgPath, false); err != nil {
		return Operation{}, err
	}
	if err = checkPath(filepath.Dir(activePath), true); err != nil {
		return Operation{}, err
	}
	old, err := os.ReadFile(cfgPath)
	if err != nil {
		return Operation{}, err
	}
	cfg, err := config.Parse(old)
	if err != nil {
		return Operation{}, err
	}
	if proposed == nil {
		proposed = cfg
	}
	if err = proposed.NormalizeAndValidate(); err != nil {
		return Operation{}, err
	}
	staged, err := yaml.Marshal(proposed)
	if err != nil {
		return Operation{}, err
	}
	active, err := os.ReadFile(activePath)
	exists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return Operation{}, err
	}
	if exists {
		if err = checkPath(activePath, false); err != nil {
			return Operation{}, err
		}
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		return Operation{}, err
	}
	j := Job{Operation: Operation{ID: hex.EncodeToString(id[:]), State: "queued", Message: "Service operation queued; verification is pending.", OldEndpoint: Endpoint(cfg.Server), ProposedEndpoint: Endpoint(proposed.Server)}, Created: time.Now(), Boot: m.Backend.BootID(), ConfigPath: cfgPath, ActivePath: activePath, OldConfig: old, OldActive: active, ActiveExists: exists, ProposedConfig: staged, ServingID: serving, SelectedID: selected, DaemonPID: pid, Executable: exe, ControlSocket: socket}
	// Journal precedes staging: even a crash between these writes is recoverable.
	if err = m.save(j); err != nil {
		return Operation{}, err
	}
	if err = AtomicWrite(cfgPath, staged); err != nil {
		restoreErr := m.restore(j)
		j.State, j.Message = "rolled_back", "Staging failed; previous configuration and selection restored."
		if restoreErr != nil { j.State, j.Message, j.Recovering = "restarting", "Staging interrupted; independent recovery required.", true }
		_ = m.save(j)
		if restoreErr != nil { c, cancel := context.WithTimeout(context.Background(), 10*time.Second); _ = m.Backend.Launch(c, exe); cancel() }
		return j.Operation, err
	}
	launchCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = m.Backend.Launch(launchCtx, exe); err != nil {
		restoreErr := m.restore(j)
		j.State = "failed"
		j.Message = "Independent worker could not start."
		if restoreErr == nil {
			j.State = "rolled_back"
			j.Message = "Worker could not start; previous configuration and selection restored."
		}
		_ = m.save(j)
		return j.Operation, err
	}
	return j.Operation, nil
}
func (m *Manager) restore(j Job) error {
	if err := AtomicWrite(j.ConfigPath, j.OldConfig); err != nil {
		return err
	}
	if j.ActiveExists {
		return AtomicWrite(j.ActivePath, j.OldActive)
	}
	err := os.Remove(j.ActivePath)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// RecoverBeforeLoad runs before parsing config, including after a reboot. A live
// independent worker owns an ordinary same-boot restart; all other interruptions
// restore the journal before the daemon can start an unverified data path.
func (m *Manager) RecoverBeforeLoad(path string) error {
	j, err := m.load()
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !Pending(j.State) || j.ConfigPath != path {
		return nil
	}
	if j.Boot == m.Backend.BootID() && workerAlive() {
		return nil
	}
	if err = m.restore(j); err != nil {
		return err
	}
	j.Recovering = true
	j.State = "restarting"
	j.Message = "Interrupted operation restored; verifying recovery."
	return m.save(j)
}
func (m *Manager) ResumeRecovery(ctx context.Context) error {
	j, err := m.load()
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !j.Recovering {
		return nil
	}
	_, exe, err := m.Backend.Authorize(ctx, j.ConfigPath)
	if err != nil {
		return err
	}
	return m.Backend.Launch(ctx, exe)
}
func (m *Manager) Run() error {
	j, err := m.load()
	if err != nil {
		return err
	}
	if !Pending(j.State) {
		return nil
	}
	// A restarted worker never retries the candidate: its last command may have
	// completed before it died. Recover the previous bytes with a fresh context.
	recovery := j.State == "restarting" || j.Boot != m.Backend.BootID() || j.Recovering
	if !recovery {
		delay := time.Until(j.Created.Add(time.Second))
		if delay > 0 {
			time.Sleep(delay)
		}
		j.State = "restarting"
		j.Message = "Restarting bypath.service; verifying tunneled HTTPS."
		if err = m.save(j); err != nil {
			return err
		}
		c, cancel := context.WithTimeout(context.Background(), Budget)
		err = m.Backend.Restart(c)
		if err == nil {
			err = m.Backend.Verify(c, j, false)
		}
		cancel()
		if err == nil {
			j.State = "serving"
			j.Message = "Service is serving the preserved connection; tunneled HTTPS verified."
			return m.save(j)
		}
	}
	j.State = "restarting"
	if err = m.restore(j); err != nil {
		j.State = "failed"
		j.Message = "Previous configuration could not be restored."
		_ = m.save(j)
		return err
	}
	j.Recovering = true
	j.Message = "Previous configuration and selection restored; restarting for recovery verification."
	if err = m.save(j); err != nil { return err }
	c, cancel := context.WithTimeout(context.Background(), Budget)
	defer cancel()
	err = m.Backend.Restart(c)
	if err == nil {
		err = m.Backend.Verify(c, j, true)
	}
	j.State = "rolled_back"
	j.Recovering = false
	j.Message = "Previous configuration and selection restored; tunneled HTTPS verified."
	if err != nil {
		j.State = "failed"
		j.Message = "Previous configuration restored, but recovery could not verify serving HTTPS."
	}
	if saveErr := m.save(j); saveErr != nil {
		return saveErr
	}
	return nil
}

func AtomicWrite(path string, b []byte) error {
	if err := checkPath(filepath.Dir(path), true); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err = checkPath(path, false); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".service-op-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = renameAtomic(f.Name(), path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}
