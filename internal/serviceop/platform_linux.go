//go:build linux

package serviceop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/profile"
)

// Command is injectable for regression tests; no request can supply a command.
var Command = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func platformBackend() Backend {
	return Backend{Authorize: authorize, Launch: launch, Restart: restart, Verify: verify, BootID: bootID}
}
func bootID() string {
	b, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	return strings.TrimSpace(string(b))
}
func securePath(path string, dir bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("unsafe non-absolute path")
	}
	for p := path; ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || fi.Mode()&0022 != 0 || fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path must be root-owned, non-symlink and not writable by other users: %s", p)
		}
		if p == path && dir != fi.IsDir() {
			return errors.New("unexpected path type")
		}
		if p == "/" {
			break
		}
	}
	return nil
}
func privatePath(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0077 != 0 {
		return errors.New("service job state must be root-only")
	}
	return nil
}

func WorkerAllowed() error {
	if os.Geteuid() != 0 || !workerAlive() {
		return ErrUnsupported
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	b, err := Command(ctx, "/usr/bin/systemctl", "show", "bypath-service-worker.service", "--property=MainPID", "--value")
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid != os.Getpid() {
		return ErrUnsupported
	}
	return nil
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
func installedIdentity(ctx context.Context) (int, string, []string, error) {
	if os.Geteuid() != 0 {
		return 0, "", nil, ErrUnsupported
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return 0, "", nil, ErrUnsupported
	}
	b, err := Command(ctx, "/usr/bin/systemctl", "show", "bypath.service", "--property=MainPID,ExecStart,FragmentPath,User", "--no-pager")
	if err != nil {
		return 0, "", nil, ErrUnsupported
	}
	props := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			props[k] = v
		}
	}
	pid, err := strconv.Atoi(props["MainPID"])
	if err != nil || pid < 2 {
		return 0, "", nil, ErrUnsupported
	}
	if props["User"] != "" && props["User"] != "root" {
		return 0, "", nil, ErrUnsupported
	}
	fragment := props["FragmentPath"]
	if !(strings.HasPrefix(fragment, "/etc/systemd/system/") || strings.HasPrefix(fragment, "/usr/lib/systemd/system/") || strings.HasPrefix(fragment, "/lib/systemd/system/")) {
		return 0, "", nil, ErrUnsupported
	}
	// Resolve distro aliases once, then verify every ownership boundary.
	fragment, err = filepath.EvalSymlinks(fragment)
	if err != nil {
		return 0, "", nil, ErrUnsupported
	}
	if err = securePath(fragment, false); err != nil {
		return 0, "", nil, ErrUnsupported
	}
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return 0, "", nil, ErrUnsupported
	}
	if err = securePath(exe, false); err != nil {
		return 0, "", nil, ErrUnsupported
	}
	self, err := os.Executable()
	if err != nil {
		return 0, "", nil, ErrUnsupported
	}
	self, err = filepath.EvalSymlinks(self)
	if err != nil || self != exe {
		return 0, "", nil, ErrUnsupported
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return 0, "", nil, ErrUnsupported
	}
	args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	if len(args) != 2 && len(args) != 4 {
		return 0, "", nil, ErrUnsupported
	}
	if args[1] != "run" && args[1] != "start" {
		return 0, "", nil, ErrUnsupported
	}
	if len(args) == 4 && args[2] != "-c" && args[2] != "--config" {
		return 0, "", nil, ErrUnsupported
	}
	start := props["ExecStart"]
	if strings.Count(start, "path=") != 1 || !strings.Contains(start, "path="+exe+" ;") || !strings.Contains(start, "argv[]="+strings.Join(args, " ")+" ;") {
		return 0, "", nil, ErrUnsupported
	}
	return pid, exe, args, nil
}
func authorize(ctx context.Context, path string) (int, string, error) {
	pid, exe, args, err := installedIdentity(ctx)
	if err != nil || pid != os.Getpid() {
		return 0, "", ErrUnsupported
	}
	if len(args) == 4 {
		p, e := filepath.Abs(args[3])
		if e != nil || p != path {
			return 0, "", ErrUnsupported
		}
	}
	if err = securePath(path, false); err != nil {
		return 0, "", ErrUnsupported
	}
	return pid, exe, nil
}
func launch(ctx context.Context, exe string) error {
	if workerAlive() {
		return ErrBusy
	}
	_, err := Command(ctx, "/usr/bin/systemd-run", "--unit=bypath-service-worker", "--collect", "--service-type=exec", "--property=Restart=on-failure", "--property=RestartSec=1s", "--property=RuntimeMaxSec=15min", "--property=TimeoutStopSec=10s", exe, "service-worker")
	return err
}
func workerAlive() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	b, err := Command(ctx, "/usr/bin/systemctl", "show", "bypath-service-worker.service", "--property=MainPID", "--value")
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid < 2 {
		return false
	}
	exe, e := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	self, _ := os.Executable()
	self, _ = filepath.EvalSymlinks(self)
	args, a := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	return e == nil && a == nil && exe == self && strings.TrimRight(string(args), "\x00") == exe+"\x00service-worker"
}
func restart(ctx context.Context) error {
	_, err := Command(ctx, "/usr/bin/systemctl", "reset-failed", "bypath.service")
	if err != nil {
		return err
	}
	_, err = Command(ctx, "/usr/bin/systemctl", "restart", "bypath.service")
	return err
}
func verify(ctx context.Context, j Job, rollback bool) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		pid, exe, _, err := installedIdentity(ctx)
		if err == nil && exe == j.Executable && pid != j.DaemonPID {
			// Enter only the validated daemon's network namespace. Filesystem/socket
			// identity stays shared; no shell or caller-selected executable is involved.
			_, err = Command(ctx, "/usr/bin/nsenter", "--target", strconv.Itoa(pid), "--net", "--", exe, "service-worker", "verify")
			if err == nil {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// VerifyWorker is a fixed internal command, invoked inside the new daemon's
// namespace. HTTPS is fetched with remote DNS over SOCKS, never direct fallback.
func VerifyWorker() error {
	m := New()
	j, err := m.load()
	if err != nil {
		return err
	}
	if !Pending(j.State) {
		return errors.New("no pending operation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	pid, _, _, err := installedIdentity(ctx)
	if err != nil {
		return err
	}
	ns, _ := os.Readlink("/proc/self/ns/net")
	target, _ := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	if ns == "" || ns != target {
		return ErrUnsupported
	}
	cfg, err := config.Load(j.ConfigPath)
	if err != nil {
		return err
	}
	expectedBytes := j.ProposedConfig
	if j.Recovering { expectedBytes = j.OldConfig }
	expected, err := config.Parse(expectedBytes); if err != nil { return err }
	if err = expected.NormalizeAndValidate(); err != nil { return err }
	if !reflect.DeepEqual(cfg, expected) { return errors.New("configuration changed during service verification") }
	// The control socket authenticates via existing root-owned socket permissions.
	// Querying it does not expose a token on the command line or in the journal.
	if err = verifyStatus(ctx, j, cfg); err != nil {
		return err
	}
	body, err := profile.FetchThroughProxy(ctx, cfg.Server.SOCKSPort, "https://api.ipify.org", 128)
	if err != nil {
		return err
	}
	if net.ParseIP(strings.TrimSpace(string(body))) == nil {
		return errors.New("HTTPS returned no exit IP")
	}
	return nil
}
