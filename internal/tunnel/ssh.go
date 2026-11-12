package tunnel

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
)

// SSHCommand is one resolved child process for a dynamic SSH tunnel. Env holds
// extra environment entries (currently the sshpass secret) that must be added
// to the inherited environment; the secret never appears in Args.
type SSHCommand struct {
	Binary string
	Args   []string
	Env    []string
}

// SSHOptions carries the daemon-wide SSH client policy. Zero values select the
// safe defaults: loopback listener, accept-new host keys, Bypath-owned
// known_hosts.
type SSHOptions struct {
	SSHPath     string // resolved ssh binary
	SSHPassPath string // resolved sshpass binary; empty when unavailable
	ListenAddr  string // SOCKS bind address; empty means 127.0.0.1
	ListenPort  int
	KnownHosts  string // Bypath-owned known_hosts file; empty uses the default
	HostKey     string // config.SSHHostKey*; empty means accept-new
}

// DefaultSSHKnownHosts returns the host-key store the daemon manages itself.
// It lives next to the configuration rather than in /dev/null so a host key
// change is detected instead of silently accepted.
func DefaultSSHKnownHosts() string {
	path := filepath.Join(paths.Get().DataDir, "ssh_known_hosts")
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// EnsureSSHKnownHosts creates the parent directory and an empty known_hosts
// file when they do not exist. The file is not secret (it holds public host
// keys) but the daemon creates it with restrictive permissions anyway.
func EnsureSSHKnownHosts(path string) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("ssh known_hosts directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("ssh known_hosts: %w", err)
	}
	return f.Close()
}

// BuildSSHCommand builds the OpenSSH invocation for a -D (dynamic SOCKS)
// tunnel. It is the single source of truth for both the daemon and the bench
// command so the child arguments under test are the child arguments that run.
//
// A password link must not offer any other identity. The daemon runs as root,
// so an unqualified ssh would try /root/.ssh/id_*, the root SSH agent, and any
// keys named in /etc/ssh/ssh_config. IdentitiesOnly plus IdentityFile=none and
// PubkeyAuthentication=no pin the child to the password. A key link keeps
// IdentitiesOnly so the agent and default keys are not offered next to the
// explicit -i. A link with neither credential is refused: authenticating it
// would mean offering the daemon's own (root) identities, so the operator must
// name a key or a password explicitly.
func BuildSSHCommand(link *profile.Link, opts SSHOptions) (SSHCommand, error) {
	if link == nil {
		return SSHCommand{}, fmt.Errorf("ssh: nil link")
	}
	if opts.SSHPath == "" {
		return SSHCommand{}, fmt.Errorf("ssh: binary path is required")
	}

	listenAddr := strings.TrimSpace(opts.ListenAddr)
	if listenAddr == "" {
		listenAddr = "127.0.0.1"
	}
	if listenAddr != "localhost" && net.ParseIP(strings.Trim(listenAddr, "[]")) == nil {
		return SSHCommand{}, fmt.Errorf("ssh: listen address %q is not an IP address", listenAddr)
	}
	listenPort := opts.ListenPort
	if listenPort < 1 || listenPort > 65535 {
		return SSHCommand{}, fmt.Errorf("ssh: listen port %d is out of range", listenPort)
	}

	sshPort := link.Port
	if sshPort == 0 {
		sshPort = 22
	}
	sshUser := link.SSHUser
	if sshUser == "" {
		sshUser = "root"
	}

	knownHosts := strings.TrimSpace(opts.KnownHosts)
	if knownHosts == "" {
		knownHosts = DefaultSSHKnownHosts()
	}

	args := []string{
		"-D", net.JoinHostPort(listenAddr, strconv.Itoa(listenPort)),
		"-N",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=3",
		"-o", "ForwardAgent=no",
	}
	if ip := net.ParseIP(strings.Trim(listenAddr, "[]")); ip != nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsUnspecified() {
		args = append(args, "-D", net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort)))
	}
	args = append(args, "-o", "ExitOnForwardFailure=yes")
	args = append(args, hostKeyOptions(opts.HostKey, knownHosts)...)

	passwordAuth := link.SSHKeyPath == "" && link.SSHPassword != ""
	switch {
	case link.SSHKeyPath != "":
		// IdentitiesOnly limits the offer to this key, but leaves the agent
		// available to sign with it so a passphrase-protected key still works.
		args = append(args,
			"-i", link.SSHKeyPath,
			"-o", "IdentitiesOnly=yes",
			"-o", "BatchMode=yes",
		)
	case passwordAuth:
		args = append(args,
			"-o", "IdentitiesOnly=yes",
			"-o", "IdentityFile=none",
			"-o", "IdentityAgent=none",
			"-o", "PubkeyAuthentication=no",
			"-o", "PreferredAuthentications=password,keyboard-interactive",
			"-o", "BatchMode=no",
		)
	default:
		return SSHCommand{}, fmt.Errorf("ssh link %s@%s has no key or password: refusing to offer the daemon's default identities; add a key (?key=<path>) or a password", sshUser, link.Address)
	}

	args = append(args,
		"-p", strconv.Itoa(sshPort),
		fmt.Sprintf("%s@%s", sshUser, link.Address),
	)

	if passwordAuth {
		if opts.SSHPassPath == "" {
			return SSHCommand{}, fmt.Errorf("sshpass not found: password auth requires sshpass (install it or use key-based auth)")
		}
		// -e reads the password from SSHPASS instead of argv, so it is not
		// exposed to every local user through ps.
		return SSHCommand{
			Binary: opts.SSHPassPath,
			Args:   append([]string{"-e", opts.SSHPath}, args...),
			Env:    []string{"SSHPASS=" + link.SSHPassword},
		}, nil
	}
	return SSHCommand{Binary: opts.SSHPath, Args: args}, nil
}

// hostKeyOptions maps the configured policy onto OpenSSH options. The explicit
// "off" value is the only path that disables verification; it still records
// host keys in the Bypath store so an operator can audit what was accepted.
func hostKeyOptions(policy, knownHosts string) []string {
	mode := "accept-new"
	switch strings.TrimSpace(policy) {
	case config.SSHHostKeyStrict:
		mode = "yes"
	case config.SSHHostKeyOff:
		mode = "no"
	}
	return []string{
		"-o", "StrictHostKeyChecking=" + mode,
		"-o", "UserKnownHostsFile=" + knownHosts,
	}
}
