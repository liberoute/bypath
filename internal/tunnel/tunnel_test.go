package tunnel

import (
	"testing"

	"github.com/liberoute/bypath/internal/profile"
)

// sshFor builds the production SSH child command with test defaults.
func sshFor(t *testing.T, link *profile.Link, tune func(*SSHOptions)) SSHCommand {
	t.Helper()
	opts := SSHOptions{
		SSHPath:     "/usr/bin/ssh",
		SSHPassPath: "/usr/bin/sshpass",
		ListenAddr:  "127.0.0.1",
		ListenPort:  10800,
		KnownHosts:  "/etc/bypath/ssh_known_hosts",
	}
	if tune != nil {
		tune(&opts)
	}
	cmd, err := BuildSSHCommand(link, opts)
	if err != nil {
		t.Fatalf("BuildSSHCommand: %v", err)
	}
	return cmd
}

func TestSSHCommandConstruction_KeyBased(t *testing.T) {
	link := &profile.Link{
		Protocol:   "ssh",
		Address:    "relay.example.com",
		Port:       2222,
		SSHUser:    "deploy",
		SSHKeyPath: "/etc/bypath/keys/id_rsa",
	}

	cmd := sshFor(t, link, nil)

	if cmd.Binary != "/usr/bin/ssh" {
		t.Errorf("binary: got %q, want %q", cmd.Binary, "/usr/bin/ssh")
	}

	assertContainsSequence(t, cmd.Args, "-D", "127.0.0.1:10800")
	assertContains(t, cmd.Args, "-N")
	assertContainsSequence(t, cmd.Args, "-o", "StrictHostKeyChecking=accept-new")
	assertContainsSequence(t, cmd.Args, "-o", "UserKnownHostsFile=/etc/bypath/ssh_known_hosts")
	assertContainsSequence(t, cmd.Args, "-o", "ServerAliveInterval=30")
	assertContainsSequence(t, cmd.Args, "-o", "ServerAliveCountMax=3")
	assertContainsSequence(t, cmd.Args, "-o", "ForwardAgent=no")
	assertContainsSequence(t, cmd.Args, "-i", "/etc/bypath/keys/id_rsa")
	assertContainsSequence(t, cmd.Args, "-o", "IdentitiesOnly=yes")
	assertContainsSequence(t, cmd.Args, "-p", "2222")
	assertContains(t, cmd.Args, "deploy@relay.example.com")
	assertNotContains(t, cmd.Args, "IdentityFile=none")
	assertNotContains(t, cmd.Args, "PubkeyAuthentication=no")
}

func TestSSHCommandConstruction_PasswordBased(t *testing.T) {
	link := &profile.Link{
		Protocol:    "ssh",
		Address:     "10.0.0.1",
		Port:        22,
		SSHUser:     "admin",
		SSHPassword: "hunter2",
	}

	cmd := sshFor(t, link, func(o *SSHOptions) { o.ListenPort = 10801 })

	if cmd.Binary != "/usr/bin/sshpass" {
		t.Errorf("binary: got %q, want %q", cmd.Binary, "/usr/bin/sshpass")
	}

	// sshpass reads the secret from the environment so it does not appear in
	// argv (visible to every local user through ps).
	if len(cmd.Args) < 3 {
		t.Fatalf("expected at least 3 args, got %d", len(cmd.Args))
	}
	if cmd.Args[0] != "-e" || cmd.Args[1] != "/usr/bin/ssh" {
		t.Fatalf("sshpass prefix = %v, want [-e /usr/bin/ssh ...]", cmd.Args[:2])
	}
	if len(cmd.Env) != 1 || cmd.Env[0] != "SSHPASS=hunter2" {
		t.Fatalf("sshpass env = %v, want [SSHPASS=hunter2]", cmd.Env)
	}
	for _, a := range cmd.Args {
		if a == "hunter2" {
			t.Fatal("password leaked into argv")
		}
	}

	assertContainsSequence(t, cmd.Args, "-D", "127.0.0.1:10801")
	assertContains(t, cmd.Args, "-N")
	assertContainsSequence(t, cmd.Args, "-o", "StrictHostKeyChecking=accept-new")
	assertContainsSequence(t, cmd.Args, "-o", "UserKnownHostsFile=/etc/bypath/ssh_known_hosts")
	assertContainsSequence(t, cmd.Args, "-p", "22")
	assertContains(t, cmd.Args, "admin@10.0.0.1")

	// A password link must not offer root's keys or agent identities.
	assertContainsSequence(t, cmd.Args, "-o", "IdentitiesOnly=yes")
	assertContainsSequence(t, cmd.Args, "-o", "IdentityFile=none")
	assertContainsSequence(t, cmd.Args, "-o", "IdentityAgent=none")
	assertContainsSequence(t, cmd.Args, "-o", "PubkeyAuthentication=no")
	assertContainsSequence(t, cmd.Args, "-o", "PreferredAuthentications=password,keyboard-interactive")
	assertNotContains(t, cmd.Args, "-i")
}

func TestSSHCommandConstruction_DefaultPortAndUser(t *testing.T) {
	link := &profile.Link{
		Protocol:   "ssh",
		Address:    "host.example.com",
		Port:       0,  // should default to 22
		SSHUser:    "", // should default to "root"
		SSHKeyPath: "/keys/default_key",
	}

	cmd := sshFor(t, link, func(o *SSHOptions) { o.ListenPort = 2801 })

	if cmd.Binary != "/usr/bin/ssh" {
		t.Errorf("binary: got %q, want %q", cmd.Binary, "/usr/bin/ssh")
	}
	assertContainsSequence(t, cmd.Args, "-p", "22")
	assertContains(t, cmd.Args, "root@host.example.com")
	assertContainsSequence(t, cmd.Args, "-D", "127.0.0.1:2801")
}

// TestSSHCommandHostKeyPolicy proves that only an explicit "off" disables
// verification; the default pins the key and "strict" rejects unknown hosts.
func TestSSHCommandHostKeyPolicy(t *testing.T) {
	link := &profile.Link{Protocol: "ssh", Address: "h", SSHKeyPath: "/k"}
	cases := map[string]string{
		"":           "accept-new",
		"accept-new": "accept-new",
		"strict":     "yes",
		"off":        "no",
	}
	for policy, want := range cases {
		cmd := sshFor(t, link, func(o *SSHOptions) { o.HostKey = policy })
		assertContainsSequence(t, cmd.Args, "-o", "StrictHostKeyChecking="+want)
	}
}

// TestSSHCommandLANListener covers the explicit LAN opt-in: the same builder
// must emit the configured bind address instead of silently forcing loopback.
func TestSSHCommandLANListener(t *testing.T) {
	link := &profile.Link{Protocol: "ssh", Address: "h", SSHKeyPath: "/k"}
	cmd := sshFor(t, link, func(o *SSHOptions) { o.ListenAddr = "0.0.0.0" })
	assertContainsSequence(t, cmd.Args, "-D", "0.0.0.0:10800")
}

// TestSSHCommandNoCredentials proves a link without a key or password is
// refused: authenticating it would mean offering the daemon's own identities.
func TestSSHCommandNoCredentials(t *testing.T) {
	link := &profile.Link{Protocol: "ssh", Address: "h"}
	if _, err := BuildSSHCommand(link, SSHOptions{SSHPath: "/usr/bin/ssh", ListenPort: 10800}); err == nil {
		t.Fatal("a credential-less SSH link was accepted")
	}
}

func TestSSHCommandRejectsBadInput(t *testing.T) {
	link := &profile.Link{Protocol: "ssh", Address: "h", SSHPassword: "x"}
	if _, err := BuildSSHCommand(link, SSHOptions{SSHPath: "/usr/bin/ssh", ListenPort: 10800}); err == nil {
		t.Fatal("password link without sshpass was accepted")
	}
	if _, err := BuildSSHCommand(link, SSHOptions{SSHPath: "/usr/bin/ssh", SSHPassPath: "/usr/bin/sshpass", ListenAddr: "relay.example.com", ListenPort: 10800}); err == nil {
		t.Fatal("hostname listen address was accepted")
	}
	if _, err := BuildSSHCommand(link, SSHOptions{SSHPath: "/usr/bin/ssh", SSHPassPath: "/usr/bin/sshpass", ListenPort: 0}); err == nil {
		t.Fatal("port 0 was accepted")
	}
	if _, err := BuildSSHCommand(nil, SSHOptions{SSHPath: "/usr/bin/ssh"}); err == nil {
		t.Fatal("nil link was accepted")
	}
}

// --- Test helpers ---

func assertContains(t *testing.T, args []string, expected string) {
	t.Helper()
	for _, a := range args {
		if a == expected {
			return
		}
	}
	t.Errorf("args %v does not contain %q", args, expected)
}

func assertNotContains(t *testing.T, args []string, unexpected string) {
	t.Helper()
	for _, a := range args {
		if a == unexpected {
			t.Errorf("args %v should not contain %q", args, unexpected)
			return
		}
	}
}

func assertContainsSequence(t *testing.T, args []string, first, second string) {
	t.Helper()
	for i := 0; i < len(args)-1; i++ {
		if args[i] == first && args[i+1] == second {
			return
		}
	}
	t.Errorf("args %v does not contain sequence [%q, %q]", args, first, second)
}
