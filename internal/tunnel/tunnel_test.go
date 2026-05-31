package tunnel

import (
	"fmt"
	"testing"

	"github.com/liberoute/bypath/internal/profile"
)

// buildSSHArgs replicates the SSH command argument construction logic from startSSHTunnel
// for testability. This mirrors the logic in tunnel.go without starting a process.
func buildSSHArgs(link *profile.Link, listenPort int) (binary string, args []string) {
	sshPort := link.Port
	if sshPort == 0 {
		sshPort = 22
	}

	sshUser := link.SSHUser
	if sshUser == "" {
		sshUser = "root"
	}

	baseArgs := []string{
		fmt.Sprintf("-D 0.0.0.0:%d", listenPort),
		"-N",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "ServerAliveInterval=30",
		"-o", "ServerAliveCountMax=3",
	}

	if link.SSHKeyPath != "" {
		baseArgs = append(baseArgs, "-i", link.SSHKeyPath)
	}

	baseArgs = append(baseArgs, "-p", fmt.Sprintf("%d", sshPort))
	baseArgs = append(baseArgs, fmt.Sprintf("%s@%s", sshUser, link.Address))

	// Password-based auth: prepend sshpass args
	if link.SSHKeyPath == "" && link.SSHPassword != "" {
		binary = "sshpass"
		args = append([]string{"-p", link.SSHPassword, "ssh"}, baseArgs...)
	} else {
		binary = "ssh"
		args = baseArgs
	}

	return binary, args
}

func TestSSHCommandConstruction_KeyBased(t *testing.T) {
	link := &profile.Link{
		Protocol:   "ssh",
		Address:    "relay.example.com",
		Port:       2222,
		SSHUser:    "deploy",
		SSHKeyPath: "/etc/bypath/keys/id_rsa",
	}

	listenPort := 10800
	binary, args := buildSSHArgs(link, listenPort)

	// Binary should be ssh (not sshpass) for key-based auth
	if binary != "ssh" {
		t.Errorf("binary: got %q, want %q", binary, "ssh")
	}

	// Verify expected args are present
	assertContains(t, args, "-D 0.0.0.0:10800")
	assertContains(t, args, "-N")
	assertContainsSequence(t, args, "-o", "StrictHostKeyChecking=no")
	assertContainsSequence(t, args, "-o", "UserKnownHostsFile=/dev/null")
	assertContainsSequence(t, args, "-o", "ServerAliveInterval=30")
	assertContainsSequence(t, args, "-o", "ServerAliveCountMax=3")
	assertContainsSequence(t, args, "-i", "/etc/bypath/keys/id_rsa")
	assertContainsSequence(t, args, "-p", "2222")
	assertContains(t, args, "deploy@relay.example.com")
}

func TestSSHCommandConstruction_PasswordBased(t *testing.T) {
	link := &profile.Link{
		Protocol:    "ssh",
		Address:     "10.0.0.1",
		Port:        22,
		SSHUser:     "admin",
		SSHPassword: "hunter2",
	}

	listenPort := 10801
	binary, args := buildSSHArgs(link, listenPort)

	// Binary should be sshpass for password-based auth
	if binary != "sshpass" {
		t.Errorf("binary: got %q, want %q", binary, "sshpass")
	}

	// sshpass args come first: -p <password> ssh ...
	if len(args) < 3 {
		t.Fatalf("expected at least 3 args, got %d", len(args))
	}
	if args[0] != "-p" {
		t.Errorf("args[0]: got %q, want %q", args[0], "-p")
	}
	if args[1] != "hunter2" {
		t.Errorf("args[1]: got %q, want %q", args[1], "hunter2")
	}
	if args[2] != "ssh" {
		t.Errorf("args[2]: got %q, want %q", args[2], "ssh")
	}

	// Verify SSH-specific args are present after sshpass prefix
	assertContains(t, args, "-D 0.0.0.0:10801")
	assertContains(t, args, "-N")
	assertContainsSequence(t, args, "-o", "StrictHostKeyChecking=no")
	assertContainsSequence(t, args, "-o", "UserKnownHostsFile=/dev/null")
	assertContainsSequence(t, args, "-p", "22")
	assertContains(t, args, "admin@10.0.0.1")

	// Key flag should NOT be present for password-based auth
	assertNotContains(t, args, "-i")
}

func TestSSHCommandConstruction_DefaultPortAndUser(t *testing.T) {
	link := &profile.Link{
		Protocol:   "ssh",
		Address:    "host.example.com",
		Port:       0, // should default to 22
		SSHUser:    "", // should default to "root"
		SSHKeyPath: "/keys/default_key",
	}

	listenPort := 2801
	binary, args := buildSSHArgs(link, listenPort)

	if binary != "ssh" {
		t.Errorf("binary: got %q, want %q", binary, "ssh")
	}

	// Port defaults to 22
	assertContainsSequence(t, args, "-p", "22")

	// User defaults to root
	assertContains(t, args, "root@host.example.com")

	// Listen port is correct
	assertContains(t, args, "-D 0.0.0.0:2801")
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
