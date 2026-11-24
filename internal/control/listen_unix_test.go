//go:build !windows

package control

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestListenCreatesOwnerOnlySocketForUnprivilegedDaemon(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "control", "control.sock")

	ln, err := Listen(path, "")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	wantSocket, wantDir := os.FileMode(0600), os.FileMode(0700)
	if os.Geteuid() == 0 {
		if _, ok := groupGID(); ok {
			wantSocket, wantDir = 0660, 0750
		}
	}
	if got := st.Mode().Perm(); got != wantSocket {
		t.Fatalf("socket mode = %o, want %o", got, wantSocket)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != wantDir {
		t.Fatalf("socket directory mode = %o, want %o", got, wantDir)
	}
}

// A root daemon's runtime root is created owner-only because it also holds
// engine secrets. Without search on that directory the group can never reach a
// correctly permissioned socket, so Listen has to widen just that bit.
func TestListenGrantsGroupSearchToRuntimeRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("group traversal is only granted by a root daemon")
	}
	gid, ok := groupGID()
	if !ok {
		t.Skipf("control group %q is not present", GroupName)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "bypath-control", "control.sock")

	ln, err := Listen(path, root)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm&0o010 == 0 {
		t.Fatalf("runtime root mode = %o, group search missing", perm)
	}
	if perm&0o004 != 0 {
		t.Fatalf("runtime root mode = %o, gained read access", perm)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Gid) != gid {
		t.Fatalf("runtime root group = %v, want %d", info.Sys(), gid)
	}

	socketDir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := socketDir.Mode().Perm(); got != 0750 {
		t.Fatalf("socket directory mode = %o, want 750", got)
	}
}

// N-07: widening the runtime root hands the control group traversal into a
// directory that also holds engine state. A directory that is already shared,
// or that holds anything bypath did not create, is not a bypath runtime root
// and must keep the mode its operator chose.
func TestGrantGroupSearchSkipsSharedRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("group traversal is only granted by a root daemon")
	}
	if _, ok := groupGID(); !ok {
		t.Skipf("control group %q is not present", GroupName)
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "bypath-control"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if err := grantGroupSearch(root); err != nil {
		t.Fatalf("grantGroupSearch: %v", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0755 {
		t.Fatalf("shared runtime root mode = %o, want 755 (unchanged)", got)
	}
}

func TestGrantGroupSearchSkipsForeignRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("group traversal is only granted by a root daemon")
	}
	if _, ok := groupGID(); !ok {
		t.Skipf("control group %q is not present", GroupName)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "unrelated.txt"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	beforeStat, ok := before.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("no syscall stat")
	}
	if err := grantGroupSearch(root); err != nil {
		t.Fatalf("grantGroupSearch: %v", err)
	}
	after, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	afterStat, ok := after.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("no syscall stat")
	}
	if after.Mode().Perm() != 0700 {
		t.Fatalf("foreign runtime root mode = %o, want 700 (unchanged)", after.Mode().Perm())
	}
	if afterStat.Gid != beforeStat.Gid {
		t.Fatalf("foreign runtime root gid = %d, want %d (unchanged)", afterStat.Gid, beforeStat.Gid)
	}
}

func TestForeignEntriesListsOnlyUnknownNames(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"bypath-control", "data", "logs", "engines"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if got := foreignEntries(root); len(got) != 0 {
		t.Fatalf("foreignEntries on a bypath root = %v, want none", got)
	}
	if err := os.Mkdir(filepath.Join(root, "someone-elses"), 0700); err != nil {
		t.Fatal(err)
	}
	got := foreignEntries(root)
	if len(got) != 1 || got[0] != "someone-elses" {
		t.Fatalf("foreignEntries = %v, want [someone-elses]", got)
	}
}

func TestListenRejectsLiveSocketAndReplacesStaleOne(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "control.sock")

	ln, err := Listen(path, "")
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}

	if _, err := Listen(path, ""); err == nil {
		t.Fatalf("second Listen replaced a live control socket")
	}

	ln.Close()
	// Closing the listener leaves the socket file behind (the daemon does not
	// unlink on exit). A fresh Listen must reclaim it.
	second, err := Listen(path, "")
	if err != nil {
		t.Fatalf("Listen over stale socket: %v", err)
	}
	second.Close()
}

func TestDialContextReachesListener(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "control.sock")
	ln, err := Listen(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := DialContext(ctx, path)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	select {
	case peer := <-accepted:
		defer peer.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(peer, buf); err != nil {
			t.Fatal(err)
		}
		if string(buf) != "ping" {
			t.Fatalf("peer read %q", buf)
		}
	case <-time.After(time.Second):
		t.Fatal("listener did not accept the control connection")
	}
}

func TestListenRefusesSymlinkedDirectory(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "real")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "linked")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := Listen(filepath.Join(link, "control.sock"), ""); err == nil {
		t.Fatal("Listen accepted a symlinked control directory")
	}
}
