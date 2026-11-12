//go:build !windows

package control

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Listen binds the control socket path. A stale socket left by an unclean exit
// is replaced only after proving nothing answers it; a live second daemon is
// never displaced. The socket is bound under a temporary sibling name and
// moved into place after its mode is set, so there is no window where the
// default umask exposes it to accounts outside the control group. The parent
// directory is already restricted to the daemon and that group.
//
// runtimeRoot, when set, is the daemon-owned directory the socket's directory
// lives under. It is created with the owner-only mode the rest of the runtime
// state needs, which would otherwise deny the control group traversal and make
// the socket's group mode unusable; Listen widens it by the group search bit.
func Listen(path, runtimeRoot string) (net.Listener, error) {
	if path == "" {
		return nil, errors.New("control socket path is empty")
	}
	dir := filepath.Dir(path)
	if err := prepareDir(dir); err != nil {
		return nil, err
	}
	if err := grantGroupSearch(runtimeRoot); err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); err == nil {
		conn, dialErr := net.DialTimeout("unix", path, 300*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return nil, fmt.Errorf("control socket %s is already served by another process", path)
		}
		if removeErr := os.Remove(path); removeErr != nil {
			return nil, fmt.Errorf("removing stale control socket: %w", removeErr)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("checking control socket: %w", err)
	}

	staging := fmt.Sprintf("%s.new.%d", path, os.Getpid())
	os.Remove(staging)
	ln, err := net.Listen("unix", staging)
	if err != nil {
		return nil, fmt.Errorf("binding control socket: %w", err)
	}
	if err := protect(staging, true); err != nil {
		ln.Close()
		os.Remove(staging)
		return nil, err
	}
	if err := os.Rename(staging, path); err != nil {
		ln.Close()
		os.Remove(staging)
		return nil, fmt.Errorf("publishing control socket: %w", err)
	}
	return ln, nil
}

// DialContext connects to the daemon control socket.
func DialContext(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}

// prepareDir keeps the socket reachable for the group while the socket file
// itself carries the executable bit boundary.
func prepareDir(dir string) error {
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("creating control socket directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("inspecting control socket directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("control socket directory %s is a symlink", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("control socket directory %s is not a directory", dir)
	}
	return protect(dir, false)
}

// protect applies the narrowest mode that still allows the daemon and the
// control group to use the path. Without the group (or without root, which
// alone may chown to it), the path stays owner-only.
func protect(path string, socket bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspecting control path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to protect symlinked control path %s", path)
	}
	if os.Geteuid() != 0 {
		if socket {
			return os.Chmod(path, 0600)
		}
		return os.Chmod(path, 0700)
	}
	if gid, ok := groupGID(); ok {
		if err := os.Chown(path, 0, gid); err != nil {
			return fmt.Errorf("setting control path group: %w", err)
		}
		if socket {
			return os.Chmod(path, 0660)
		}
		return os.Chmod(path, 0750)
	}
	if socket {
		return os.Chmod(path, 0600)
	}
	return os.Chmod(path, 0700)
}

// grantGroupSearch adds the group search bit to the runtime root so a control
// group member can traverse to the socket. Search is all that is needed to
// reach a known socket path, so listing stays closed to the group: the
// directory also holds owner-only runtime state. Only a real, root-owned
// directory is touched; anything else keeps its operator-chosen mode.
func grantGroupSearch(root string) error {
	if root == "" || os.Geteuid() != 0 {
		return nil
	}
	gid, ok := groupGID()
	if !ok {
		return nil
	}
	info, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("inspecting control runtime root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return nil
	}
	perm := info.Mode().Perm()
	if perm&0o001 != 0 || (perm&0o010 != 0 && int(st.Gid) == gid) {
		return nil
	}
	// Only a private directory that holds nothing but bypath state is widened.
	// A shared or foreign directory (for example an explicit BYPATH_RUNTIME_DIR
	// pointing at a system or home directory) keeps its operator-chosen mode;
	// the daemon still works as root, only group traversal stays off.
	if perm&0o077 != 0 {
		log.Printf("⚠️  Control runtime root %s is group/other accessible; leaving its mode unchanged", root)
		return nil
	}
	if foreign := foreignEntries(root); len(foreign) > 0 {
		log.Printf("⚠️  Control runtime root %s contains entries bypath does not own (%s); leaving its mode unchanged",
			root, strings.Join(foreign, ", "))
		return nil
	}
	// Root keeps its access; the group only gains search, never read.
	if err := os.Chown(root, 0, gid); err != nil {
		return fmt.Errorf("setting control runtime root group: %w", err)
	}
	if err := os.Chmod(root, perm|0o010); err != nil {
		return fmt.Errorf("granting control runtime root search: %w", err)
	}
	return nil
}

// runtimeRootEntries are the only names a bypath runtime root may contain for
// the group search bit to be added. Anything else means the directory predates
// bypath or is shared with another product, and bypath must not touch it.
var runtimeRootEntries = map[string]bool{
	"bypath-control":  true,
	"data":            true,
	"logs":            true,
	"configs":         true,
	"engines":         true,
	"geo":             true,
	"bypath.pid":      true,
	"bypath.children": true,
	"bypath":          true,
	"bypath.exe":      true,
}

func foreignEntries(root string) []string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return []string{"unreadable"}
	}
	var foreign []string
	for _, e := range entries {
		if !runtimeRootEntries[e.Name()] {
			foreign = append(foreign, e.Name())
		}
	}
	return foreign
}

func groupGID() (int, bool) {
	g, err := user.LookupGroup(GroupName)
	if err != nil {
		return 0, false
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, false
	}
	return gid, true
}
