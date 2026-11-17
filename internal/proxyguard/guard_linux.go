//go:build linux

package proxyguard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	"github.com/liberoute/bypath/internal/serviceop"
)

const chain = "BYPATH_PROXY_IN"

var statePath = "/var/lib/bypath/proxy-input.json"
var rootUID = os.Geteuid
var checkState = serviceop.CheckRootPath
var trustedLANs = config.TrustedLANs
var writeState = serviceop.AtomicWrite
var Command = func(ctx context.Context, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, "/usr/sbin/iptables", args...).CombinedOutput()
}

// Every destructive guard operation runs under one exclusive lease that covers
// exactly the resource it protects. iptables state is per network namespace, and
// an abstract Unix socket name is per network namespace too: a host-network
// container shares the host namespace and therefore the lease, while a container
// with its own network namespace owns a separate firewall and correctly needs no
// shared lease. Abstract names have no filesystem entry, so they cannot be
// unlinked, recreated or replaced, and the kernel releases them when the process
// dies: there is no stale lock file and no pathname/inode check-then-act window.
// The daemon holds the lease for its whole lifetime, so a stop in another process
// can neither run between a run's ownership proof and its install nor remove a
// guard a replacement run is holding.
//
// Trust boundary: this excludes accidental concurrent owners (a second daemon, a
// supervisor restart, a stop command, another host-network container). A process
// that already has host root can rewrite iptables directly and is out of scope.
const guardLockName = "@bypath-proxy-guard-v1"

var (
	ErrGuardBusy     = errors.New("proxy guard is in use by a running bypath process")
	ErrGuardReplaced = errors.New("proxy guard belongs to a different run")
	ErrGuardUnshared = errors.New("proxy guard state directory is not shared with the firewall owner")
	lockWait         = 2 * time.Second
)

// lease is the exclusive guard lease of this process. legacy carries the pre-fix
// flock file when one exists, so an older binary that is still running keeps
// excluding a current one during an upgrade. shared records whether the record
// directory existed before this process looked at it: a directory this process
// had to create belongs to this mount only, not to the firewall's owner.
type lease struct {
	sock   *os.File
	legacy *os.File
	shared bool
}

// held is the lease of the daemon in this process, if any.
var held *lease

func lockPath() string {
	return filepath.Join(filepath.Dir(statePath), "proxy-guard.lock")
}

func lockGuard(wait time.Duration) (*lease, error) {
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	addr := &syscall.SockaddrUnix{Name: guardLockName}
	deadline := time.Now().Add(wait)
	for {
		if err = syscall.Bind(fd, addr); err == nil {
			break
		}
		if err != syscall.EADDRINUSE {
			syscall.Close(fd)
			return nil, err
		}
		if time.Now().After(deadline) {
			syscall.Close(fd)
			return nil, ErrGuardBusy
		}
		time.Sleep(20 * time.Millisecond)
	}
	l := &lease{sock: os.NewFile(uintptr(fd), "bypath-proxy-guard.lock")}
	if _, statErr := os.Stat(filepath.Dir(statePath)); statErr == nil {
		l.shared = true
	}
	if l.legacy, err = legacyFlock(wait); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// legacyFlock honours a pre-fix lock file when it exists. It never creates the
// path: the abstract lease is authoritative, and a recreated path must not be
// able to grant exclusion on its own.
func legacyFlock(wait time.Duration) (*os.File, error) {
	f, err := os.OpenFile(lockPath(), os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN && err != syscall.EINTR {
			f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, ErrGuardBusy
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (l *lease) Close() {
	if l.legacy != nil {
		_ = syscall.Flock(int(l.legacy.Fd()), syscall.LOCK_UN)
		l.legacy.Close()
	}
	if l.sock != nil {
		l.sock.Close()
	}
}

func unlockGuard(l *lease) { l.Close() }

func releaseHeld() {
	if held == nil {
		return
	}
	held.Close()
	held = nil
}

// RecordToken reports the token of the guard currently recorded on disk. The
// stop path samples it before stopping so its cleanup stays bound to that run.
func RecordToken() string {
	r, err := load()
	if err != nil {
		return ""
	}
	return r.Token
}

type entry struct {
	CIDR      string
	Interface string
}
type record struct {
	Token   string
	Port    int
	Entries []entry
	Rules   [][]string
}

func run(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return Command(ctx, append([]string{"-w", "3"}, args...)...)
}
func ruleSet(r record) [][]string {
	port := strconv.Itoa(r.Port)
	marker := []string{"-m", "comment", "--comment", r.Token}
	rule := func(args ...string) []string { return append(args, marker...) }
	rules := [][]string{
		// Host-local clients are trusted whatever source address they select: the
		// daemon's own probes bind to the LAN IP, and a specific-address bind
		// serves loopback through a second listener. Only packets that ingress on
		// a trusted interface from an allow-listed source may pass.
		rule("-i", "lo", "-j", "RETURN"),
	}
	for _, e := range r.Entries {
		rules = append(rules, rule("-i", e.Interface, "-s", e.CIDR, "-j", "RETURN"))
	}
	return append(rules,
		rule("-p", "tcp", "--dport", port, "-j", "DROP"),
		rule("-p", "udp", "--dport", port, "-j", "DROP"),
	)
}
func jump(r record, proto string) []string {
	return []string{"-p", proto, "--dport", strconv.Itoa(r.Port), "-m", "comment", "--comment", r.Token, "-j", chain}
}
func validEntries(entries []entry) bool {
	if len(entries) == 0 {
		return false
	}
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		_, cidr, err := net.ParseCIDR(e.CIDR)
		if err != nil || cidr.IP.To4() == nil || !cidr.IP.IsPrivate() || cidr.String() != e.CIDR {
			return false
		}
		if e.Interface == "" || len(e.Interface) > 32 || strings.ContainsAny(e.Interface, "/\\\\ \t\x00") {
			return false
		}
		key := e.Interface + " " + e.CIDR
		if seen[key] {
			return false
		}
		seen[key] = true
	}
	return true
}
func load() (record, error) {
	var r record
	if err := checkState(statePath, false); err != nil {
		return r, err
	}
	b, err := os.ReadFile(statePath)
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(b, &r)
	if err != nil {
		return r, err
	}
	_, tokenErr := hex.DecodeString(r.Token)
	if len(r.Token) != 32 || tokenErr != nil || !validEntries(r.Entries) || !reflect.DeepEqual(r.Rules, ruleSet(r)) || r.Port < 1 || r.Port > 65535 {
		return r, errors.New("invalid proxy guard ownership")
	}
	return r, nil
}

// chainRules keeps only the rule lines of an iptables listing. iptables writes
// legacy-table notices to stderr, which CombinedOutput merges into the listing;
// counting them as rules would reject our own chain and block startup.
func chainRules(out []byte) []string {
	var rules []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-A ") {
			rules = append(rules, line)
		}
	}
	return rules
}
func owns(r record) error {
	b, err := run("-S", chain)
	if err != nil {
		return err
	}
	lines := chainRules(b)
	if len(lines) > len(r.Rules) {
		return errors.New("proxy guard contains foreign rules")
	}
	for _, line := range lines {
		if !strings.Contains(line, r.Token) {
			return errors.New("proxy guard contains foreign rules")
		}
	}
	found := 0
	for _, rule := range r.Rules {
		if _, err = run(append([]string{"-C", chain}, rule...)...); err == nil {
			found++
		}
	}
	if found != len(r.Rules) {
		return errors.New("proxy guard rules do not match ownership")
	}
	return nil
}

// ruleView is a parsed iptables rule line, in either the -S listing form
// ("-A CHAIN ...") or the argument form used to build deletions.
type ruleView struct {
	parent string
	args   []string
	marker string
	proto  string
	dport  int
	src    string
	iface  string
	target string
}

func parseRule(line string) (ruleView, bool) {
	f := strings.Fields(line)
	if len(f) < 3 || f[0] != "-A" {
		return ruleView{}, false
	}
	v := ruleView{parent: f[1], args: f[2:]}
	for i := 0; i < len(v.args); i++ {
		next := func() string {
			if i+1 < len(v.args) {
				i++
				return v.args[i]
			}
			return ""
		}
		switch v.args[i] {
		case "-p", "--protocol":
			v.proto = next()
		case "--dport", "--destination-port":
			v.dport, _ = strconv.Atoi(next())
		case "-s", "--source":
			v.src = next()
		case "-i", "--in-interface":
			v.iface = next()
		case "-j", "--jump":
			v.target = next()
		case "--comment":
			v.marker = next()
		}
	}
	return v, true
}

// view is what the kernel currently holds for the guard, independent of any
// record. Everything the lifecycle decides is derived from this observation.
type view struct {
	exists bool
	rules  []ruleView
	jumps  []ruleView
	extra  []ruleView
	marker string
}

// guardParents are the only built-in chains the guard may appear in. Each is
// listed on its own so a truncated combined listing cannot hide a jump.
var guardParents = []string{"INPUT", "FORWARD", "OUTPUT"}

func references() (jumps, extra []ruleView, err error) {
	for _, parent := range guardParents {
		out, err := run("-S", parent)
		if err != nil {
			return nil, nil, fmt.Errorf("listing %s: %w", parent, err)
		}
		for _, line := range chainRules(out) {
			r, ok := parseRule(line)
			if !ok || r.target != chain {
				continue
			}
			if parent == "INPUT" {
				jumps = append(jumps, r)
			} else {
				extra = append(extra, r)
			}
		}
	}
	return jumps, extra, nil
}

func inspect() (view, error) {
	var v view
	if out, err := run("-S", chain); err == nil {
		v.exists = true
		for _, line := range chainRules(out) {
			if r, ok := parseRule(line); ok && r.parent == chain {
				v.rules = append(v.rules, r)
			}
		}
	}
	jumps, extra, err := references()
	if err != nil {
		return v, err
	}
	v.jumps, v.extra = jumps, extra
	if !v.exists && len(v.jumps)+len(v.extra) > 0 {
		return v, errors.New("proxy firewall jumps reference a chain that does not exist; inspect iptables before starting")
	}
	v.marker = uniformMarker(v)
	return v, nil
}

// uniformMarker returns the single well-formed marker shared by every rule in
// the chain and every jump into it. Empty means the object cannot be attributed
// to one bypath run, which is the only case that must be treated as foreign.
func uniformMarker(v view) string {
	marker := ""
	for _, list := range [][]ruleView{v.rules, v.jumps} {
		for _, r := range list {
			if len(r.marker) != 32 {
				return ""
			}
			if _, err := hex.DecodeString(r.marker); err != nil {
				return ""
			}
			if marker == "" {
				marker = r.marker
			} else if marker != r.marker {
				return ""
			}
		}
	}
	return marker
}

// ownedByRecord proves the installed objects belong to this run even when the
// install or the previous cleanup was interrupted: a strict subset of the
// recorded rules, every line carrying the recorded token, and only the two
// recorded jumps. A missing rule is expected after a crash; an extra or
// untagged rule is not ours.
func ownedByRecord(v view, r record) bool {
	if len(v.extra) > 0 {
		return false
	}
	if len(v.rules) == 0 && len(v.jumps) == 0 {
		// Nothing foreign remains and the record names this chain; a flush that
		// was interrupted before deletion is ours to finish.
		return true
	}
	if v.marker == "" || v.marker != r.Token {
		return false
	}
	if len(v.rules) > len(r.Rules) || len(v.jumps) > 2 {
		return false
	}
	for _, rule := range v.rules {
		if rule.marker != r.Token {
			return false
		}
	}
	for _, j := range v.jumps {
		if j.marker != r.Token || j.dport != r.Port || (j.proto != "tcp" && j.proto != "udp") || j.iface != "" || j.src != "" {
			return false
		}
	}
	return true
}

// adoptable is the record-free proof: the chain is named exactly like the guard
// and every rule matches the guard's structure with one shared 32-hex marker.
// Anything less could be a foreign chain that merely borrowed the name, and is
// never deleted.
func adoptable(v view) bool {
	if v.marker == "" || len(v.extra) > 0 || len(v.jumps) != 2 {
		return false
	}
	var entries []entry
	loop, tcpDrop, udpDrop := 0, 0, 0
	tcpPort, udpPort := 0, 0
	for _, rule := range v.rules {
		if rule.marker != v.marker {
			return false
		}
		switch rule.target {
		case "RETURN":
			if rule.proto != "" || rule.dport != 0 {
				return false
			}
			if rule.iface == "lo" && rule.src == "" {
				loop++
				continue
			}
			if rule.iface == "" || rule.src == "" {
				return false
			}
			entries = append(entries, entry{CIDR: rule.src, Interface: rule.iface})
		case "DROP":
			if rule.src != "" || rule.iface != "" || rule.dport < 1 || rule.dport > 65535 {
				return false
			}
			switch rule.proto {
			case "tcp":
				tcpDrop++
				tcpPort = rule.dport
			case "udp":
				udpDrop++
				udpPort = rule.dport
			default:
				return false
			}
		default:
			return false
		}
	}
	if loop != 1 || tcpDrop != 1 || udpDrop != 1 || tcpPort != udpPort {
		return false
	}
	seen := map[string]bool{}
	for _, j := range v.jumps {
		if j.marker != v.marker || j.dport != tcpPort || j.iface != "" || j.src != "" || seen[j.proto] || (j.proto != "tcp" && j.proto != "udp") {
			return false
		}
		seen[j.proto] = true
	}
	return seen["tcp"] && seen["udp"] && validEntries(entries)
}

// absentVerified proves the chain is gone from an independent listing before
// the ownership record may be deleted. Removing the record while the chain is
// still installed is what turns a crash into a permanent startup refusal.
func absentVerified() error {
	if _, err := run("-S", chain); err == nil {
		return errors.New("proxy guard chain still present")
	}
	jumps, extra, err := references()
	if err != nil {
		return fmt.Errorf("cannot confirm the proxy guard was removed: %w", err)
	}
	if len(jumps)+len(extra) > 0 {
		return errors.New("proxy guard jumps still present")
	}
	return nil
}

func removeRecord() error {
	if err := os.Remove(statePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Ensure installs containment before any engine listener starts, in proxy-only
// and gateway modes. An unverifiable LAN or foreign chain prevents engine
// startup. The guard lock is held until Cleanup, so no other process can
// replace or remove this run's guard while it serves.
func Ensure(cfg *config.Config) error {
	if cfg.Server.SOCKSListenAddress() == "127.0.0.1" {
		// A loopback listener exposes nothing to the LAN: no guard is needed, so
		// no iptables access may be required. A guard left by an earlier LAN-mode
		// run stays fail-closed until a LAN start or an explicit stop reconciles it.
		return nil
	}
	if rootUID() != 0 {
		return errors.New("LAN proxy requires root-owned IPv4 firewall")
	}
	releaseHeld()
	l, err := lockGuard(lockWait)
	if err != nil {
		return err
	}
	held = l
	fail := func(err error) error {
		releaseHeld()
		return err
	}
	if err := cleanupLocked("", false, l.shared); err != nil {
		return fail(err)
	}
	lan, err := trustedLANs(cfg.Gateway.Interface, cfg.Server.SOCKSAllowCIDRs)
	if err != nil {
		return fail(err)
	}
	if !cfg.Server.SOCKSAllowLAN {
		return fail(errors.New("LAN bind not confirmed"))
	}
	addr := cfg.Server.SOCKSListenAddress()
	bound := addr == "0.0.0.0"
	for _, l := range lan {
		if addr == l.IP {
			bound = true
		}
	}
	if !bound {
		return fail(errors.New("proxy bind is not the trusted LAN interface"))
	}
	v, err := inspect()
	if err != nil {
		return fail(err)
	}
	if v.exists {
		return fail(errors.New("refusing foreign proxy firewall chain"))
	}
	var token [16]byte
	if _, err = rand.Read(token[:]); err != nil {
		return fail(err)
	}
	r := record{Token: hex.EncodeToString(token[:]), Port: cfg.Server.SOCKSPort}
	for _, l := range lan {
		r.Entries = append(r.Entries, entry{CIDR: l.CIDR, Interface: l.Interface})
	}
	r.Rules = ruleSet(r)
	b, _ := json.Marshal(r)
	if err = os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		return fail(err)
	}
	if err = writeState(statePath, b); err != nil {
		return fail(err)
	}
	created, err := install(r)
	if err != nil {
		if !created {
			// Chain creation failed, so this run installed nothing. Only its own
			// record has to go; the chain that blocked creation belongs to someone
			// else and is never touched.
			if rmErr := removeRecord(); rmErr != nil {
				return fail(fmt.Errorf("%w (record cleanup failed: %v)", err, rmErr))
			}
			return fail(err)
		}
		// A half-installed chain is recoverable on the next start because the
		// record names every rule, but rollback must prove that what is installed
		// is still this run's before deleting any of it.
		if undoErr := rollback(r); undoErr != nil {
			return fail(fmt.Errorf("%w (rollback withheld: %v)", err, undoErr))
		}
		return fail(err)
	}
	return nil
}

// install reports whether this run created the chain. A failed -N means the
// chain already existed and belongs to somebody else: rollback must not run.
func install(r record) (bool, error) {
	if _, err := run("-N", chain); err != nil {
		return false, err
	}
	for _, rule := range r.Rules {
		if _, err := run(append([]string{"-A", chain}, rule...)...); err != nil {
			return true, err
		}
	}
	// INPUT position 1 precedes established/accept rules. RETURN preserves host
	// policy for permitted sources; forbidden clients are always dropped.
	for _, proto := range []string{"tcp", "udp"} {
		if _, err := run(append([]string{"-I", "INPUT", "1"}, jump(r, proto)...)...); err != nil {
			return true, err
		}
	}
	if err := owns(r); err != nil {
		return true, err
	}
	for _, proto := range []string{"tcp", "udp"} {
		if _, err := run(append([]string{"-C", "INPUT"}, jump(r, proto)...)...); err != nil {
			return true, err
		}
	}
	return true, nil
}

// rollback undoes a failed install. It acts only on objects proven to be this
// run's by the record it wrote, and it never flushes: rules are deleted one by
// one and the chain is deleted only after a fresh listing shows it empty.
func rollback(r record) error {
	v, err := inspect()
	if err != nil {
		return err
	}
	if !v.exists {
		if len(v.jumps)+len(v.extra) > 0 {
			return errors.New("guard jumps reference a chain that does not exist")
		}
		return removeRecord()
	}
	if !ownedByRecord(v, r) {
		return errors.New("installed rules do not match this run's record")
	}
	return removeVerified(v)
}

// removeVerified deletes exactly the observed guard objects and then the chain,
// but only after an independent listing proves the chain is empty. Anything that
// cannot be attributed keeps the chain and the record in place.
func removeVerified(v view) error {
	for _, j := range v.jumps {
		args := append([]string{"-D", j.parent}, j.args...)
		for {
			if _, err := run(args...); err != nil {
				break
			}
		}
	}
	for _, rule := range v.rules {
		args := append([]string{"-D", chain}, rule.args...)
		for {
			if _, err := run(args...); err != nil {
				break
			}
		}
	}
	if out, err := run("-S", chain); err == nil {
		if left := chainRules(out); len(left) > 0 {
			return fmt.Errorf("retaining proxy guard chain: %d unverified rule(s) remain", len(left))
		}
		if err := run1("-X", chain); err != nil {
			return err
		}
	}
	if err := absentVerified(); err != nil {
		return err
	}
	return removeRecord()
}

func run1(args ...string) error {
	_, err := run(args...)
	return err
}

// firewallUnavailable reports whether iptables could not be executed at all.
// That is the only failure under which an absent record proves nothing was
// installed, so a proxy-only host without iptables keeps starting.
func firewallUnavailable(err error) bool {
	return errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist)
}

// Cleanup removes the guard of this process's run, or, without a lease, any
// guard that is verifiably bypath's. It is the daemon's shutdown path.
func Cleanup() error {
	if held != nil {
		l := held
		defer releaseHeld()
		return cleanupLocked("", false, l.shared)
	}
	l, err := lockGuard(lockWait)
	if err != nil {
		return err
	}
	defer l.Close()
	return cleanupLocked("", false, l.shared)
}

// CleanupOwned is the stop-time entry point. It removes the guard only when the
// record still names the token that was sampled before that daemon was stopped.
// A replacement daemon either holds the guard lease (ErrGuardBusy) or has
// recorded its own token (ErrGuardReplaced); in both cases its guard is left in
// place. With a lost or corrupt record the chain is still adopted only when the
// lease proves no daemon is running and the state directory is the shared one.
func CleanupOwned(token string) error {
	if held != nil {
		return ErrGuardBusy
	}
	l, err := lockGuard(lockWait)
	if err != nil {
		return err
	}
	defer l.Close()
	return cleanupLocked(token, true, l.shared)
}

// cleanupLocked removes the guard only after proving whose it is, with the
// guard lease already held. The record is the primary proof; a uniform marker
// over the exact guard structure is the recovery proof when the record was
// lost. The record is deleted last and only after two listings confirm the
// chain is gone, so no crash window can leave an unowned chain behind.
func cleanupLocked(token string, scoped, shared bool) error {
	r, recErr := load()
	if scoped && recErr == nil && (token == "" || r.Token != token) {
		return ErrGuardReplaced
	}
	v, err := inspect()
	if err != nil {
		if recErr != nil && firewallUnavailable(err) {
			return nil
		}
		return err
	}
	if !v.exists {
		// Nothing is installed, so the record protects nothing and its loss or
		// corruption must not block every later start.
		return removeRecord()
	}
	owned := false
	if recErr == nil {
		owned = ownedByRecord(v, r)
	}
	if !owned && shared {
		// Shape-based adoption is the record-loss recovery path, but it is only
		// meaningful in the firewall owner's state directory. In a directory this
		// process had to create, the chain belongs to someone else's record.
		owned = adoptable(v)
	}
	if !owned {
		if os.IsNotExist(recErr) && !shared {
			// Without the owner's state directory there is no record to prove
			// what this chain is. A directory this process had to create belongs
			// to a different mount; adopting a chain from it would be a guess.
			return ErrGuardUnshared
		}
		if os.IsNotExist(recErr) {
			return errors.New("retaining unverified proxy firewall ownership: no record and the installed rules are not a verifiable guard")
		}
		if recErr != nil {
			return fmt.Errorf("retaining unverified proxy firewall ownership: %v", recErr)
		}
		return errors.New("retaining unverified proxy firewall ownership: installed rules do not match the record and the guard structure")
	}
	return removeVerified(v)
}
