package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/liberoute/bypath/internal/paths"
)

// bypath owns only its own iptables chains. Built-in chains are never flushed:
// doing so would erase firewall rules bypath did not create.
const (
	chainNat     = "BYPATH_NAT"
	chainMangle  = "BYPATH_MANGLE"
	chainForward = "BYPATH_FWD"
	chainDNS     = "BYPATH_DNS"
	chainV6Drop  = "BYPATH_V6"
	// chainGuard is a fail-closed placeholder placed first in FORWARD while the
	// real chains are flushed and rebuilt. Without it the moment between the
	// flush and the re-installed jump leaves forwarded LAN traffic accepted.
	chainGuard = "BYPATH_GUARD"
)

// Command execution is indirect so failure-injection tests can prove rollback
// behaviour without root or a live host.
//
// Every host command is bounded: ip/iptables can block on the xtables lock or a
// wedged netlink socket, and an unbounded command turns Stop into an unbounded
// wait during shutdown.
const hostCommandTimeout = 30 * time.Second

var (
	runCommand = func(name string, args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), hostCommandTimeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s %s: %s (%w)", name, strings.Join(args, " "), string(out), err)
		}
		return nil
	}
	statusCommand = func(name string, args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), hostCommandTimeout)
		defer cancel()
		return exec.CommandContext(ctx, name, args...).Run()
	}
	outputCommand = func(name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), hostCommandTimeout)
		defer cancel()
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}
)

func run(name string, args ...string) error {
	return runCommand(name, args...)
}

func commandOutput(name string, args ...string) (string, error) {
	out, err := outputCommand(name, args...)
	return string(out), err
}

const gatewayStateVersion = 2

// gatewayRunState is the write-ahead record of host-network changes made by one
// gateway run. It is saved before each operation is applied and is deleted only
// after the inverse operation has been attempted, so a crash leaves enough
// information to undo exactly what bypath owns and nothing else.
type gatewayRunState struct {
	Version     int        `json:"version"`
	Mode        string     `json:"mode"` // native, legacy, or pending (mutations before routing)
	Routes      [][]string `json:"routes,omitempty"`
	RuleAdded   bool       `json:"rule_added,omitempty"`
	NativeRules bool       `json:"native_rules,omitempty"`
	// NativeRuleTable is the routing table bypath reserved for sing-box
	// auto_route. It is persisted before the engine starts, so cleanup can
	// remove exactly the engine's rules and routes instead of guessing.
	NativeRuleTable  int  `json:"native_rule_table,omitempty"`
	TunCreated       bool `json:"tun_created,omitempty"`
	ForwardingWasOff bool `json:"forwarding_was_off,omitempty"`
	ResolvChanged    bool `json:"resolv_changed,omitempty"`
	ResolvedStopped  bool `json:"resolved_stopped,omitempty"`
	// ResolvedDropIn marks a bypath-owned systemd-resolved drop-in that points
	// the host's stub resolver at the gateway listener's nonstandard port. It is
	// separate from ResolvChanged because /etc/resolv.conf is left untouched.
	ResolvedDropIn bool `json:"resolved_drop_in,omitempty"`
	DnsmasqStopped   bool `json:"dnsmasq_stopped,omitempty"`
	HostsPinned      bool `json:"hosts_pinned,omitempty"`
	V6Isolated       bool `json:"v6_isolated,omitempty"`
	// ContainmentRetained marks a stopped run that deliberately left the
	// fail-closed DROP chains in place because ip_forward is still owned by
	// another service (for example Docker). The record is kept so an explicit
	// teardown or the next start can take over or remove exactly that state.
	ContainmentRetained bool   `json:"containment_retained,omitempty"`
	ContainmentIface    string `json:"containment_iface,omitempty"`

	// LegacyFormat marks a plain "native"/"legacy" marker written by an older
	// build that recorded no ownership details.
	LegacyFormat bool `json:"-"`
}

func gatewayStateFile() string {
	return filepath.Join(paths.Get().TmpDir, "gateway-network-state")
}

// markGatewayState starts a new ownership record. The record is written before
// any host change is applied, and the caller must abort when it cannot be
// persisted.
func markGatewayState(mode string) (*gatewayRunState, error) {
	st := &gatewayRunState{Version: gatewayStateVersion, Mode: mode}
	if err := saveGatewayState(st); err != nil {
		return nil, err
	}
	return st, nil
}

// loadGatewayState loads the ownership record, including the old plain-text
// format which carries no per-operation detail. A missing record is (nil, nil);
// a record that exists but cannot be parsed is an error. Recovery must never
// mistake a corrupt record for a clean host and skip rollback.
func loadGatewayState() (*gatewayRunState, error) {
	data, err := os.ReadFile(gatewayStateFile())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading the ownership record: %w", err)
	}
	var st gatewayRunState
	if err := json.Unmarshal(data, &st); err == nil && st.Version == gatewayStateVersion && st.Mode != "" {
		return &st, nil
	}
	switch strings.TrimSpace(string(data)) {
	case "native", "legacy":
		return &gatewayRunState{Mode: strings.TrimSpace(string(data)), LegacyFormat: true}, nil
	}
	return nil, fmt.Errorf("ownership record %s is corrupt or from an unsupported version", gatewayStateFile())
}

// gatewayState returns a usable record or nil. Callers that decide whether host
// mutation is safe must use loadGatewayState: here an unreadable record is
// indistinguishable from a missing one by design.
func gatewayState() *gatewayRunState {
	st, _ := loadGatewayState()
	return st
}

// saveGatewayState replaces the record atomically. A partially written record
// must never be mistaken for a complete one.
func saveGatewayState(st *gatewayRunState) error {
	if st == nil {
		return nil
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	// The staging file lives beside the target so the final rename stays on one
	// filesystem and is atomic even when the runtime directory is a separate
	// mount from the process temp directory.
	dir := filepath.Dir(gatewayStateFile())
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".gateway-state-*")
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
	// Flush the record before the rename so a power loss cannot leave a
	// successful rename pointing at unwritten contents.
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, gatewayStateFile()); err != nil {
		os.Remove(name)
		return err
	}
	// Persist the directory entry so the rename survives a power loss. Some
	// filesystems (and Windows) do not support directory sync; there the
	// rename is still atomic, so this stays best effort.
	if d, err := os.Open(dir); err == nil {
		d.Sync() //nolint:errcheck
		d.Close()
	}
	return nil
}

// writeResolvConf writes a resolver file atomically unless the path is a
// symlink, where following the link is the intended semantics.
func writeResolvConf(path string, data []byte, mode os.FileMode) error {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return os.WriteFile(path, data, mode)
	}
	return writeFileAtomic(path, data, mode)
}

// writeFileAtomic replaces path with data through a same-directory rename, so
// an interrupted write can never leave a truncated resolver file.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".bypath-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func clearGatewayState() {
	os.Remove(gatewayStateFile())
}

// ensureRunState returns this instance's ownership record, creating or
// upgrading it (from "pending" to a concrete mode) without discarding fields.
// The record is persisted before it is returned: a caller that cannot store
// ownership must not mutate the host.
func (gw *Gateway) ensureRunState(mode string) (*gatewayRunState, error) {
	if gw.run == nil {
		gw.run = gatewayState()
	}
	if gw.run == nil {
		gw.run = &gatewayRunState{Version: gatewayStateVersion, Mode: mode}
	}
	if mode != "" && gw.run.Mode != mode {
		gw.run.Mode = mode
	}
	if err := saveGatewayState(gw.run); err != nil {
		return nil, fmt.Errorf("persisting network ownership record: %w", err)
	}
	return gw.run, nil
}

func (gw *Gateway) persistRunState() error {
	if gw.run == nil {
		return nil
	}
	if err := saveGatewayState(gw.run); err != nil {
		return fmt.Errorf("persisting network ownership record: %w", err)
	}
	return nil
}

// iptablesQuery reports whether a chain or rule exists. A nonzero exit whose
// message states that the chain/rule is missing is proof of absence. Every
// other failure is an error: cleanup must never report success while
// bypath-owned rules may still be redirecting or blocking traffic.
func iptablesQuery(bin string, args ...string) (bool, error) {
	out, err := commandOutput(bin, args...)
	if err == nil {
		return true, nil
	}
	msg := strings.ToLower(out)
	if strings.Contains(msg, "no chain/target/match by that name") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "bad rule (does a matching rule exist") ||
		// iptables-nft reports this instead of "no chain" for a chain that
		// lives in neither backend; the chain is simply absent.
		strings.Contains(msg, "incompatible with this kernel") {
		return false, nil
	}
	return false, fmt.Errorf("%s %s: %w: %s", bin, strings.Join(args, " "), err, strings.TrimSpace(out))
}

// ensureChainE creates a chain when absent; existing chains are reused. Errors
// are returned so routing setup can abort instead of continuing half-applied.
func ensureChainE(table, chain string) error {
	exists, err := chainExists(table, chain)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return run("iptables", "-t", table, "-N", chain)
}

func flushChainE(table, chain string) error {
	return run("iptables", "-t", table, "-F", chain)
}

func chainExists(table, chain string) (bool, error) {
	return iptablesQuery("iptables", "-t", table, "-S", chain)
}

// ensureJumpE appends the jump only when an identical rule is not present.
func ensureJumpE(table, parent, chain string) error {
	exists, err := iptablesQuery("iptables", "-t", table, "-C", parent, "-j", chain)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return run("iptables", "-t", table, "-A", parent, "-j", chain)
}

// removeJump deletes one bypath-owned jump rule. An already absent rule is a
// successful inverse, which makes repeated recovery safe.
func removeJump(table, parent, chain string) error {
	return removeJumpBin("iptables", table, parent, chain)
}

func removeJumpBin(bin, table, parent, chain string) error {
	exists, err := iptablesQuery(bin, "-t", table, "-C", parent, "-j", chain)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	return run(bin, "-t", table, "-D", parent, "-j", chain)
}

// removeJump6 is the IPv6 counterpart of removeJump.
func removeJump6(table, parent, chain string) error {
	exists, err := iptablesQuery("ip6tables", "-t", table, "-C", parent, "-j", chain)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	return run("ip6tables", "-t", table, "-D", parent, "-j", chain)
}

func chainExists6(table, chain string) (bool, error) {
	return iptablesQuery("ip6tables", "-t", table, "-S", chain)
}

func ensureChain6E(table, chain string) error {
	exists, err := chainExists6(table, chain)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return run("ip6tables", "-t", table, "-N", chain)
}

func flushChain6E(table, chain string) error {
	return run("ip6tables", "-t", table, "-F", chain)
}

// jumpPosition returns the 1-based position of the first jump to chain in the
// parent chain, or 0 when the jump is absent. Reading the effective list is the
// only way to reorder a jump without deleting the sole containment rule.
func jumpPosition(bin, table, parent, chain string) (int, error) {
	out, err := commandOutput(bin, "-t", table, "-S", parent)
	if err != nil {
		return 0, fmt.Errorf("reading %s %s rules: %w", bin, parent, err)
	}
	pos := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A "+parent+" ") {
			continue
		}
		pos++
		if strings.Contains(line, "-j "+chain) {
			return pos, nil
		}
	}
	return 0, nil
}

// ensureJumpTop places a jump at the head of the parent chain. The insertion
// happens before any duplicate is removed: deleting the existing jump first
// would leave the parent chain without containment for one command, which is
// exactly the forwarded-packet window this chain exists to close.
func ensureJumpTop(bin, table, parent, chain string) error {
	pos, err := jumpPosition(bin, table, parent, chain)
	if err != nil {
		return err
	}
	if err := run(bin, "-t", table, "-I", parent, "1", "-j", chain); err != nil {
		return err
	}
	if pos == 0 {
		return nil
	}
	// The new rule occupies position 1, so the previous jump moved one slot
	// down and can be deleted by number without touching the head.
	return run(bin, "-t", table, "-D", parent, strconv.Itoa(pos+1))
}

// verifyJumpFirst proves a jump is the first rule evaluated in the parent
// chain. This is the difference between a generated command string and an
// effective containment policy.
func verifyJumpFirst(bin, table, parent, chain string) error {
	out, err := commandOutput(bin, "-t", table, "-S", parent)
	if err != nil {
		return fmt.Errorf("reading %s %s rules: %w", bin, parent, err)
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-A "+parent+" ") {
			continue
		}
		if strings.Contains(line, "-j "+chain) {
			return nil
		}
		return fmt.Errorf("%s containment is not effective: %q precedes -j %s", bin, line, chain)
	}
	return fmt.Errorf("%s jump to %s is missing from %s", bin, chain, parent)
}

// ensureJumpFirst keeps an already-correct head jump untouched. Reordering an
// effective jump would briefly remove containment, so the listing is checked
// before any delete/insert pair runs.
func ensureJumpFirst(bin, table, parent, chain string) error {
	if verifyJumpFirst(bin, table, parent, chain) == nil {
		return nil
	}
	return ensureJumpTop(bin, table, parent, chain)
}

func ensureJump6Top(table, parent, chain string) error {
	return ensureJumpTop("ip6tables", table, parent, chain)
}

func verifyJump6First(table, parent, chain string) error {
	return verifyJumpFirst("ip6tables", table, parent, chain)
}

// cleanupBypathChains removes only rules and chains created by bypath. It
// returns every failed inverse instead of discarding them; an absent rule or
// chain is already cleaned and is not an error.
func cleanupBypathChains() error {
	return cleanupBypathChainsMode(true)
}

// cleanupInterceptChains removes the DNS/NAT/mangle/guard objects but keeps the
// fail-closed FORWARD and IPv6 DROP chains. It is used when a stopped run has
// to stay contained because ip_forward remains enabled under another owner.
func cleanupInterceptChains() error {
	return cleanupBypathChainsMode(false)
}

// hostFirewallAvailable reports whether the host firewall is managed through
// iptables/ip6tables. Overridable so regression tests exercise the Linux
// containment contract regardless of the machine running them.
var hostFirewallAvailable = func() bool { return runtime.GOOS == "linux" }

func cleanupBypathChainsMode(containment bool) error {
	// iptables/ip6tables are Linux-only; on other platforms there is no
	// bypath chain to remove and shelling out would only produce noise.
	if !hostFirewallAvailable() {
		return nil
	}
	var errs []error
	jumps := []struct{ table, parent, chain string }{
		{"nat", "PREROUTING", chainDNS},
		{"nat", "POSTROUTING", chainNat},
		{"filter", "FORWARD", chainGuard},
		{"mangle", "PREROUTING", chainMangle},
	}
	if containment {
		jumps = append(jumps,
			struct{ table, parent, chain string }{"filter", "FORWARD", chainForward},
			struct{ table, parent, chain string }{"filter", "FORWARD", chainV6Drop},
		)
	}
	for _, j := range jumps {
		bin := "iptables"
		if j.chain == chainV6Drop {
			bin = "ip6tables"
		}
		if err := removeJumpBin(bin, j.table, j.parent, j.chain); err != nil {
			errs = append(errs, fmt.Errorf("removing %s jump from %s: %w", j.chain, j.parent, err))
		}
	}

	chains := []struct{ table, chain string }{
		{"nat", chainDNS},
		{"nat", chainNat},
		{"mangle", chainMangle},
		{"filter", chainGuard},
	}
	if containment {
		chains = append(chains, struct{ table, chain string }{"filter", chainForward})
	}
	for _, c := range chains {
		exists, err := chainExists(c.table, c.chain)
		if err != nil {
			errs = append(errs, fmt.Errorf("inspecting %s: %w", c.chain, err))
			continue
		}
		if !exists {
			continue
		}
		if err := flushChainE(c.table, c.chain); err != nil {
			errs = append(errs, fmt.Errorf("flushing %s: %w", c.chain, err))
			continue
		}
		if err := run("iptables", "-t", c.table, "-X", c.chain); err != nil {
			errs = append(errs, fmt.Errorf("deleting %s: %w", c.chain, err))
		}
	}
	if containment {
		if exists, err := chainExists6("filter", chainV6Drop); err != nil {
			errs = append(errs, fmt.Errorf("inspecting %s: %w", chainV6Drop, err))
		} else if exists {
			if err := run("ip6tables", "-t", "filter", "-F", chainV6Drop); err != nil {
				errs = append(errs, fmt.Errorf("flushing %s: %w", chainV6Drop, err))
			} else if err := run("ip6tables", "-t", "filter", "-X", chainV6Drop); err != nil {
				errs = append(errs, fmt.Errorf("deleting %s: %w", chainV6Drop, err))
			}
		}
	}
	return errors.Join(errs...)
}

// ipForwardPath is overridable so tests never depend on the host's forwarding
// setting. A host that already forwards (Docker, libvirt) is never claimed.
var ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

func ipv4ForwardingEnabled() (bool, error) {
	data, err := os.ReadFile(ipForwardPath)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(data)) == "1", nil
}

// networkNamespaceIsolated reports whether this process runs in a network
// namespace other than init's. The network stack is private, but the mount
// namespace is shared, so /etc/resolv.conf, /etc/hosts and systemd-resolved
// still belong to the host: rewriting them would break host DNS without ever
// serving the namespace. Overridable for tests.
var networkNamespaceIsolated = func() bool {
	self, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		return false
	}
	init, err := os.Stat("/proc/1/ns/net")
	if err != nil {
		return false
	}
	return !os.SameFile(self, init)
}

// resolvConfPinned reports whether /etc/resolv.conf is itself a mount point.
// Container runtimes bind-mount the file, and replacing it then fails with
// EBUSY; gateway mode refuses instead of leaving host DNS half-configured.
func resolvConfPinned() bool {
	return mountPointListed("/proc/self/mountinfo", resolvConfPath)
}

// mountPointListed reads a kernel mountinfo table and reports whether target is
// one of its mount points.
func mountPointListed(mountinfoPath, target string) bool {
	data, err := os.ReadFile(mountinfoPath)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		point := fields[4]
		point = strings.ReplaceAll(point, `\040`, " ")
		point = strings.ReplaceAll(point, `\011`, "\t")
		point = strings.ReplaceAll(point, `\012`, "\n")
		point = strings.ReplaceAll(point, `\134`, `\`)
		if point == target {
			return true
		}
	}
	return false
}

// ensureGuardContainment installs a bypath-owned DROP chain at the head of
// FORWARD before the real chains are flushed. The window between flushing
// BYPATH_FWD and re-installing its jump would otherwise accept forwarded LAN
// traffic; the guard is removed only once the real jump is verified first.
func ensureGuardContainment(iface string) error {
	if !hostFirewallAvailable() {
		return nil
	}
	if err := ensureChainE("filter", chainGuard); err != nil {
		return err
	}
	present, err := iptablesQuery("iptables", "-C", chainGuard, "-i", iface, "-j", "DROP")
	if err != nil {
		return err
	}
	if !present {
		if err := run("iptables", "-A", chainGuard, "-i", iface, "-j", "DROP"); err != nil {
			return err
		}
	}
	return ensureJumpFirst("iptables", "filter", "FORWARD", chainGuard)
}

// removeGuardContainment deletes the placeholder chain. A failure is fatal for
// routing setup: a leftover guard would drop LAN-to-LAN forwarding too.
func removeGuardContainment() error {
	if !hostFirewallAvailable() {
		return nil
	}
	if err := removeJump("filter", "FORWARD", chainGuard); err != nil {
		return err
	}
	exists, err := chainExists("filter", chainGuard)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if err := flushChainE("filter", chainGuard); err != nil {
		return err
	}
	return run("iptables", "-t", "filter", "-X", chainGuard)
}

// retainForwardContainment keeps bypath's fail-closed DROP policy in place when
// a stopped run leaves ip_forward enabled under a foreign owner. It never
// flushes the forward chain: the already-installed DROP rules stay effective
// for the whole transition, and no foreign forwarding setting is touched.
func retainForwardContainment(iface string) error {
	if !hostFirewallAvailable() {
		return nil
	}
	if err := ensureChainE("filter", chainForward); err != nil {
		return err
	}
	present, err := iptablesQuery("iptables", "-C", chainForward, "-i", iface, "-j", "DROP")
	if err != nil {
		return err
	}
	if !present {
		if err := run("iptables", "-A", chainForward, "-i", iface, "-j", "DROP"); err != nil {
			return err
		}
	}
	if err := ensureJumpFirst("iptables", "filter", "FORWARD", chainForward); err != nil {
		return err
	}
	if err := verifyJumpFirst("iptables", "filter", "FORWARD", chainForward); err != nil {
		return err
	}

	if err := ensureChain6E("filter", chainV6Drop); err != nil {
		return err
	}
	present6, err := iptablesQuery("ip6tables", "-t", "filter", "-C", chainV6Drop, "-i", iface, "-j", "DROP")
	if err != nil {
		return err
	}
	if !present6 {
		if err := run("ip6tables", "-t", "filter", "-A", chainV6Drop, "-i", iface, "-j", "DROP"); err != nil {
			return err
		}
	}
	if err := ensureJumpFirst("ip6tables", "filter", "FORWARD", chainV6Drop); err != nil {
		return err
	}
	return verifyJumpFirst("ip6tables", "filter", "FORWARD", chainV6Drop)
}

// reverseRoute turns a recorded "route add ..." argument list into the matching
// deletion.
func reverseRoute(args []string) []string {
	out := append([]string(nil), args...)
	if len(out) > 1 && out[0] == "route" && out[1] == "add" {
		out[1] = "del"
	}
	return out
}

func routeArgsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

var errNoOwnership = errors.New("no ownership record")

// CleanupPersistedState reverts host-network changes recorded by a bypath run
// that is no longer alive. It is the crash-recovery entry point for external
// commands (bypath stop/update) and never flushes shared firewall or routing
// state. Only bypath-named chains are removed when no record exists.
//
// Safe stop contract: when IP forwarding stays enabled because another service
// owns it, bypath's fail-closed LAN containment is deliberately kept. Removing
// those chains while a client still uses this host as its gateway would forward
// its traffic directly, so only PurgePersistedState may do that.
func CleanupPersistedState() error {
	return cleanupPersistedState(false)
}

// PurgePersistedState removes every bypath-owned firewall object, including the
// fail-closed containment a stop deliberately retained. Callers must accept
// that LAN clients still routing through this host are forwarded directly
// afterwards.
func PurgePersistedState() error {
	return cleanupPersistedState(true)
}

// RetainedContainment reports whether bypath's fail-closed LAN containment is
// still installed after a stop. It never claims containment it cannot observe.
func RetainedContainment() bool {
	st, err := loadGatewayState()
	if err != nil {
		return false
	}
	if st != nil {
		return st.ContainmentRetained
	}
	if !hostFirewallAvailable() {
		return false
	}
	enabled, err := ipv4ForwardingEnabled()
	if err != nil || !enabled {
		return false
	}
	installed, _, err := forwardContainmentInstalled()
	return err == nil && installed
}

func cleanupPersistedState(purge bool) error {
	killTrackedChildren()

	st, err := loadGatewayState()
	if err != nil {
		return err
	}
	if st == nil {
		return cleanupChainsWithoutRecord(purge)
	}
	if st.LegacyFormat {
		return cleanupLegacyPersistedState(st, purge)
	}
	if purge || !forwardingLeftOn(st) {
		gw := &Gateway{}
		if err := gw.recoverState(st); err != nil {
			// undoNetworkState pruned every inverse that did succeed; the record
			// that survives is what still needs to be undone.
			return err
		}
		clearGatewayState()
		return nil
	}
	return keepPersistedContainment(st)
}

// forwardingLeftOn reports whether the host will still forward after bypath's
// inverses run. An unreadable setting is treated as enabled: assuming it is off
// would remove the only protection against direct forwarding.
func forwardingLeftOn(st *gatewayRunState) bool {
	if st != nil && st.ForwardingWasOff {
		// bypath enabled forwarding itself, and its inverse turns it back off.
		return false
	}
	enabled, err := ipv4ForwardingEnabled()
	return err != nil || enabled
}

// keepPersistedContainment reverses the data path of a stopped run while
// leaving the fail-closed chains effective for the whole transition. Only the
// intercept chains that reference the dead data path are removed.
func keepPersistedContainment(st *gatewayRunState) error {
	gw := &Gateway{}
	if err := gw.undoNetworkStateWith(st, true, false); err != nil {
		return err
	}
	if err := cleanupInterceptChains(); err != nil {
		return fmt.Errorf("removing intercept chains: %w", err)
	}
	installed, iface, err := forwardContainmentInstalled()
	if err != nil {
		return err
	}
	if !installed {
		return fmt.Errorf("IP forwarding remains enabled by another service but bypath's LAN containment is not installed; refusing to forward client traffic directly (use 'bypath stop --purge-firewall' to remove bypath state anyway)")
	}
	v6, err := forwardContainment6Installed()
	if err != nil {
		return err
	}
	if st.V6Isolated && !v6 {
		return fmt.Errorf("IPv6 containment is not installed while IP forwarding remains enabled; refusing to forward client traffic directly")
	}
	st.ContainmentRetained = true
	if st.ContainmentIface == "" {
		st.ContainmentIface = iface
	}
	if err := saveGatewayState(st); err != nil {
		return fmt.Errorf("recording retained containment: %w", err)
	}
	return nil
}

// cleanupLegacyPersistedState handles a plain marker written by an older build.
// It has no forwarding or containment ownership, so the installed chains decide
// whether the fail-closed policy may stay.
func cleanupLegacyPersistedState(st *gatewayRunState, purge bool) error {
	gw := &Gateway{}
	if purge || !forwardingLeftOn(st) {
		return gw.recoverState(st)
	}
	installed, iface, err := forwardContainmentInstalled()
	if err != nil {
		return err
	}
	if !installed {
		// Nothing is protecting forwarded traffic, so the historical cleanup is
		// the only correct action.
		return gw.recoverState(st)
	}
	if err := gw.recoverLegacyDataPath(st); err != nil {
		return err
	}
	if err := cleanupInterceptChains(); err != nil {
		return fmt.Errorf("removing intercept chains: %w", err)
	}
	v6, err := forwardContainment6Installed()
	if err != nil {
		return err
	}
	upgraded := &gatewayRunState{
		Version:             gatewayStateVersion,
		Mode:                st.Mode,
		V6Isolated:          v6,
		ContainmentRetained: true,
		ContainmentIface:    iface,
	}
	if err := saveGatewayState(upgraded); err != nil {
		return fmt.Errorf("recording retained containment: %w", err)
	}
	return nil
}

// cleanupChainsWithoutRecord never removes fail-closed containment while the
// host still forwards for someone else: with no record there is no way to
// rebuild it, and an uncontained forwarded packet is the one outcome a stop
// must never produce.
func cleanupChainsWithoutRecord(purge bool) error {
	if purge || !hostFirewallAvailable() {
		return cleanupBypathChains()
	}
	enabled, err := ipv4ForwardingEnabled()
	if err != nil || !enabled {
		return cleanupBypathChains()
	}
	installed, _, err := forwardContainmentInstalled()
	if err != nil {
		return err
	}
	if !installed {
		return cleanupBypathChains()
	}
	return cleanupInterceptChains()
}

// forwardContainmentInstalled reports whether bypath's fail-closed IPv4 chain
// is installed, first in FORWARD, and still drops the LAN interface. It returns
// the interface the DROP rule covers and never mutates firewall state.
func forwardContainmentInstalled() (bool, string, error) {
	if !hostFirewallAvailable() {
		return false, "", nil
	}
	exists, err := chainExists("filter", chainForward)
	if err != nil || !exists {
		return false, "", err
	}
	out, err := commandOutput("iptables", "-t", "filter", "-S", chainForward)
	if err != nil {
		return false, "", fmt.Errorf("reading %s: %w", chainForward, err)
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != "-A" || fields[1] != chainForward {
			continue
		}
		iface, drop := "", false
		for i := 0; i+1 < len(fields); i++ {
			switch fields[i] {
			case "-i":
				iface = fields[i+1]
			case "-j":
				drop = fields[i+1] == "DROP"
			}
		}
		if !drop || iface == "" {
			continue
		}
		if verifyJumpFirst("iptables", "filter", "FORWARD", chainForward) != nil {
			return false, "", nil
		}
		return true, iface, nil
	}
	return false, "", nil
}

// forwardContainment6Installed is the IPv6 counterpart: the chain must exist,
// be first in FORWARD and still contain a DROP rule.
func forwardContainment6Installed() (bool, error) {
	if !hostFirewallAvailable() {
		return false, nil
	}
	exists, err := chainExists6("filter", chainV6Drop)
	if err != nil || !exists {
		return false, err
	}
	if verifyJump6First("filter", "FORWARD", chainV6Drop) != nil {
		return false, nil
	}
	out, err := commandOutput("ip6tables", "-t", "filter", "-S", chainV6Drop)
	if err != nil {
		return false, fmt.Errorf("reading %s: %w", chainV6Drop, err)
	}
	return strings.Contains(out, "-j DROP"), nil
}
