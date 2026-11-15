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

// Ensure installs containment before any engine listener starts, in proxy-only
// and gateway modes. An ambiguous LAN or foreign chain prevents engine startup.
func Ensure(cfg *config.Config) error {
	if rootUID() != 0 {
		if cfg.Server.SOCKSListenAddress() == "127.0.0.1" {
			return nil
		}
		return errors.New("LAN proxy requires root-owned IPv4 firewall")
	}
	if err := Cleanup(); err != nil {
		return err
	}
	if cfg.Server.SOCKSListenAddress() == "127.0.0.1" {
		return nil
	}
	lan, err := trustedLANs(cfg.Gateway.Interface, cfg.Server.SOCKSAllowCIDRs)
	if err != nil {
		return err
	}
	if !cfg.Server.SOCKSAllowLAN {
		return errors.New("LAN bind not confirmed")
	}
	addr := cfg.Server.SOCKSListenAddress()
	bound := addr == "0.0.0.0"
	for _, l := range lan {
		if addr == l.IP {
			bound = true
		}
	}
	if !bound {
		return errors.New("proxy bind is not the trusted LAN interface")
	}
	if _, err = run("-S", chain); err == nil {
		return errors.New("refusing foreign proxy firewall chain")
	}
	var token [16]byte
	if _, err = rand.Read(token[:]); err != nil {
		return err
	}
	r := record{Token: hex.EncodeToString(token[:]), Port: cfg.Server.SOCKSPort}
	for _, l := range lan {
		r.Entries = append(r.Entries, entry{CIDR: l.CIDR, Interface: l.Interface})
	}
	r.Rules = ruleSet(r)
	if err = os.MkdirAll(filepath.Dir(statePath), 0700); err != nil {
		return err
	}
	b, _ := json.Marshal(r)
	if err = writeState(statePath, b); err != nil {
		return err
	}
	if err = install(r); err != nil {
		// A half-installed chain would fail the next startup's ownership check
		// forever; remove exactly what was added before reporting the failure.
		if undoErr := uninstall(r); undoErr != nil {
			return fmt.Errorf("%w (guard cleanup failed: %v)", err, undoErr)
		}
		return err
	}
	return nil
}

func install(r record) error {
	if _, err := run("-N", chain); err != nil {
		return err
	}
	for _, rule := range r.Rules {
		if _, err := run(append([]string{"-A", chain}, rule...)...); err != nil {
			return err
		}
	}
	// INPUT position 1 precedes established/accept rules. RETURN preserves host
	// policy for permitted sources; forbidden clients are always dropped.
	for _, proto := range []string{"tcp", "udp"} {
		if _, err := run(append([]string{"-I", "INPUT", "1"}, jump(r, proto)...)...); err != nil {
			return err
		}
	}
	if err := owns(r); err != nil {
		return err
	}
	for _, proto := range []string{"tcp", "udp"} {
		if _, err := run(append([]string{"-C", "INPUT"}, jump(r, proto)...)...); err != nil {
			return err
		}
	}
	return nil
}

func uninstall(r record) error {
	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	for _, proto := range []string{"tcp", "udp"} {
		for {
			if _, err := run(append([]string{"-D", "INPUT"}, jump(r, proto)...)...); err != nil {
				break
			}
		}
	}
	if _, err := run("-S", chain); err == nil {
		keep(run1("-F", chain))
		keep(run1("-X", chain))
	}
	if err := os.Remove(statePath); err != nil && !os.IsNotExist(err) {
		keep(err)
	}
	return first
}

func run1(args ...string) error {
	_, err := run(args...)
	return err
}
func Cleanup() error {
	r, err := load()
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	all, err := run("-S")
	if err != nil {
		return err
	}
	if !strings.Contains(string(all), "-N "+chain+"\n") && !strings.HasSuffix(string(all), "-N "+chain) {
		if strings.Contains(string(all), "-j "+chain) {
			return errors.New("orphan proxy guard jump")
		}
		return os.Remove(statePath)
	}
	if err = owns(r); err != nil {
		return fmt.Errorf("retaining unverified proxy firewall ownership: %w", err)
	}
	for _, proto := range []string{"tcp", "udp"} {
		if _, err = run(append([]string{"-C", "INPUT"}, jump(r, proto)...)...); err == nil {
			if _, err = run(append([]string{"-D", "INPUT"}, jump(r, proto)...)...); err != nil {
				return err
			}
		}
	}
	if _, err = run("-F", chain); err != nil {
		return err
	}
	if _, err = run("-X", chain); err != nil {
		return err
	}
	return os.Remove(statePath)
}
