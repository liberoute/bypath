package gateway

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// applyRoute records a route before adding it. The record is durable first so a
// crash after the add still leaves an exact inverse. A failed add is removed
// from the record: the route was not applied, and deleting a pre-existing route
// during rollback would destroy host configuration bypath does not own.
func (gw *Gateway) applyRoute(st *gatewayRunState, args ...string) error {
	rec := append([]string(nil), args...)
	st.Routes = append(st.Routes, rec)
	if err := saveGatewayState(st); err != nil {
		st.Routes = st.Routes[:len(st.Routes)-1]
		return err
	}
	if err := run("ip", args...); err != nil {
		st.Routes = st.Routes[:len(st.Routes)-1]
		if saveErr := saveGatewayState(st); saveErr != nil {
			return errors.Join(err, fmt.Errorf("removing the failed route from the ownership record: %w", saveErr))
		}
		return err
	}
	return nil
}

// applyFwmarkRule adds the policy rule only when an identical rule is not
// already present. A pre-existing rule is not owned by bypath and is therefore
// never removed during cleanup.
func (gw *Gateway) applyFwmarkRule(st *gatewayRunState) error {
	out, err := commandOutput("ip", "rule", "show")
	if err != nil {
		// Without a trustworthy listing a pre-existing rule could be claimed
		// and later deleted. Abort instead of mutating host state.
		return fmt.Errorf("inspecting policy rules: %w", err)
	}
	if fwmarkRulePresent(out) {
		return nil
	}
	st.RuleAdded = true
	if err := saveGatewayState(st); err != nil {
		st.RuleAdded = false
		return err
	}
	if err := run("ip", "rule", "add", "fwmark", "0x1", "lookup", "100", "prio", "100"); err != nil {
		st.RuleAdded = false
		if saveErr := saveGatewayState(st); saveErr != nil {
			return errors.Join(err, fmt.Errorf("removing the failed rule from the ownership record: %w", saveErr))
		}
		return err
	}
	return nil
}

func fwmarkRulePresent(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "fwmark 0x1") && strings.Contains(line, "lookup 100") {
			return true
		}
	}
	return false
}

func fwmarkRuleAt100(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "100:") && strings.Contains(line, "fwmark 0x1") && strings.Contains(line, "lookup 100") {
			return true
		}
	}
	return false
}

// enableIPv4Forwarding records whether forwarding had to be turned on. A host
// that already forwarded is never claimed or reset.
func (gw *Gateway) enableIPv4Forwarding(st *gatewayRunState) error {
	enabled, err := ipv4ForwardingEnabled()
	if err != nil {
		return nil // not Linux/procfs; the routing commands themselves will fail closed
	}
	if enabled {
		return nil
	}
	st.ForwardingWasOff = true
	if err := saveGatewayState(st); err != nil {
		st.ForwardingWasOff = false
		return err
	}
	if err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		st.ForwardingWasOff = false
		if saveErr := saveGatewayState(st); saveErr != nil {
			return errors.Join(err, fmt.Errorf("removing the failed sysctl from the ownership record: %w", saveErr))
		}
		return err
	}
	return nil
}

// tun0State reports whether tun0 exists and whether it carries bypath's fixed
// address. A lookup that cannot prove the interface foreign is an error, never
// a silent "not ours".
func tun0State() (exists, ours bool, err error) {
	out, outErr := commandOutput("ip", "-brief", "addr", "show", "tun0")
	if outErr != nil {
		if statusCommand("ip", "link", "show", "tun0") != nil {
			return false, false, nil
		}
		return true, false, fmt.Errorf("inspecting tun0: %w", outErr)
	}
	return true, strings.Contains(out, "10.0.0.1/24"), nil
}

func linkExists(name string) bool {
	return statusCommand("ip", "link", "show", name) == nil
}

// legacyNativePriorities are the rule priorities sing-box used before bypath
// pinned its own routing table. Records written by that build may only remove
// these priorities, and only when they target table 2022.
var legacyNativePriorities = map[string]bool{
	"9000": true,
	"9001": true,
	"9002": true,
	"9003": true,
	"9010": true,
}

// removeEngineNativeRules deletes the policy rules and routes sing-box created
// for bypath's reserved routing table. With a pinned table (table > 0) any rule
// or route that references only that table is owned by bypath's engine. Legacy
// records (table 0) are restricted to the historical priorities and table 2022.
// Shared routing tables are never flushed; each route is deleted individually.
func removeEngineNativeRules(table int) error {
	out, err := commandOutput("ip", "rule", "show")
	if err != nil {
		return fmt.Errorf("reading policy rules: %w", err)
	}
	target := "2022"
	legacy := table <= 0
	if !legacy {
		target = strconv.Itoa(table)
	}

	var errs []error
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		prio := strings.TrimSpace(parts[0])
		if legacy && !legacyNativePriorities[prio] {
			continue
		}
		if !strings.Contains(parts[1], "lookup "+target) {
			continue
		}
		if err := run("ip", "rule", "del", "prio", prio, "lookup", target); err != nil {
			errs = append(errs, fmt.Errorf("deleting policy rule prio %s lookup %s: %w", prio, target, err))
		}
	}

	// A pinned table contains only routes created by bypath's engine. They are
	// removed one by one so nothing outside the reserved table is touched. The
	// listing omits the table name, so every delete must name the table
	// explicitly or iproute2 would resolve it against the main table instead.
	if !legacy {
		routes, routeErr := routesInTable(target)
		if routeErr != nil {
			errs = append(errs, routeErr)
		} else {
			for _, line := range strings.Split(routes, "\n") {
				fields := strings.Fields(line)
				if len(fields) == 0 {
					continue
				}
				args := append([]string{"route", "del"}, fields...)
				args = append(args, "table", target)
				if err := run("ip", args...); err != nil {
					errs = append(errs, fmt.Errorf("deleting route %q from table %s: %w", line, target, err))
				}
			}
			if after, afterErr := routesInTable(target); afterErr != nil {
				errs = append(errs, afterErr)
			} else if strings.TrimSpace(after) != "" {
				errs = append(errs, fmt.Errorf("reserved table %s still holds routes after cleanup: %q", target, strings.TrimSpace(after)))
			}
		}
		if after, afterErr := commandOutput("ip", "rule", "show"); afterErr == nil {
			if strings.Contains(after, "lookup "+target) {
				errs = append(errs, fmt.Errorf("policy rules still reference reserved table %s", target))
			}
		}
	}
	return errors.Join(errs...)
}

// isRecordedRouteAdd proves a stored argument list is the exact shape
// applyRoute writes. Nothing else is ever executed as an inverse.
func isRecordedRouteAdd(args []string) bool {
	return len(args) >= 4 && args[0] == "route" && args[1] == "add"
}

// recordedRouteTable returns the table named in a recorded route, defaulting to
// the main table exactly as iproute2 does.
func recordedRouteTable(args []string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "table" {
			return args[i+1]
		}
	}
	return "main"
}

func routeAttr(fields []string, attr string) string {
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == attr {
			return fields[i+1]
		}
	}
	return ""
}

// routePresent reports whether the recorded route still appears in a table
// listing. Only the identifying attributes are compared.
func routePresent(rec []string, listing string) bool {
	if len(rec) < 3 {
		return false
	}
	dest := rec[2]
	for _, line := range strings.Split(listing, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != dest {
			continue
		}
		match := true
		for _, attr := range []string{"via", "dev"} {
			want := routeAttr(rec, attr)
			if want != "" && routeAttr(fields, attr) != want {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// tableMissing reports iproute2's error for an FIB table with no routes. An
// uninstantiated table is exactly the clean, unused state bypath requires, not
// an inspection failure.
func tableMissing(output string) bool {
	return strings.Contains(output, "FIB table does not exist") ||
		strings.Contains(output, "RTNETLINK answers: No such file or directory")
}

// routesInTable lists a table and treats a missing FIB table as empty.
func routesInTable(table string) (string, error) {
	out, err := commandOutput("ip", "route", "show", "table", table)
	if err != nil {
		if tableMissing(out) {
			return "", nil
		}
		return "", fmt.Errorf("reading routes in table %s: %w", table, err)
	}
	return out, nil
}

// removeRecordedRoute applies the inverse of one recorded route. An already
// absent route is a successful inverse, which lets a second recovery finish
// after an interruption.
func removeRecordedRoute(rec []string) error {
	table := recordedRouteTable(rec)
	out, err := routesInTable(table)
	if err != nil {
		return err
	}
	if !routePresent(rec, out) {
		return nil
	}
	if err := run("ip", reverseRoute(rec)...); err != nil {
		return fmt.Errorf("deleting route %q: %w", strings.Join(rec, " "), err)
	}
	return nil
}

// undoNetworkState applies the inverse of every recorded operation and prunes
// each one from the record only after it succeeds. A failed inverse keeps its
// flag, so the next recovery attempt still knows what remains. It never flushes
// a shared routing table and never deletes an interface it cannot prove it
// created. Fail-closed firewall containment is removed last, after every route,
// rule and interface that could otherwise leak has already been reversed.
func (gw *Gateway) undoNetworkState(st *gatewayRunState) error {
	return gw.undoNetworkStateWith(st, false, false)
}

// undoNetworkStateKeepingContainment reverses the data path but leaves firewall
// containment and the forwarding setting untouched, so a daemon restart never
// opens a window in which LAN traffic can leave directly through the WAN.
func (gw *Gateway) undoNetworkStateKeepingContainment(st *gatewayRunState) error {
	return gw.undoNetworkStateWith(st, true, true)
}

func (gw *Gateway) undoNetworkStateWith(st *gatewayRunState, keepChains, keepForwarding bool) error {
	if st == nil {
		return errNoOwnership
	}
	// Validate the entire record before touching the host. A record containing
	// anything other than a route addition is not trustworthy: refusing the
	// whole pass keeps a corrupt record from causing a partial mutation that
	// cannot be described by the remaining state.
	for _, rec := range st.Routes {
		if !isRecordedRouteAdd(rec) {
			return fmt.Errorf("recorded route %q is not a route addition; refusing to clean up from an untrusted record", strings.Join(rec, " "))
		}
	}
	var errs []error
	prune := func() {
		if err := saveGatewayState(st); err != nil {
			errs = append(errs, fmt.Errorf("persisting cleanup progress: %w", err))
		}
	}

	// Resolver files, host pins and services are restored before the interface
	// and routes they depend on disappear, and long before containment is
	// lifted.
	if st.HostsPinned {
		if err := gw.unpinHostsFromEtcHosts(); err != nil {
			errs = append(errs, err)
		} else {
			st.HostsPinned = false
			prune()
		}
	}
	if st.ResolvChanged {
		if err := gw.restoreResolvConf(); err != nil {
			errs = append(errs, err)
		} else {
			st.ResolvChanged = false
			prune()
		}
	}
	// Services are restored only when the record proves bypath stopped them.
	if st.ResolvedStopped {
		if err := systemctlRun("start", "systemd-resolved"); err != nil {
			errs = append(errs, err)
		} else {
			st.ResolvedStopped = false
			prune()
		}
	}
	if st.DnsmasqStopped {
		if err := systemctlRun("start", "dnsmasq"); err != nil {
			errs = append(errs, err)
		} else {
			st.DnsmasqStopped = false
			prune()
		}
	}
	// Only an explicit NativeRules flag grants permission to remove engine
	// routing. Mode alone is not ownership: a v2 native record that never added
	// rules (for example, rules already present, or a failure before the add)
	// must not fall back to deleting legacy table 2022 entries that belong to
	// another installation. Legacy records take the separate recovery path,
	// which is where the historical 2022 cleanup is allowed.
	if st.NativeRules {
		if st.NativeRuleTable <= 0 {
			errs = append(errs, fmt.Errorf("native ownership is recorded without a reserved table; refusing to guess which table to clean"))
		} else if err := removeEngineNativeRules(st.NativeRuleTable); err != nil {
			errs = append(errs, err)
		} else {
			st.NativeRules = false
			st.NativeRuleTable = 0
			prune()
		}
	}
	for i := len(st.Routes) - 1; i >= 0; i-- {
		rec := st.Routes[i]
		if err := removeRecordedRoute(rec); err != nil {
			errs = append(errs, err)
			continue
		}
		st.Routes = append(st.Routes[:i], st.Routes[i+1:]...)
		prune()
	}
	if st.RuleAdded {
		out, err := commandOutput("ip", "rule", "show")
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("inspecting policy rules: %w", err))
		case !fwmarkRuleAt100(out):
			st.RuleAdded = false
			prune()
		default:
			if err := run("ip", "rule", "del", "fwmark", "0x1", "lookup", "100", "prio", "100"); err != nil {
				errs = append(errs, fmt.Errorf("deleting fwmark rule: %w", err))
			} else {
				st.RuleAdded = false
				prune()
			}
		}
	}
	if st.TunCreated {
		exists, ours, err := tun0State()
		switch {
		case err != nil:
			errs = append(errs, err)
		case !exists:
			st.TunCreated = false
			prune()
		case ours:
			if err := run("ip", "link", "del", "tun0"); err != nil {
				errs = append(errs, err)
			} else {
				st.TunCreated = false
				prune()
			}
		default:
			errs = append(errs, fmt.Errorf("tun0 exists but does not carry bypath's address; refusing to delete it"))
		}
	}
	if st.ForwardingWasOff && !keepForwarding {
		if err := run("sysctl", "-w", "net.ipv4.ip_forward=0"); err != nil {
			errs = append(errs, err)
		} else {
			st.ForwardingWasOff = false
			prune()
		}
	}
	// Containment is the last thing to go. Until this point every packet from
	// the LAN is still dropped unless it can reach tun0. It may only go once
	// forwarding is proven off: removing it after a failed reset would forward
	// LAN traffic directly.
	if !keepChains {
		if st.ForwardingWasOff {
			errs = append(errs, fmt.Errorf("IP forwarding is still enabled after a failed restore; keeping fail-closed LAN containment"))
		} else if err := cleanupBypathChains(); err != nil {
			errs = append(errs, err)
		} else {
			st.V6Isolated = false
			st.ContainmentRetained = false
			st.ContainmentIface = ""
			prune()
		}
	}
	return errors.Join(errs...)
}

// recoverLegacyState handles a plain marker written by an older build. Only
// content-verified objects are removed; nothing is flushed wholesale.
func (gw *Gateway) recoverLegacyState(st *gatewayRunState) error {
	var errs []error
	if err := cleanupBypathChains(); err != nil {
		errs = append(errs, err)
	}
	if err := gw.recoverLegacyDataPath(st); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// recoverLegacyDataPath reverses everything a legacy marker proves bypath
// changed, except the firewall chains. It is split out so a stop can keep the
// fail-closed chains when another service still enables forwarding.
func (gw *Gateway) recoverLegacyDataPath(st *gatewayRunState) error {
	var errs []error
	switch st.Mode {
	case "legacy":
		if out, err := commandOutput("ip", "route", "show", "table", "100"); err != nil {
			errs = append(errs, fmt.Errorf("reading table 100: %w", err))
		} else if strings.Contains(out, "default via 10.0.0.1 dev tun0") {
			if err := run("ip", "route", "del", "default", "via", "10.0.0.1", "dev", "tun0", "table", "100"); err != nil {
				errs = append(errs, err)
			}
		}
		if out, err := commandOutput("ip", "rule", "show"); err != nil {
			errs = append(errs, fmt.Errorf("reading policy rules: %w", err))
		} else if fwmarkRuleAt100(out) {
			if err := run("ip", "rule", "del", "fwmark", "0x1", "lookup", "100", "prio", "100"); err != nil {
				errs = append(errs, err)
			}
		}
		if exists, ours, err := tun0State(); err != nil {
			errs = append(errs, err)
		} else if exists && ours {
			if err := run("ip", "link", "del", "tun0"); err != nil {
				errs = append(errs, err)
			}
		}
	case "native":
		if err := removeEngineNativeRules(0); err != nil {
			errs = append(errs, err)
		}
	}
	if fileExists(resolvLinkBackup) || fileExists(resolvBackup) {
		if err := gw.restoreResolvConf(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := gw.unpinHostsFromEtcHosts(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (gw *Gateway) recoverState(st *gatewayRunState) error {
	if st == nil {
		return errNoOwnership
	}
	if st.LegacyFormat {
		return gw.recoverLegacyState(st)
	}
	return gw.undoNetworkState(st)
}

// recoverStateKeepingContainment is the startup-recovery path for a gateway
// run. A daemon restart must not tear down the fail-closed chains seconds
// before setupRouting rebuilds them, and it must not reset forwarding that the
// next run still needs.
func (gw *Gateway) recoverStateKeepingContainment(st *gatewayRunState) error {
	if st == nil {
		return errNoOwnership
	}
	if st.LegacyFormat {
		return gw.recoverLegacyState(st)
	}
	return gw.undoNetworkStateKeepingContainment(st)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Overridable for tests so no test writes the real host resolver files.
var (
	resolvConfPath = "/etc/resolv.conf"
	hostsFilePath  = "/etc/hosts"
)
