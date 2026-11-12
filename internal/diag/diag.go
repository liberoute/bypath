// Package diag implements `bypath doctor`: read-only observations about an
// installation. No check here starts, stops or reconfigures anything, and none
// prints a credential, a subscription URL or a raw proxy URI.
package diag

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/liberoute/bypath/internal/build"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/profile"
)

// Status is the outcome of one check.
type Status string

const (
	Pass Status = "pass"
	Warn Status = "warn"
	Fail Status = "fail"
	Skip Status = "skip"
	Info Status = "info"
)

// Check is one observation with the evidence behind it.
type Check struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Status      Status   `json:"status"`
	Summary     string   `json:"summary"`
	Detail      []string `json:"detail,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// Report is the complete doctor output.
type Report struct {
	Tool        string  `json:"tool"`
	Version     string  `json:"version"`
	Variant     string  `json:"variant"`
	Commit      string  `json:"commit"`
	BuildDate   string  `json:"build_date"`
	OS          string  `json:"os"`
	Arch        string  `json:"arch"`
	ConfigPath  string  `json:"config_path"`
	GeneratedAt string  `json:"generated_at"`
	ReadOnly    bool    `json:"read_only"`
	Checks      []Check `json:"checks"`
	Summary     Summary `json:"summary"`
}

// Summary counts the checks by status.
type Summary struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
	Skip int `json:"skip"`
	Info int `json:"info"`
}

// Egress is the result of asking a running gateway for its exit addresses.
type Egress struct {
	Tunnel      string `json:"tunnel_exit,omitempty"`
	TunnelError string `json:"tunnel_error,omitempty"`
	Direct      string `json:"direct_ip,omitempty"`
	DirectError string `json:"direct_error,omitempty"`
	Same        bool   `json:"same"`
	Note        string `json:"note,omitempty"`
}

// Host isolates the operating-system probes so the checks are testable.
type Host interface {
	GOOS() string
	TUN() (bool, string)
	// Listeners describes local TCP and UDP listeners bound to port.
	Listeners(port int) []string
	SystemdUnit(name string) (installed bool, state string)
	FirewallChain(chain string) (rules int, available bool, detail string)
	IsRoot() bool
	Dial(addr string, timeout time.Duration) error
}

// Options configures one run.
type Options struct {
	ConfigPath string
	Host       Host
	// Egress is nil unless the operator asked for a live exit-address probe.
	Egress func(context.Context) (Egress, error)
}

// Run performs every check. It never returns an error: a broken installation is
// reported as failing checks so the JSON output stays machine-readable.
func Run(ctx context.Context, opts Options) *Report {
	host := opts.Host
	if host == nil {
		host = DefaultHost()
	}
	rep := &Report{
		Tool:        build.Name,
		Version:     build.Version,
		Variant:     build.Variant,
		Commit:      build.Commit,
		BuildDate:   build.BuildDate,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		ConfigPath:  opts.ConfigPath,
		GeneratedAt: time.Now().Format(time.RFC3339),
		ReadOnly:    true,
	}
	rep.add(rep.buildCheck(host))

	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		rep.add(Check{
			ID:          "config",
			Title:       "Configuration",
			Status:      Fail,
			Summary:     fmt.Sprintf("%s could not be loaded: %v", opts.ConfigPath, err),
			Remediation: "Run `bypath setup` to create a valid configuration, or point doctor at one with --config.",
		})
		rep.summarize()
		return rep
	}
	rep.add(checkConfig(cfg))
	rep.add(checkEngines(cfg))
	rep.add(checkTUN(cfg, host))
	rep.add(checkRouting(cfg))
	rep.add(checkDNS(cfg, host))
	rep.add(checkLAN(cfg, host))
	rep.add(checkAPI(cfg))
	rep.add(checkService(host))
	rep.add(checkProxy(cfg, host))
	rep.add(checkConnection(cfg))
	rep.add(checkEgress(ctx, opts))

	rep.summarize()
	return rep
}

func (r *Report) add(c Check) { r.Checks = append(r.Checks, c) }

func (r *Report) summarize() {
	r.Summary = Summary{}
	for _, c := range r.Checks {
		switch c.Status {
		case Pass:
			r.Summary.Pass++
		case Warn:
			r.Summary.Warn++
		case Fail:
			r.Summary.Fail++
		case Skip:
			r.Summary.Skip++
		default:
			r.Summary.Info++
		}
	}
}

func (r *Report) buildCheck(host Host) Check {
	detail := []string{
		fmt.Sprintf("version %s", build.Version),
		fmt.Sprintf("variant %s", build.Variant),
		fmt.Sprintf("commit %s", build.Commit),
		fmt.Sprintf("built %s", build.BuildDate),
		fmt.Sprintf("platform %s/%s", runtime.GOOS, runtime.GOARCH),
	}
	var embedded []string
	for _, name := range []string{"sing-box", "xray", "wireguard-go"} {
		if build.IsEmbeddedEngine(name) {
			embedded = append(embedded, name)
		}
	}
	if len(embedded) > 0 {
		detail = append(detail, "embedded engines: "+strings.Join(embedded, ", "))
	} else {
		detail = append(detail, "embedded engines: none (lite build; external engine required)")
	}
	status := Pass
	summary := fmt.Sprintf("%s %s (%s)", build.Name, build.Version, build.Variant)
	if build.Commit == "" || build.Commit == "unknown" {
		status = Warn
		summary = "this binary carries no source commit, so it cannot be traced to a revision"
	}
	return Check{ID: "build", Title: "Build", Status: status, Summary: summary, Detail: detail}
}

func checkConfig(cfg *config.Config) Check {
	detail := []string{fmt.Sprintf("mode: %s", modeLabel(cfg))}
	if cfg.Gateway.Enabled {
		detail = append(detail, fmt.Sprintf("gateway interface: %s", orDefault(cfg.Gateway.Interface, "auto")))
		detail = append(detail, fmt.Sprintf("dns mode: %s", orDefault(cfg.Gateway.DNSMode, "strict")))
	}
	detail = append(detail, fmt.Sprintf("proxy listener: %s:%d", cfg.Server.SOCKSListenAddress(), cfg.Server.SOCKSPort))
	detail = append(detail, fmt.Sprintf("management api: %s:%d", cfg.Server.Listen, cfg.Server.APIPort))
	if cfg.Server.Web.Enabled {
		detail = append(detail, fmt.Sprintf("web panel: %s:%d", cfg.Server.Web.Listen, cfg.Server.Web.Port))
	} else {
		detail = append(detail, "web panel: disabled")
	}
	return Check{
		ID:      "config",
		Title:   "Configuration",
		Status:  Pass,
		Summary: "configuration loads and passes validation",
		Detail:  detail,
	}
}

// modeLabel names the two operating modes without guessing what the operator
// intended.
func modeLabel(cfg *config.Config) string {
	if cfg.Gateway.Enabled {
		return "gateway (LAN devices use this host as their gateway and DNS)"
	}
	return "proxy-only (no LAN takeover; clients use the SOCKS listener explicitly)"
}

func checkEngines(cfg *config.Config) Check {
	sources := map[string]string{}
	for _, name := range []string{"sing-box", "xray", "tun2socks", "wireguard-go", "openvpn"} {
		sources[name] = engineSource(cfg, name)
	}
	var detail []string
	tunnel := 0
	for _, name := range []string{"sing-box", "xray"} {
		src := sources[name]
		switch {
		case src == "embedded":
			detail = append(detail, name+": embedded in this binary")
			tunnel++
		case src != "":
			detail = append(detail, name+": "+src)
			tunnel++
		default:
			detail = append(detail, name+": not found")
		}
	}
	for _, name := range []string{"tun2socks", "wireguard-go", "openvpn"} {
		if src := sources[name]; src == "" {
			detail = append(detail, name+": not found (optional)")
		} else {
			detail = append(detail, name+": "+src)
		}
	}
	if tunnel == 0 {
		return Check{
			ID:          "engine",
			Title:       "Tunnel engine",
			Status:      Fail,
			Summary:     "no sing-box or xray engine is available, so no connection can be established",
			Detail:      detail,
			Remediation: "Install the full release asset (engines compiled in) or place a sing-box/xray binary in the engines directory.",
		}
	}
	return Check{
		ID:      "engine",
		Title:   "Tunnel engine",
		Status:  Pass,
		Summary: fmt.Sprintf("%d tunnel engine(s) available", tunnel),
		Detail:  detail,
	}
}

// engineSource reports where an engine comes from without creating the engines
// directory (engine.Manager.Init does, and doctor must not write).
func engineSource(cfg *config.Config, name string) string {
	if build.IsEmbeddedEngine(name) {
		return "embedded"
	}
	if p, err := exec.LookPath(name); err == nil {
		return "system: " + p
	}
	for _, candidate := range []string{name, name + ".exe"} {
		p := filepath.Join(cfg.Engines.Directory, candidate)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return "local: " + p
		}
	}
	return ""
}

func checkTUN(cfg *config.Config, host Host) Check {
	if !cfg.Gateway.Enabled {
		return Check{
			ID:      "tun",
			Title:   "TUN device",
			Status:  Info,
			Summary: "not required: this installation is proxy-only",
		}
	}
	if host.GOOS() != "linux" {
		return Check{
			ID:          "tun",
			Title:       "TUN device",
			Status:      Fail,
			Summary:     "gateway mode needs a Linux TUN device; this platform is not supported for gateway mode",
			Remediation: "Run the gateway on Linux, or switch this installation to proxy-only with `bypath setup`.",
		}
	}
	if !cfg.Gateway.NativeTUN {
		return Check{
			ID:          "tun",
			Title:       "TUN device",
			Status:      Warn,
			Summary:     "gateway.native_tun is false: the legacy datapath needs an external tun2socks helper",
			Remediation: "Set gateway.native_tun: true to use the engine's native TUN inbound, or install the full release asset that carries tun2socks.",
		}
	}
	exists, detail := host.TUN()
	if !exists {
		return Check{
			ID:          "tun",
			Title:       "TUN device",
			Status:      Fail,
			Summary:     "gateway mode is enabled but there is no usable TUN device",
			Detail:      []string{detail},
			Remediation: "Load the tun module (`modprobe tun`) or enable /dev/net/tun on this host; until then use proxy-only mode.",
		}
	}
	return Check{ID: "tun", Title: "TUN device", Status: Pass, Summary: "native TUN available", Detail: []string{detail}}
}

func checkRouting(cfg *config.Config) Check {
	final, deny := finalOutbound(cfg)
	detail := []string{fmt.Sprintf("catch-all outbound: %s", final)}
	if deny {
		detail[0] = "catch-all outbound: deny (traffic not matched by a rule is rejected)"
	}
	if n := len(cfg.Routing.Rules); n > 0 {
		detail = append(detail, fmt.Sprintf("%d routing rule(s)", n))
	} else {
		detail = append(detail, "no routing rules: every connection uses the tunnel")
	}
	if !cfg.Gateway.Enabled {
		return Check{
			ID:      "routing",
			Title:   "Routing",
			Status:  Pass,
			Summary: "proxy-only: only clients that use the proxy port are affected",
			Detail:  detail,
		}
	}
	selection, links := readSelection(cfg)
	if links == 0 {
		return Check{
			ID:          "routing",
			Title:       "Routing",
			Status:      Fail,
			Summary:     "gateway mode is enabled but no connection is stored",
			Detail:      detail,
			Remediation: "Add and select a working connection (panel, `bypath setup` or `bypath add`) before enabling gateway mode; otherwise LAN traffic has no working path.",
		}
	}
	if selection == "" {
		return Check{
			ID:          "routing",
			Title:       "Routing",
			Status:      Fail,
			Summary:     fmt.Sprintf("gateway mode is enabled but no connection is selected (%d stored)", links),
			Detail:      detail,
			Remediation: "Select one connection first; the gateway refuses to start without an active link.",
		}
	}
	status := Pass
	summary := fmt.Sprintf("%d connection(s); unmatched traffic goes %s", links, strings.ToUpper(final))
	if strings.EqualFold(final, "direct") {
		status = Warn
		summary = "the catch-all rule is DIRECT, so unmatched LAN traffic would leave outside the tunnel"
	}
	return Check{ID: "routing", Title: "Routing", Status: status, Summary: summary, Detail: detail}
}

// readSelection reports the active "group/remark" selection and how many
// connections are stored, without creating or rewriting anything.
func readSelection(cfg *config.Config) (string, int) {
	dir := cfg.Profiles.Directory
	links := 0
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		var group profile.Group
		if err := json.Unmarshal(data, &group); err != nil {
			continue
		}
		links += len(group.Links)
	}
	data, err := os.ReadFile(filepath.Join(dir, ".active"))
	if err != nil {
		return "", links
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		return "", links
	}
	group, remark := strings.TrimSpace(lines[0]), strings.TrimSpace(lines[1])
	if group == "" || remark == "" {
		return "", links
	}
	return group + "/" + remark, links
}

func finalOutbound(cfg *config.Config) (string, bool) {
	final := "proxy"
	deny := false
	for _, rule := range cfg.Routing.Rules {
		if !strings.EqualFold(strings.TrimSpace(rule.Match), "default") {
			continue
		}
		if config.IsDenyOutbound(rule.Outbound) {
			deny = true
			continue
		}
		final = rule.Outbound
	}
	return final, deny
}

func checkDNS(cfg *config.Config, host Host) Check {
	port := cfg.Server.DNSPort
	if port <= 0 {
		port = 53
	}
	listeners := host.Listeners(port)
	var active []string
	for _, name := range []string{"systemd-resolved", "dnsmasq", "named", "unbound"} {
		if installed, state := host.SystemdUnit(name); installed && state == "active" {
			active = append(active, name)
		}
	}
	detail := []string{fmt.Sprintf("gateway dns port: %d", port)}
	if len(listeners) > 0 {
		detail = append(detail, "listening now: "+strings.Join(listeners, ", "))
	}
	if len(active) > 0 {
		detail = append(detail, "active resolver services: "+strings.Join(active, ", "))
	}
	if !cfg.Gateway.Enabled {
		check := Check{
			ID:      "dns",
			Title:   "DNS",
			Status:  Info,
			Summary: "proxy-only: this installation does not answer DNS for the LAN",
			Detail:  detail,
		}
		if len(active) > 0 {
			check.Detail = append(check.Detail, "an existing resolver stays in charge; bypath never stops it")
		}
		return check
	}
	_, serviceState := host.SystemdUnit("bypath")
	if len(listeners) > 0 {
		if serviceState == "active" {
			return Check{
				ID:      "dns",
				Title:   "DNS",
				Status:  Pass,
				Summary: fmt.Sprintf("port %d is bound while the gateway service runs", port),
				Detail:  detail,
			}
		}
		return Check{
			ID:          "dns",
			Title:       "DNS",
			Status:      Fail,
			Summary:     fmt.Sprintf("port %d is already in use, so gateway DNS would fail to start", port),
			Detail:      detail,
			Remediation: fmt.Sprintf("Choose another gateway dns_port in `bypath setup`, or move the other resolver yourself. Bypath does not stop systemd-resolved or dnsmasq."),
		}
	}
	return Check{
		ID:      "dns",
		Title:   "DNS",
		Status:  Pass,
		Summary: fmt.Sprintf("port %d is free for the gateway resolver", port),
		Detail:  detail,
	}
}

func checkLAN(cfg *config.Config, host Host) Check {
	listen := cfg.Server.SOCKSListenAddress()
	detail := []string{fmt.Sprintf("socks listener: %s:%d", listen, cfg.Server.SOCKSPort)}
	if !cfg.Server.SOCKSAllowLAN {
		return Check{
			ID:      "lan",
			Title:   "Proxy exposure",
			Status:  Pass,
			Summary: "the unauthenticated proxy stays on loopback",
			Detail:  detail,
		}
	}
	if config.IsLoopbackHost(listen) {
		return Check{
			ID:      "lan",
			Title:   "Proxy exposure",
			Status:  Warn,
			Summary: "socks_allow_lan is set but the listener is still loopback, so no LAN client can use it",
			Detail:  detail,
		}
	}
	lans, err := config.TrustedLANs("", cfg.Server.SOCKSAllowCIDRs)
	if err != nil {
		return Check{
			ID:          "lan",
			Title:       "Proxy exposure",
			Status:      Fail,
			Summary:     "the LAN proxy bind has no unambiguous trusted network: " + err.Error(),
			Detail:      detail,
			Remediation: "Name the trusted subnet in server.socks_trusted_cidrs, or set the LAN interface in `bypath setup`.",
		}
	}
	trusted := make([]string, 0, len(lans))
	for _, lan := range lans {
		trusted = append(trusted, fmt.Sprintf("%s via %s", lan.CIDR, lan.Interface))
	}
	detail = append(detail, "trusted sources: "+strings.Join(trusted, ", "))
	if host.GOOS() == "linux" && !host.IsRoot() {
		return Check{
			ID:          "lan",
			Title:       "Proxy exposure",
			Status:      Fail,
			Summary:     "a LAN proxy bind needs root to install its firewall guard",
			Detail:      detail,
			Remediation: "Run the gateway as root (the systemd unit does), or keep the proxy on loopback.",
		}
	}
	rules, available, fwDetail := host.FirewallChain("BYPATH_PROXY_IN")
	if !available {
		return Check{
			ID:          "lan",
			Title:       "Proxy exposure",
			Status:      Fail,
			Summary:     "the firewall guard cannot be inspected, so the LAN listener cannot be trusted",
			Detail:      append(detail, fwDetail),
			Remediation: "Install iptables, or keep the proxy on loopback.",
		}
	}
	if rules == 0 {
		detail = append(detail, "guard chain present but empty (the gateway is not running)")
		return Check{
			ID:          "lan",
			Title:       "Proxy exposure",
			Status:      Warn,
			Summary:     "the trusted networks are named, but the firewall guard is not installed right now",
			Detail:      detail,
			Remediation: "Start the gateway before relying on the LAN listener; it installs the guard before it binds.",
		}
	}
	detail = append(detail, fmt.Sprintf("guard chain BYPATH_PROXY_IN: %d rule(s)", rules))
	return Check{
		ID:      "lan",
		Title:   "Proxy exposure",
		Status:  Pass,
		Summary: "LAN proxy is limited to the named trusted networks by the firewall guard",
		Detail:  detail,
	}
}

func checkAPI(cfg *config.Config) Check {
	detail := []string{fmt.Sprintf("management api: %s:%d", cfg.Server.Listen, cfg.Server.APIPort)}
	if cfg.Server.APIToken != "" {
		detail = append(detail, "api token: set")
	} else if config.IsLoopbackHost(cfg.Server.Listen) {
		detail = append(detail, "api token: not set (loopback and control socket only)")
	} else {
		return Check{
			ID:          "api",
			Title:       "Management API",
			Status:      Fail,
			Summary:     "the management API is bound off-loopback without a token",
			Detail:      detail,
			Remediation: "Set server.api_token, or bind the API to 127.0.0.1.",
		}
	}
	if !cfg.Server.Web.Enabled {
		detail = append(detail, "web panel: disabled")
		return Check{ID: "api", Title: "Management API", Status: Pass, Summary: "management plane stays local or authenticated", Detail: detail}
	}
	detail = append(detail, fmt.Sprintf("web panel: %s:%d", cfg.Server.Web.Listen, cfg.Server.Web.Port))
	if cfg.Server.Web.Listen != "" && !config.IsLoopbackHost(cfg.Server.Web.Listen) {
		if !cfg.Server.Web.AllowLAN {
			return Check{
				ID:      "api",
				Title:   "Management API",
				Status:  Fail,
				Summary: "the web panel bind is not loopback but allow_lan is false",
				Detail:  detail,
				Remediation: "Set server.web.allow_lan: true deliberately, or bind the panel to loopback behind a TLS proxy.",
			}
		}
		if len(cfg.Server.Web.AllowedOrigins) == 0 {
			detail = append(detail, "allowed_origins: empty (only same-origin requests are accepted)")
		}
		return Check{
			ID:          "api",
			Title:       "Management API",
			Status:      Warn,
			Summary:     "the web panel is reachable from the LAN",
			Detail:      detail,
			Remediation: "Terminate TLS in a reverse proxy on this host and keep the panel account password strong; the panel creates its first administrator on first local visit.",
		}
	}
	return Check{ID: "api", Title: "Management API", Status: Pass, Summary: "web panel stays on loopback", Detail: detail}
}

func checkService(host Host) Check {
	if host.GOOS() != "linux" {
		return Check{ID: "service", Title: "Service", Status: Skip, Summary: "systemd supervision is Linux-only"}
	}
	installed, state := host.SystemdUnit("bypath")
	switch {
	case !installed:
		return Check{
			ID:          "service",
			Title:       "Service",
			Status:      Info,
			Summary:     "no bypath systemd unit is installed (the gateway runs in the foreground)",
			Remediation: "Re-run the installer without --no-systemd to supervise it, or keep running `bypath run` yourself.",
		}
	case state == "active":
		return Check{ID: "service", Title: "Service", Status: Pass, Summary: "systemd reports bypath as active"}
	case state == "" || state == "unknown":
		return Check{ID: "service", Title: "Service", Status: Warn, Summary: "the unit exists but its state could not be read"}
	default:
		return Check{
			ID:          "service",
			Title:       "Service",
			Status:      Warn,
			Summary:     "systemd reports bypath as " + state,
			Remediation: "Inspect `systemctl status bypath` and `journalctl -u bypath`. Try `bypath doctor` again after fixing the cause.",
		}
	}
}

func checkProxy(cfg *config.Config, host Host) Check {
	endpoints := config.ProxyEndpoints(cfg.Server)
	for _, ep := range endpoints {
		if err := host.Dial(ep, 700*time.Millisecond); err == nil {
			return Check{
				ID:      "proxy",
				Title:   "Proxy listener",
				Status:  Pass,
				Summary: "the proxy accepts TCP connections on " + ep,
				Detail:  []string{"a listener answers; authentication with a test request is still required from a client"},
			}
		}
	}
	// Without a stored connection there is no engine, so the proxy port is
	// closed by design: saying "the gateway is not running" would send the
	// operator to restart a service that is already up.
	if _, links := readSelection(cfg); links == 0 {
		return Check{
			ID:          "proxy",
			Title:       "Proxy listener",
			Status:      Info,
			Summary:     "no connection is configured yet, so the engine and the proxy port are not started",
			Detail:      []string{"expected at " + strings.Join(endpoints, ", ") + " once a connection is selected"},
			Remediation: "Import or add a connection, select it, then restart the gateway.",
		}
	}
	_, state := host.SystemdUnit("bypath")
	status := Info
	summary := "the proxy is not listening; the gateway is not running"
	remediation := "Start the gateway with `bypath run` or `systemctl start bypath`."
	if state == "active" {
		status = Warn
		summary = "the service is active but the proxy port does not answer"
		remediation = "Check `systemctl status bypath` and the log; the engine may have failed to start."
	}
	return Check{
		ID:          "proxy",
		Title:       "Proxy listener",
		Status:      status,
		Summary:     summary,
		Detail:      []string{"expected at " + strings.Join(endpoints, ", ")},
		Remediation: remediation,
	}
}

func checkConnection(cfg *config.Config) Check {
	selection, links := readSelection(cfg)
	if links == 0 {
		return Check{
			ID:          "connection",
			Title:       "Connection",
			Status:      Info,
			Summary:     "no connection is configured yet",
			Remediation: "Add a proxy URI or subscription in `bypath setup`, the panel, or with `bypath add`.",
		}
	}
	detail := []string{fmt.Sprintf("%d connection(s) stored", links)}
	if selection != "" {
		detail = append(detail, "selected: "+selection)
	} else {
		detail = append(detail, "no active selection recorded")
	}
	status := Pass
	summary := "a connection is configured; live health is only proven by a connection test"
	if selection == "" {
		status = Warn
		summary = "connections exist but none is selected"
	}
	return Check{ID: "connection", Title: "Connection", Status: status, Summary: summary, Detail: detail}
}

func checkEgress(ctx context.Context, opts Options) Check {
	if opts.Egress == nil {
		return Check{
			ID:      "egress",
			Title:   "Tunnel egress",
			Status:  Skip,
			Summary: "not measured; rerun with --egress to compare the tunnel exit with the direct address",
		}
	}
	res, err := opts.Egress(ctx)
	if err != nil {
		return Check{
			ID:          "egress",
			Title:       "Tunnel egress",
			Status:      Warn,
			Summary:     "the running gateway could not be queried: " + err.Error(),
			Remediation: "Start the gateway, then rerun `bypath doctor --egress`.",
		}
	}
	detail := []string{}
	if res.Tunnel != "" {
		detail = append(detail, "tunnel exit: "+res.Tunnel)
	}
	if res.TunnelError != "" {
		detail = append(detail, "tunnel: "+res.TunnelError)
	}
	if res.Direct != "" {
		detail = append(detail, "this host's direct address: "+res.Direct)
	}
	if res.DirectError != "" {
		detail = append(detail, "direct: "+res.DirectError)
	}
	if res.Note != "" {
		detail = append(detail, res.Note)
	}
	switch {
	case res.Tunnel == "":
		return Check{ID: "egress", Title: "Tunnel egress", Status: Fail, Summary: "no tunnel exit address could be measured", Detail: detail}
	case res.Same:
		return Check{ID: "egress", Title: "Tunnel egress", Status: Warn, Summary: "the tunnel exit and the direct address are the same", Detail: detail}
	default:
		return Check{ID: "egress", Title: "Tunnel egress", Status: Pass, Summary: "traffic leaves through a different address than this host's direct path", Detail: detail}
	}
}

func orDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
