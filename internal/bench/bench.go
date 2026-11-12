// Package bench benchmarks stored links by starting each one on a temporary
// loopback listener and exercising it like a real connection. The CLI and the
// TUI share it so a benchmark row means the same thing in both frontends.
package bench

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/profile"
	"github.com/liberoute/bypath/internal/tunnel"
)

// benchmarkReadiness bounds how long one benchmark engine may take to open its
// listener. It matches the live gateway's per-engine startup budget.
const benchmarkReadiness = 6 * time.Second

// ErrNoGroups reports that no profile group exists.
var ErrNoGroups = errors.New("no groups found")

// ErrNoLinks reports that the selection contains no benchable link.
var ErrNoLinks = errors.New("no testable links found")

// Request selects what to benchmark. Group empty means every group.
type Request struct {
	Group string
}

// Options supplies host-specific paths and policy.
type Options struct {
	HostKeyPolicy    string        // SSH host-key policy; empty means accept-new
	TmpDir           string        // scratch directory for per-link engine configs
	EngineDir        string        // managed engine directory
	PreferredEngine  string        // configured engines.preferred; empty means auto
	EngineOrder      []string      // configured engines.fallback.order
	FallbackEnabled  bool          // configured engines.fallback.enabled
	MaxParallel      int           // 0 selects a safe default
	EndpointResolver *net.Resolver // host bootstrap only; never used for tunneled targets
	ProfileDir       string        // resolves artifact references recorded by an earlier install
	// OnResult is called once per finished link and must not block. It lets a
	// frontend show progress without the bench holding its UI.
	OnResult func(Row)
}

// Row is one link's benchmark outcome.
type Row struct {
	Group    string `json:"group"`
	Remark   string `json:"remark"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Latency  int64  `json:"latency_ms"`
	HTTPS    bool   `json:"https"`
	Passed   bool   `json:"passed"`
}

// Report is the outcome of a full run.
type Report struct {
	Rows    []Row    `json:"rows"`
	Groups  []string `json:"groups"`
	Best    *Row     `json:"best,omitempty"`
	Skipped []Row    `json:"skipped,omitempty"` // faster links lacking HTTPS
	NoHTTPS bool     `json:"no_https,omitempty"`
}

// Probe is a single-link quick check: TCP reachability plus a relayed request.
type Probe struct {
	Ping    time.Duration `json:"ping_ms"`
	PingOK  bool          `json:"ping_ok"`
	Latency time.Duration `json:"latency_ms"`
	HTTPS   bool          `json:"https"`
	Passed  bool          `json:"passed"`
}

// Benchable matches the filter behind 'bypath list', so a bench row and a list
// row always describe the same link.
func Benchable(l *profile.Link) bool {
	return l != nil && l.Port >= 10 && l.Address != "" && l.Address != "0.0.0.0"
}

// EngineFor selects the engine a link is benchmarked with first, mirroring the
// engine the gateway would choose for it.
func EngineFor(link *profile.Link) string {
	return engine.EngineStartOrder(link, "", nil, false)[0]
}

// Run benchmarks every benchable link in the request scope and persists each
// link's HTTPS capability. It does not change the active link.
func Run(ctx context.Context, mgr *profile.Manager, req Request, opts Options) (Report, error) {
	if mgr == nil {
		return Report{}, errors.New("no profile manager")
	}
	all := mgr.ListGroups()
	if len(all) == 0 {
		return Report{}, ErrNoGroups
	}
	groups := all
	if req.Group != "" {
		found := false
		for _, g := range all {
			if g == req.Group {
				found = true
				break
			}
		}
		if !found {
			return Report{}, fmt.Errorf("%w: %q", ErrNoGroups, req.Group)
		}
		groups = []string{req.Group}
	}

	var links []*profile.Link
	for _, name := range groups {
		g, err := mgr.GetGroup(name)
		if err != nil {
			continue
		}
		for _, l := range g.Links {
			if Benchable(l) {
				links = append(links, l)
			}
		}
	}
	if len(links) == 0 {
		return Report{}, ErrNoLinks
	}

	parallel := opts.MaxParallel
	if parallel <= 0 {
		parallel = 6
	}
	if parallel > len(links) {
		parallel = len(links)
	}

	rows := make([]Row, len(links))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i, link := range links {
		wg.Add(1)
		go func(idx int, l *profile.Link) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				rows[idx] = newRow(links[idx], 0, false, false)
				return
			}
			defer func() { <-sem }()
			port := 19870 + idx
			latency, passed, httpsOK := Relay(ctx, l, port, opts)
			row := newRow(l, latency, passed, httpsOK)
			rows[idx] = row
			if opts.OnResult != nil {
				mu.Lock()
				opts.OnResult(row)
				mu.Unlock()
			}
		}(i, link)
	}
	wg.Wait()

	// Persist the HTTPS verdict per group; the link objects are the manager's.
	byGroup := map[string][]*profile.Link{}
	for i, link := range links {
		if rows[i].Passed {
			if rows[i].HTTPS {
				link.HTTPSCapable = 1
			} else {
				link.HTTPSCapable = -1
			}
		}
		byGroup[link.Group] = append(byGroup[link.Group], link)
	}
	for name := range byGroup {
		if err := mgr.SaveGroup(name); err != nil {
			return Report{}, fmt.Errorf("saving group %q: %w", name, err)
		}
	}

	report := Report{Groups: groups}
	results := make([]*profile.BenchResult, len(rows))
	for i := range rows {
		report.Rows = append(report.Rows, rows[i])
		results[i] = &profile.BenchResult{
			Link:    links[i],
			Latency: time.Duration(rows[i].Latency) * time.Millisecond,
			HTTPSOk: rows[i].HTTPS,
			Passed:  rows[i].Passed,
		}
	}
	sel := profile.SelectBest(results)
	if sel.Best != nil {
		for i := range rows {
			if rows[i].Remark == sel.Best.Link.Remark && rows[i].Group == sel.Best.Link.Group {
				best := rows[i]
				report.Best = &best
				break
			}
		}
	}
	report.NoHTTPS = sel.NoHTTPS
	for _, sk := range sel.Skipped {
		for i := range rows {
			if rows[i].Remark == sk.Link.Remark && rows[i].Group == sk.Link.Group {
				report.Skipped = append(report.Skipped, rows[i])
				break
			}
		}
	}
	return report, nil
}

// Activate makes the given link the active one. It resolves the link through
// the manager so the caller only has to name the row it displayed.
func Activate(mgr *profile.Manager, group, remark string) error {
	if mgr == nil {
		return errors.New("no profile manager")
	}
	g, err := mgr.GetGroup(group)
	if err != nil {
		return err
	}
	for _, l := range g.Links {
		if l.Remark == remark {
			mgr.SetActiveLink(l)
			return nil
		}
	}
	return fmt.Errorf("link %q not found in group %q", remark, group)
}

// ProbeLink runs the quick check used by 'bypath bench --single'.
func ProbeLink(ctx context.Context, link *profile.Link, opts Options) Probe {
	var p Probe
	addr := net.JoinHostPort(link.Address, fmt.Sprintf("%d", link.Port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err == nil {
		conn.Close()
		p.Ping = time.Since(start)
		p.PingOK = true
	}
	latency, passed, httpsOK := Relay(ctx, link, 19999, opts)
	p.Latency, p.Passed, p.HTTPS = latency, passed, httpsOK
	return p
}

// Relay starts link on a loopback port and drives one HTTPS request through it.
// It tries the engines in the same order as the live gateway, using an embedded
// engine when this build provides one before falling back to external binaries.
func Relay(ctx context.Context, link *profile.Link, port int, opts Options) (latency time.Duration, ok bool, httpsOk bool) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	if link.Protocol == "ssh" {
		return relaySSH(ctx, link, port, opts)
	}

	linkCopy := *link
	linkCopy.ListenPort = port
	cfgDir := filepath.Join(opts.TmpDir, fmt.Sprintf("bench-%d-%d", os.Getpid(), port))
	defer os.RemoveAll(cfgDir)

	for _, engineName := range engine.EngineStartOrder(link, opts.PreferredEngine, opts.EngineOrder, opts.FallbackEnabled) {
		latency, ok, httpsOk = relayEngine(ctx, &linkCopy, engineName, port, cfgDir, opts)
		if ok {
			return latency, true, httpsOk
		}
		if ctx.Err() != nil {
			return 0, false, false
		}
	}
	return 0, false, false
}

// relayEngine starts one engine on the benchmark port and probes it. The engine
// config is generated for the exact engine that will serve the link, so version
// gates (VLESS Encryption, OpenVPN) are evaluated like a production start.
func relayEngine(ctx context.Context, link *profile.Link, engineName string, port int, cfgDir string, opts Options) (time.Duration, bool, bool) {
	eng := &engine.Engine{Name: engineName}
	// A resolved binary lets the generator run its version gate. Without one,
	// an embedded engine of this build serves the link.
	if binary, found := engine.FindBinary(engineName, opts.EngineDir); found {
		eng.Path = binary
	}
	cg := tunnel.NewConfigGenerator(cfgDir)
	cg.ProfileDir = opts.ProfileDir
	configFile, err := cg.Generate(eng, link)
	if err != nil {
		log.Printf("  ❌ benchmark %s for %q: %v", engineName, link.Remark, err)
		return 0, false, false
	}
	if _, err := isolateConfigFile(configFile); err != nil {
		log.Printf("  ❌ benchmark %s for %q: %v", engineName, link.Remark, err)
		return 0, false, false
	}

	inst, err := engine.StartBenchmark(ctx, engineName, configFile, opts.EngineDir, port, benchmarkReadiness)
	if err != nil {
		log.Printf("  ❌ benchmark %s for %q: %v", engineName, link.Remark, err)
		return 0, false, false
	}
	defer inst.Stop()
	mode := "binary"
	if inst.Embedded {
		mode = "embedded"
	}
	log.Printf("  🧪 benchmark %s for %q on :%d (%s)", engineName, link.Remark, port, mode)

	probeURL, err := PickProbeURL(ctx, port)
	if err != nil {
		return 0, false, false
	}
	start := time.Now()
	// A URL that answered once is reused so the elapsed time reflects one path.
	if _, err := profile.FetchThroughProxy(ctx, port, probeURL, 4096); err != nil {
		return 0, false, false
	}
	elapsed := time.Since(start)

	httpsOk := profile.TestHTTPS(ctx, port)
	return elapsed, true, httpsOk
}

func relaySSH(ctx context.Context, link *profile.Link, port int, opts Options) (time.Duration, bool, bool) {
	cmd := buildSSHBenchCmd(ctx, link, port, opts)
	if cmd == nil {
		return 0, false, false
	}
	if err := cmd.Start(); err != nil {
		return 0, false, false
	}
	defer func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()

	deadline := time.Now().Add(benchmarkReadiness)
	ready := false
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !ready {
		return 0, false, false
	}

	probeURL, err := PickProbeURL(ctx, port)
	if err != nil {
		return 0, false, false
	}
	start := time.Now()
	if _, err := profile.FetchThroughProxy(ctx, port, probeURL, 4096); err != nil {
		return 0, false, false
	}
	elapsed := time.Since(start)

	httpsOk := profile.TestHTTPS(ctx, port)
	return elapsed, true, httpsOk
}

func newRow(l *profile.Link, latency time.Duration, passed, httpsOK bool) Row {
	row := Row{
		Group:    l.Group,
		Remark:   l.Remark,
		Protocol: l.Protocol,
		Address:  l.Address,
		Port:     l.Port,
		HTTPS:    httpsOK,
		Passed:   passed,
	}
	if passed {
		row.Latency = latency.Milliseconds()
	} else {
		row.Latency = -1
	}
	return row
}

func buildSSHBenchCmd(ctx context.Context, link *profile.Link, port int, opts Options) *exec.Cmd {
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		return nil
	}
	sshPassPath := ""
	if link.SSHKeyPath == "" && link.SSHPassword != "" {
		sshPassPath, err = exec.LookPath("sshpass")
		if err != nil {
			return nil
		}
	}
	hostKey := opts.HostKeyPolicy
	if hostKey == "" {
		hostKey = "accept-new"
	}
	knownHosts := tunnel.DefaultSSHKnownHosts()
	if err := tunnel.EnsureSSHKnownHosts(knownHosts); err != nil {
		return nil
	}
	cmd, err := tunnel.BuildSSHCommand(link, tunnel.SSHOptions{
		SSHPath:     sshPath,
		SSHPassPath: sshPassPath,
		ListenAddr:  "127.0.0.1",
		ListenPort:  port,
		KnownHosts:  knownHosts,
		HostKey:     hostKey,
	})
	if err != nil {
		return nil
	}
	c := exec.CommandContext(ctx, cmd.Binary, cmd.Args...)
	c.Env = append(os.Environ(), cmd.Env...)
	return c
}

// SortRowsByRemark orders rows the way 'bypath list' numbers them, which is
// what a --single selection refers to.
func SortRowsByRemark(rows []Row) []Row {
	out := make([]Row, len(rows))
	copy(out, rows)
	sort.Slice(out, func(i, j int) bool { return out[i].Remark < out[j].Remark })
	return out
}
