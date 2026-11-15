package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/liberoute/bypath/internal/build"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/embedbin"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/gateway"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/pidfile"
	"github.com/liberoute/bypath/internal/updater"
)

// maxUpdateSize bounds a self-update download. The binary is a few tens of
// megabytes; a larger response is not the release asset that was verified.
const maxUpdateSize = 256 << 20

// Stop timings. Graceful shutdown must be long enough for the gateway to stop
// its engine and restore host state, but 'bypath stop' must never report
// success while the daemon is still running.
const (
	stopGracePeriod = 15 * time.Second
	stopPollPeriod  = 200 * time.Millisecond
	stopKillWait    = 5 * time.Second
)

func cmdStop(args []string) {
	purgeFirewall := false
	for _, arg := range args {
		switch arg {
		case "--purge-firewall":
			purgeFirewall = true
		default:
			fmt.Printf("Unknown option for stop: %s\n\n", arg)
			printUsage()
			os.Exit(1)
		}
	}

	fmt.Println("🛑 Stopping gateway...")
	if purgeFirewall {
		fmt.Println("⚠️  --purge-firewall: removing all bypath firewall containment.")
		fmt.Println("   Clients that still use this host as their gateway will be forwarded directly.")
	}

	p := paths.Get()
	pidPath := p.PidFile

	pid, running := pidfile.IsRunningFromFile(pidPath)
	stoppedRemotely := false
	if running {
		fmt.Printf("  Stopping bypath (PID: %d)...\n", pid)
		// The control socket lets an unprivileged operator stop a root daemon
		// without write access to the daemon's runtime directory.
		stoppedRemotely = requestDisconnect(pid)
		if !stoppedRemotely {
			requestGracefulStop(p.TmpDir, pid)
		}
	} else {
		fmt.Println("  No running bypath daemon found")
	}

	// A remote stop cannot prove that the daemon's own rollback finished (it may
	// have been killed after the graceful period). Replay the persisted cleanup
	// as root; as an unprivileged user the files are unreadable and the attempt
	// would only produce noise, so it stays scoped to the local-stop path.
	if !stoppedRemotely || os.Geteuid() == 0 {
		pidfile.ClearStopRequest(p.TmpDir)
		// Revert only what a bypath run recorded changing. Shared firewall
		// chains, routing tables and interfaces are never flushed or deleted.
		// Fail-closed LAN containment is kept while another service owns IP
		// forwarding, so a client that still routes through this host cannot
		// fall through to the WAN.
		var err error
		if purgeFirewall {
			err = gateway.PurgePersistedState()
		} else {
			err = gateway.CleanupPersistedState()
		}
		if err != nil {
			fmt.Printf("  ⚠️  Incomplete host-network cleanup: %v\n", err)
		}
	}

	pidfile.Remove(pidPath)

	// Verify truthfully: a removed pidfile is not proof of shutdown.
	if err := verifyStopped(pid); err != nil {
		fmt.Printf("❌ %v\n", err)
		os.Exit(1)
	}
	if !purgeFirewall && gateway.RetainedContainment() {
		fmt.Println("🛡️  Fail-closed LAN containment retained: another service keeps IP forwarding enabled.")
		fmt.Println("   Clients that still use this host as their gateway stay blocked, not forwarded directly.")
		fmt.Println("   Remove it with: bypath stop --purge-firewall")
	}
	fmt.Println("✅ Gateway stopped")
}

// stopProcessGracefully asks the daemon to shut down so its Stop path can
// restore networking, escalating to a kill only if it does not exit in time.
func stopProcessGracefully(pid int) {
	requestGracefulStop(paths.Get().TmpDir, pid)
}

// requestDisconnect asks the running daemon to shut down through the service
// contract. Over the local control socket this needs no privilege beyond the
// socket's own filesystem permissions, so an unprivileged operator can stop a
// root-owned daemon. It reports true only when the process actually exited.
func requestDisconnect(pid int) bool {
	svc, err := openService()
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := svc.Shutdown(ctx); err != nil {
		return false
	}

	deadline := time.Now().Add(stopGracePeriod)
	for time.Now().Before(deadline) {
		if !pidfile.IsRunning(pid) {
			return true
		}
		time.Sleep(stopPollPeriod)
	}
	return false
}

// requestGracefulStop asks the daemon to shut down and escalates to a forced
// kill only when it does not exit in time. The stop-request file is the
// portable channel (Windows has no SIGTERM); Unix also gets SIGTERM so older
// builds without the watcher still exit.
func requestGracefulStop(tmpDir string, pid int) {
	if err := pidfile.RequestStop(tmpDir, pid); err != nil {
		fmt.Printf("  ⚠️  Could not write stop request: %v\n", err)
	}
	if runtime.GOOS != "windows" {
		if proc, err := os.FindProcess(pid); err == nil {
			_ = proc.Signal(syscall.SIGTERM)
		}
	}

	deadline := time.Now().Add(stopGracePeriod)
	for time.Now().Before(deadline) {
		if !pidfile.IsRunning(pid) {
			return
		}
		time.Sleep(stopPollPeriod)
	}

	fmt.Println("  ⚠️  Graceful shutdown timed out — terminating")
	if proc, err := os.FindProcess(pid); err == nil {
		_ = proc.Kill()
	}
	deadline = time.Now().Add(stopKillWait)
	for time.Now().Before(deadline) {
		if !pidfile.IsRunning(pid) {
			return
		}
		time.Sleep(stopPollPeriod)
	}
}

// verifyStopped fails when the daemon, its API, or its proxy listener is still
// alive. Port checks run after CleanupPersistedState, which also kills tracked
// engine children, so a genuine orphan is reported instead of hidden.
func verifyStopped(pid int) error {
	if pid > 0 && pidfile.IsRunning(pid) {
		return fmt.Errorf("daemon (PID %d) is still running after stop", pid)
	}

	apiPort, socksPort := configuredPorts()
	if apiPort > 0 && listenerResponds(apiPort) {
		return fmt.Errorf("bypath API is still listening on :%d", apiPort)
	}
	if socksPort > 0 && portOpen(socksPort) {
		return fmt.Errorf("proxy listener is still active on :%d", socksPort)
	}
	return nil
}

// configuredPorts returns the API and SOCKS ports from config, falling back to
// the daemon defaults when the config cannot be read.
func configuredPorts() (int, int) {
	cfg, err := config.Load(paths.Get().ConfigFile)
	if err != nil || cfg == nil {
		return 8080, 2801
	}
	api, socks := cfg.Server.APIPort, cfg.Server.SOCKSPort
	if api <= 0 {
		api = 8080
	}
	if socks <= 0 {
		socks = 2801
	}
	return api, socks
}

// listenerResponds reports whether an HTTP server answers on port. Any response
// (including 401) proves a listener still owns the port.
func listenerResponds(port int) bool {
	client := &http.Client{Timeout: time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v1/status", port))
	if err != nil {
		return false
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	resp.Body.Close()
	return true
}

func portOpen(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func cmdEngines(args []string) {
	dir, preferSystem := diagnosticEngines(args)
	printEngines(os.Stdout, dir, preferSystem)
}

// printEngines is the read-only engine report. It resolves engines exactly as
// the runtime does (configured directory and prefer_system), and names the
// helpers that this build carries internally instead of reporting them missing.
func printEngines(w io.Writer, dir string, preferSystem bool) {
	mgr := engine.NewManager(config.EnginesConfig{Directory: dir, PreferSystem: preferSystem})
	if err := mgr.Init(); err != nil {
		fmt.Fprintf(w, "❌ engine detection failed: %v\n", err)
		return
	}

	fmt.Fprintf(w, "Engines (directory: %s, prefer_system: %v):\n", dir, preferSystem)
	for _, eng := range mgr.List() {
		source := eng.Source
		if eng.Digest != "" {
			source += ", sha256:" + shortHex(eng.Digest)
		}
		fmt.Fprintf(w, "  %s\n", eng.Name)
		fmt.Fprintf(w, "      %s (%s)\n", eng.Path, source)
	}
	for _, name := range []string{"sing-box", "xray", "wireguard-go"} {
		if build.IsEmbeddedEngine(name) {
			fmt.Fprintf(w, "  %s\n      compiled in (embedded)\n", name)
		}
	}
	if a, ok := embedbin.EmbeddedTun2socksInfo(); ok {
		fmt.Fprintf(w, "  tun2socks\n      compiled in (%s %s/%s, %d bytes, sha256:%s)\n",
			a.Version, a.GOOS, a.GOARCH, a.Size, shortHex(a.SHA256))
	}
	if !mgr.HasSSHPass() {
		fmt.Fprintln(w, "  sshpass: not found (SSH password links need it; key auth does not)")
	}
}

func shortHex(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func cmdUpdate() {
	cfg, cfgErr := config.Load(paths.Get().ConfigFile)
	feedURL := ""
	if cfgErr == nil {
		feedURL = strings.TrimSpace(cfg.Update.URL)
	}
	if feedURL == "" {
		feedURL = strings.TrimSpace(os.Getenv("BYPATH_UPDATE_URL"))
	}
	if feedURL == "" {
		feedURL = build.UpdateURL
	}
	if feedURL == "" {
		// Reporting "latest" would be a guess. This build has no release feed.
		fmt.Println("ℹ️  No update channel is configured for this build.")
		fmt.Println("   Set update.url in the configuration, BYPATH_UPDATE_URL, or install")
		fmt.Println("   updates from the distribution package or the build you were given.")
		return
	}
	socksPort := 2801
	if cfgErr == nil && cfg.Server.SOCKSPort > 0 {
		socksPort = cfg.Server.SOCKSPort
	}

	useProxy := false
	for _, arg := range os.Args[2:] {
		if arg == "--proxy" {
			useProxy = true
		}
		if arg == "--direct" {
			useProxy = false
		}
	}

	if useProxy {
		proxyAddr := fmt.Sprintf("socks5://127.0.0.1:%d", socksPort)
		os.Setenv("ALL_PROXY", proxyAddr)
		defer os.Unsetenv("ALL_PROXY")
	}

	result, err := updater.CheckURL(feedURL)
	if err != nil {
		if !useProxy {
			proxyAddr := fmt.Sprintf("socks5://127.0.0.1:%d", socksPort)
			os.Setenv("ALL_PROXY", proxyAddr)
			result, err = updater.CheckURL(feedURL)
			os.Unsetenv("ALL_PROXY")
		}
		if err != nil {
			fmt.Printf("❌ Update check failed: %v\n", err)
			os.Exit(1)
		}
	}

	if !result.Available {
		fmt.Printf("✅ You're on the latest version (%s)\n", result.CurrentVersion)
		return
	}

	fmt.Printf("🆕 Update available: %s → %s\n", result.CurrentVersion, result.LatestVersion)

	if result.DownloadURL == "" {
		fmt.Println("❌ No download URL found for your platform")
		return
	}

	fmt.Printf("📥 Downloading: %s\n", result.AssetName)

	exe, _ := os.Executable()

	transport := &http.Transport{Proxy: http.ProxyFromEnvironment}
	client := &http.Client{Timeout: 5 * time.Minute, Transport: transport}
	resp, downloadErr := client.Get(result.DownloadURL)
	if downloadErr != nil || (resp != nil && resp.StatusCode != 200) {
		if resp != nil {
			resp.Body.Close()
		}
		if !useProxy {
			fmt.Printf("   ⚠️  Direct download failed, trying via proxy...\n")
			proxyURL := fmt.Sprintf("socks5://127.0.0.1:%d", socksPort)
			if u, parseErr := url.Parse(proxyURL); parseErr == nil {
				transport2 := &http.Transport{Proxy: http.ProxyURL(u)}
				client2 := &http.Client{Timeout: 5 * time.Minute, Transport: transport2}
				resp, downloadErr = client2.Get(result.DownloadURL)
			}
		}
	}

	if downloadErr != nil {
		fmt.Printf("❌ Download failed: %v\n", downloadErr)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		fmt.Printf("❌ Download failed: HTTP %d\n", resp.StatusCode)
		os.Exit(1)
	}

	if resp.ContentLength > maxUpdateSize {
		fmt.Printf("❌ Download is larger than the %d byte limit\n", maxUpdateSize)
		os.Exit(1)
	}
	totalSize := resp.ContentLength

	// Stage beside the target so the final rename is a single atomic replace on
	// the same filesystem. A crash leaves either the old binary or the verified
	// new one, never a half-written install.
	tmpOut, err := os.CreateTemp(filepath.Dir(exe), ".bypath-update-*")
	if err != nil {
		fmt.Printf("❌ Cannot create temp file: %v\n", err)
		os.Exit(1)
	}
	tmpFile := tmpOut.Name()

	var written int64
	buf := make([]byte, 32*1024)
	lastPrint := time.Now()
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			written += int64(n)
			if written > maxUpdateSize {
				tmpOut.Close()
				os.Remove(tmpFile)
				fmt.Printf("\n❌ Download exceeded the %d byte limit\n", maxUpdateSize)
				os.Exit(1)
			}
			_, writeErr := tmpOut.Write(buf[:n])
			if writeErr != nil {
				tmpOut.Close()
				os.Remove(tmpFile)
				fmt.Printf("\n❌ Write error: %v\n", writeErr)
				os.Exit(1)
			}
			if time.Since(lastPrint) > 200*time.Millisecond {
				if totalSize > 0 {
					pct := float64(written) / float64(totalSize) * 100
					bar := progressBar(pct, 30)
					fmt.Printf("\r   %s %.1f%% (%s / %s)", bar, pct, humanSize(written), humanSize(totalSize))
				} else {
					fmt.Printf("\r   %s downloaded", humanSize(written))
				}
				lastPrint = time.Now()
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			tmpOut.Close()
			os.Remove(tmpFile)
			fmt.Printf("\n❌ Download error: %v\n", readErr)
			os.Exit(1)
		}
	}
	tmpOut.Close()

	if totalSize > 0 {
		fmt.Printf("\r   %s 100%% (%s)          \n", progressBar(100, 30), humanSize(written))
	} else {
		fmt.Printf("\r   Downloaded %s          \n", humanSize(written))
	}

	// Never replace the running executable with bytes that were not verified
	// against the digest published for this exact release asset.
	if result.DownloadDigest == "" {
		os.Remove(tmpFile)
		fmt.Println("❌ Release asset has no published sha256 digest — refusing to install an unverified binary")
		fmt.Println("   Install the new release manually from the project's releases page.")
		os.Exit(1)
	}
	if err := updater.VerifyFile(tmpFile, result.DownloadDigest); err != nil {
		os.Remove(tmpFile)
		fmt.Printf("❌ Downloaded binary failed verification: %v\n", err)
		os.Exit(1)
	}

	// Permissions are applied only after the bytes are proven to be the
	// published asset, and the replace is one atomic rename.
	os.Chmod(tmpFile, 0755)
	if err := os.Rename(tmpFile, exe); err != nil {
		os.Remove(tmpFile)
		fmt.Printf("❌ Cannot install new binary: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✅ Updated to %s!\n", result.LatestVersion)

	// Restart the gateway if it was running, so the new binary takes effect.
	pidPath := paths.Get().PidFile
	if pid, running := pidfile.IsRunningFromFile(pidPath); running {
		fmt.Printf("🔄 Restarting gateway (PID: %d)...\n", pid)
		stopProcessGracefully(pid)
		if err := gateway.CleanupPersistedState(); err != nil {
			fmt.Printf("  ⚠️  Incomplete host-network cleanup: %v\n", err)
		}
		restarted := false
		if _, err := exec.LookPath("systemctl"); err == nil {
			if out, _ := exec.Command("systemctl", "is-active", "bypath").Output(); strings.TrimSpace(string(out)) == "active" || strings.TrimSpace(string(out)) == "activating" {
				if err := exec.Command("systemctl", "restart", "bypath").Run(); err == nil {
					fmt.Println("  ✓ systemd service restarted")
					restarted = true
				}
			}
		}
		if !restarted && gateway.RetainedContainment() {
			fmt.Println("  🛡️  LAN containment retained (another service keeps IP forwarding enabled).")
			fmt.Println("     Start the gateway again, or run 'bypath stop --purge-firewall' to remove it.")
		}
	}
	if result.ReleaseNotes != "" {
		fmt.Printf("\n   Release notes:\n%s\n", result.ReleaseNotes)
	}
	fmt.Printf("\n   Changelog: https://github.com/liberoute/bypath/compare/v%s...v%s\n", result.CurrentVersion, result.LatestVersion)
}

func progressBar(pct float64, width int) string {
	filled := int(pct / 100 * float64(width))
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return "[" + bar + "]"
}

func humanSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	} else {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
}
