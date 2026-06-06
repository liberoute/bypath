package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/engine"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/pidfile"
	"github.com/liberoute/bypath/internal/updater"
)

func cmdStop() {
	fmt.Println("🛑 Stopping gateway...")

	pidPath := paths.Get().PidFile

	pid, running := pidfile.IsRunningFromFile(pidPath)
	if running {
		fmt.Printf("  Stopping bypath (PID: %d)...\n", pid)
		if err := pidfile.StopFromFile(pidPath); err != nil {
			fmt.Printf("  ⚠️  Could not kill process: %v\n", err)
		} else {
			fmt.Println("  ✓ bypath stopped")
		}
	} else {
		exec.Command("pkill", "-f", "bypath run").Run()
	}

	exec.Command("pkill", "sing-box").Run()
	exec.Command("pkill", "-f", "xray run -c /tmp/bypath").Run()
	exec.Command("pkill", "dns2socks").Run()
	exec.Command("pkill", "tun2socks").Run()
	exec.Command("ip", "link", "del", "tun0").Run()
	exec.Command("iptables", "-t", "mangle", "-F").Run()
	exec.Command("iptables", "-t", "nat", "-F", "POSTROUTING").Run()
	exec.Command("iptables", "-F", "FORWARD").Run()
	exec.Command("ip", "rule", "del", "fwmark", "0x1", "lookup", "100").Run()
	exec.Command("ip", "rule", "del", "fwmark", "0x66/0xff", "lookup", "200").Run()

	pidfile.Remove("")

	fmt.Println("✅ Gateway stopped")
}

func cmdEngines(_ []string) {
	cfg := config.EnginesConfig{Directory: engineDir(), PreferSystem: true}
	mgr := engine.NewManager(cfg)
	mgr.Init()

	fmt.Println("Available engines:")
}

func cmdUpdate() {
	cfg, cfgErr := config.Load(paths.Get().ConfigFile)
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

	result, err := updater.Check()
	if err != nil {
		if !useProxy {
			proxyAddr := fmt.Sprintf("socks5://127.0.0.1:%d", socksPort)
			os.Setenv("ALL_PROXY", proxyAddr)
			result, err = updater.Check()
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
	tmpFile := exe + ".new"

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

	totalSize := resp.ContentLength
	out, err := os.Create(tmpFile)
	if err != nil {
		fmt.Printf("❌ Cannot create temp file: %v\n", err)
		os.Exit(1)
	}

	var written int64
	buf := make([]byte, 32*1024)
	lastPrint := time.Now()
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			_, writeErr := out.Write(buf[:n])
			if writeErr != nil {
				out.Close()
				os.Remove(tmpFile)
				fmt.Printf("\n❌ Write error: %v\n", writeErr)
				os.Exit(1)
			}
			written += int64(n)
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
			out.Close()
			os.Remove(tmpFile)
			fmt.Printf("\n❌ Download error: %v\n", readErr)
			os.Exit(1)
		}
	}
	out.Close()

	if totalSize > 0 {
		fmt.Printf("\r   %s 100%% (%s)          \n", progressBar(100, 30), humanSize(written))
	} else {
		fmt.Printf("\r   Downloaded %s          \n", humanSize(written))
	}

	os.Chmod(tmpFile, 0755)
	backupFile := exe + ".bak"
	os.Remove(backupFile)
	if err := os.Rename(exe, backupFile); err != nil {
		os.Remove(tmpFile)
		fmt.Printf("❌ Cannot backup current binary: %v\n", err)
		os.Exit(1)
	}
	if err := os.Rename(tmpFile, exe); err != nil {
		os.Rename(backupFile, exe)
		fmt.Printf("❌ Cannot install new binary: %v\n", err)
		os.Exit(1)
	}
	os.Remove(backupFile)

	fmt.Printf("✅ Updated to %s!\n", result.LatestVersion)

	// Restart the gateway if it was running, so the new binary takes effect.
	pidPath := paths.Get().PidFile
	if pid, running := pidfile.IsRunningFromFile(pidPath); running {
		fmt.Printf("🔄 Restarting gateway (PID: %d)...\n", pid)
		pidfile.StopFromFile(pidPath) //nolint:errcheck
		exec.Command("pkill", "sing-box").Run()
		exec.Command("pkill", "-f", "xray run -c /tmp/bypath").Run()
		exec.Command("pkill", "tun2socks").Run()
		exec.Command("ip", "link", "del", "tun0").Run()
		if _, err := exec.LookPath("systemctl"); err == nil {
			if out, _ := exec.Command("systemctl", "is-active", "bypath").Output();
				strings.TrimSpace(string(out)) == "active" || strings.TrimSpace(string(out)) == "activating" {
				exec.Command("systemctl", "restart", "bypath").Run()
				fmt.Println("  ✓ systemd service restarted")
			}
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
