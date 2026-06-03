package engine

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/liberoute/bypath/internal/config"
)

// Engine represents a tunnel engine binary (sing-box, xray, openvpn, wireguard-go).
type Engine struct {
	Name    string
	Path    string // resolved path to binary
	Version string
	Source  string // "system" or "local" or "downloaded"
}

// Manager handles engine detection, download, and lifecycle.
type Manager struct {
	config         config.EnginesConfig
	engines        map[string]*Engine
	SSHPassAvailable bool // whether sshpass binary is available (for password auth)
}

// NewManager creates a new engine manager.
func NewManager(cfg config.EnginesConfig) *Manager {
	return &Manager{
		config:  cfg,
		engines: make(map[string]*Engine),
	}
}

// Init detects or downloads all supported engines.
func (m *Manager) Init() error {
	log.Println("🔍 Detecting tunnel engines...")

	// Ensure engines directory exists
	if err := os.MkdirAll(m.config.Directory, 0755); err != nil {
		return fmt.Errorf("creating engines directory: %w", err)
	}

	// Detect each supported engine
	supported := []struct {
		name     string
		binaries []string // possible binary names
	}{
		{"sing-box", []string{"sing-box", "sing-box.exe"}},
		{"xray", []string{"xray", "xray.exe"}},
		{"wireguard-go", []string{"wireguard-go", "wireguard-go.exe", "wireguard.exe"}},
		{"openvpn", []string{"openvpn", "openvpn.exe"}},
	}

	for _, eng := range supported {
		resolved := m.resolve(eng.name, eng.binaries)
		if resolved != nil {
			m.engines[eng.name] = resolved
			log.Printf("  ✅ %s: %s (%s)", eng.name, resolved.Path, resolved.Source)
		} else {
			log.Printf("  ⚠️  %s: not found (will download on demand)", eng.name)
		}
	}

	// Detect SSH binary (system tool, not downloadable)
	if sshPath, err := exec.LookPath("ssh"); err == nil {
		m.engines["ssh"] = &Engine{Name: "ssh", Path: sshPath, Source: "system"}
		log.Printf("  ✅ ssh: %s (system)", sshPath)
	} else {
		log.Printf("  ⚠️  ssh: not found")
	}

	// Detect sshpass binary (optional, needed for password-based SSH auth)
	if sshpassPath, err := exec.LookPath("sshpass"); err == nil {
		m.SSHPassAvailable = true
		log.Printf("  ✅ sshpass: %s (system)", sshpassPath)
	} else {
		m.SSHPassAvailable = false
		log.Printf("  ℹ️  sshpass: not found (password auth unavailable, use key-based auth)")
	}

	return nil
}

// Get returns the engine by name, downloading if necessary.
func (m *Manager) Get(name string) (*Engine, error) {
	if eng, ok := m.engines[name]; ok {
		return eng, nil
	}

	// Try to download
	log.Printf("📥 Downloading engine: %s", name)
	eng, err := m.download(name)
	if err != nil {
		return nil, fmt.Errorf("engine %s not available: %w", name, err)
	}

	m.engines[name] = eng
	return eng, nil
}

// resolve tries to find an engine binary on the system or in the local directory.
func (m *Manager) resolve(name string, binaries []string) *Engine {
	// 1. Check system PATH (if prefer_system is true)
	if m.config.PreferSystem {
		for _, bin := range binaries {
			if path, err := exec.LookPath(bin); err == nil {
				return &Engine{Name: name, Path: path, Source: "system"}
			}
		}
	}

	// 2. Check local engines directory
	for _, bin := range binaries {
		localPath := filepath.Join(m.config.Directory, bin)
		if info, err := os.Stat(localPath); err == nil && !info.IsDir() {
			return &Engine{Name: name, Path: localPath, Source: "local"}
		}
	}

	// 3. Check system PATH even if prefer_system is false (fallback)
	if !m.config.PreferSystem {
		for _, bin := range binaries {
			if path, err := exec.LookPath(bin); err == nil {
				return &Engine{Name: name, Path: path, Source: "system"}
			}
		}
	}

	return nil
}

// download fetches the engine binary from its official release.
func (m *Manager) download(name string) (*Engine, error) {
	url, destName, err := m.getDownloadURL(name)
	if err != nil {
		return nil, err
	}

	destPath := filepath.Join(m.config.Directory, destName)

	log.Printf("  📦 Downloading %s from %s", name, url)
	if err := downloadFile(url, destPath); err != nil {
		return nil, fmt.Errorf("downloading %s: %w", name, err)
	}

	// For archives (.zip, .tar.gz), the actual binary was extracted to the engines
	// directory. Find it by the engine name, not the archive filename.
	binaryPath := destPath
	if strings.HasSuffix(destName, ".zip") || strings.HasSuffix(destName, ".tar.gz") || strings.HasSuffix(destName, ".tgz") {
		// Binary name is the engine name (e.g. "xray", "sing-box")
		binaryName := name
		if runtime.GOOS == "windows" {
			binaryName += ".exe"
		}
		binaryPath = filepath.Join(m.config.Directory, binaryName)
		// Clean up the archive file
		os.Remove(destPath)
	}

	// Make executable on Unix
	if runtime.GOOS != "windows" {
		os.Chmod(binaryPath, 0755)
	}

	// Verify the binary exists and is executable
	if _, err := os.Stat(binaryPath); err != nil {
		return nil, fmt.Errorf("binary not found after download/extract at %s: %w", binaryPath, err)
	}

	return &Engine{Name: name, Path: binaryPath, Source: "downloaded"}, nil
}

// getDownloadURL returns the download URL for an engine based on OS/Arch.
func (m *Manager) getDownloadURL(name string) (url string, filename string, err error) {
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	switch name {
	case "sing-box":
		ver := "1.13.0"
		arch := goarch
		if goarch == "arm" {
			arch = "armv7"
		}
		platform := fmt.Sprintf("%s-%s", goos, arch)
		ext := ".tar.gz"
		if goos == "windows" {
			ext = ".zip"
		}
		filename = fmt.Sprintf("sing-box-%s-%s%s", ver, platform, ext)
		url = fmt.Sprintf("https://github.com/SagerNet/sing-box/releases/download/v%s/%s", ver, filename)

	case "xray":
		ver := "25.1.1"
		archMap := map[string]string{"amd64": "64", "arm64": "arm64-v8a", "arm": "arm32-v7a"}
		arch := archMap[goarch]
		if arch == "" {
			arch = "64"
		}
		osName := "linux"
		if goos == "windows" {
			osName = "windows"
		}
		ext := ".zip"
		filename = fmt.Sprintf("Xray-%s-%s%s", osName, arch, ext)
		url = fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/download/v%s/%s", ver, filename)

	case "wireguard-go":
		// wireguard-go doesn't have official releases with binaries
		// We'll build from source or use system package
		return "", "", fmt.Errorf("wireguard-go must be installed via system package manager")

	case "openvpn":
		return "", "", fmt.Errorf("openvpn must be installed via system package manager")

	default:
		return "", "", fmt.Errorf("unknown engine: %s", name)
	}

	return url, filename, nil
}
