package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/liberoute/bypath/internal/config"
)

// Engine represents a tunnel engine binary (sing-box, xray, openvpn, wireguard-go).
type Engine struct {
	Name    string
	Path    string // resolved path to binary
	Version string
	Source  string // "system" or "local" or "downloaded"
	Digest  string // sha256 of the resolved binary, recorded for audit
}

// Manager handles engine detection, download, and lifecycle.
type Manager struct {
	config           config.EnginesConfig
	engines          map[string]*Engine
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
		{"tun2socks", []string{"tun2socks", "tun2socks.exe"}},
		{"wireguard-go", []string{"wireguard-go", "wireguard-go.exe", "wireguard.exe"}},
		{"openvpn", []string{"openvpn", "openvpn.exe"}},
	}

	for _, eng := range supported {
		resolved := m.resolve(eng.name, eng.binaries)
		if resolved != nil {
			if digest, err := fileSHA256(resolved.Path); err == nil {
				resolved.Digest = digest
			}
			m.engines[eng.name] = resolved
			if resolved.Digest != "" {
				log.Printf("  ✅ %s: %s (%s, sha256:%s)", eng.name, resolved.Path, resolved.Source, resolved.Digest)
			} else {
				log.Printf("  ✅ %s: %s (%s, digest unavailable)", eng.name, resolved.Path, resolved.Source)
			}
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

// EnsureManaged returns the bypath-managed copy of name, downloading the pinned
// release when it is absent. Unlike Get it never returns a PATH binary: the
// transparent data path must not depend on an operator-installed helper, and a
// managed copy whose digest no longer matches the pinned release is replaced
// instead of trusted.
func (m *Manager) EnsureManaged(name string) (*Engine, error) {
	if eng, ok := m.engines[name]; ok && eng.Source != "system" {
		return eng, nil
	}

	if err := os.MkdirAll(m.config.Directory, 0755); err != nil {
		return nil, fmt.Errorf("creating engines directory: %w", err)
	}
	binaryName := name
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	localPath := filepath.Join(m.config.Directory, binaryName)
	if info, err := os.Stat(localPath); err == nil && !info.IsDir() {
		digest, _ := fileSHA256(localPath)
		expected := ""
		if artifact, aErr := ArtifactFor(name, runtime.GOOS, runtime.GOARCH); aErr == nil {
			expected = artifact.SHA256
		}
		if expected == "" || digest == expected {
			eng := &Engine{Name: name, Path: localPath, Source: "local", Digest: digest}
			m.engines[name] = eng
			return eng, nil
		}
		log.Printf("  ⚠️  Managed %s at %s does not match the pinned digest — reinstalling", name, localPath)
	}

	eng, err := m.download(name)
	if err != nil {
		return nil, err
	}
	m.engines[name] = eng
	return eng, nil
}

// resolve tries to find an engine binary on the system or in the local directory.
//
// Selection policy: prefer_system=true checks PATH first, then the engines
// directory, then PATH again; prefer_system=false checks the engines directory
// first. Binaries found this way are operator-supplied: their identity is
// recorded (path and SHA-256) but cannot be pinned to a release. Only binaries
// downloaded by bypath are verified against pinned release digests. A version
// string is never treated as proof of integrity.
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

// download fetches the engine binary from its official release and installs it
// only after the pinned checksum and the platform-specific asset both match.
func (m *Manager) download(name string) (*Engine, error) {
	switch name {
	case "wireguard-go", "openvpn":
		return nil, fmt.Errorf("%s must be installed via the system package manager", name)
	case "sing-box", "xray", "tun2socks":
	default:
		return nil, fmt.Errorf("unknown engine: %s", name)
	}

	artifact, err := ArtifactFor(name, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return nil, err
	}

	binaryName := name
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}

	log.Printf("  📦 Downloading %s %s (sha256:%s)", name, artifact.Name, artifact.SHA256)
	download, err := os.CreateTemp(m.config.Directory, ".bypath-download-*")
	if err != nil {
		return nil, fmt.Errorf("creating download file: %w", err)
	}
	downloadPath := download.Name()
	download.Close()
	defer os.Remove(downloadPath)

	if err := downloadVerified(artifact.URL, downloadPath, artifact.SHA256); err != nil {
		return nil, fmt.Errorf("downloading %s: %w", name, err)
	}
	archiveBinary := artifact.Binary
	if archiveBinary == "" {
		archiveBinary = binaryName
	}
	if err := installArtifactAs(downloadPath, artifact.Name, m.config.Directory, binaryName, archiveBinary); err != nil {
		return nil, fmt.Errorf("installing %s: %w", name, err)
	}

	binaryPath := filepath.Join(m.config.Directory, binaryName)
	if err := os.Chmod(binaryPath, 0755); err != nil {
		return nil, fmt.Errorf("making %s executable: %w", binaryPath, err)
	}
	if _, err := os.Stat(binaryPath); err != nil {
		return nil, fmt.Errorf("binary not found after download/extract at %s: %w", binaryPath, err)
	}
	digest, _ := fileSHA256(binaryPath)
	if digest != "" {
		log.Printf("  ✅ %s installed at %s (sha256:%s)", name, binaryPath, digest)
	} else {
		log.Printf("  ✅ %s installed at %s (digest unavailable)", name, binaryPath)
	}

	return &Engine{Name: name, Path: binaryPath, Source: "downloaded", Digest: digest}, nil
}

// fileSHA256 hashes a binary for provenance logging. It is not a substitute for
// a pinned release checksum, which is enforced in downloadVerified.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// List returns every engine this manager has detected, in a stable order.
func (m *Manager) List() []*Engine {
	order := []string{"sing-box", "xray", "tun2socks", "wireguard-go", "openvpn", "ssh"}
	out := make([]*Engine, 0, len(m.engines))
	for _, name := range order {
		if eng, ok := m.engines[name]; ok {
			copyEng := *eng
			out = append(out, &copyEng)
		}
	}
	return out
}

// SSHPassAvailable reports whether password-based SSH auth is usable.
func (m *Manager) HasSSHPass() bool { return m.SSHPassAvailable }
