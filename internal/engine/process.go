package engine

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
)

// Process represents a running engine process.
type Process struct {
	Name    string
	Cmd     *exec.Cmd
	cancel  context.CancelFunc
	stdout  io.ReadCloser
	stderr  io.ReadCloser
	mu      sync.Mutex
	running bool
}

// RunOptions configures how an engine process is started.
type RunOptions struct {
	Engine     *Engine
	Args       []string
	ConfigFile string
	LogFile    string
	Firejail   *FirejailOptions
}

// FirejailOptions configures firejail isolation.
type FirejailOptions struct {
	Enabled   bool
	Namespace string
	NetIface  string
	IP        string
	Gateway   string
	DNS       []string
}

// StartProcess starts an engine process with the given options.
func StartProcess(ctx context.Context, opts RunOptions) (*Process, error) {
	ctx, cancel := context.WithCancel(ctx)

	var args []string
	var binary string

	if opts.Firejail != nil && opts.Firejail.Enabled {
		// Wrap in firejail
		binary = "firejail"
		args = buildFirejailArgs(opts)
	} else {
		binary = opts.Engine.Path
		args = buildEngineArgs(opts)
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = os.Environ()

	// Setup logging
	var stdout, stderr io.ReadCloser
	var err error

	if opts.LogFile != "" {
		logFile, err := os.OpenFile(opts.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("opening log file: %w", err)
		}
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	} else {
		stdout, err = cmd.StdoutPipe()
		if err != nil {
			cancel()
			return nil, err
		}
		stderr, err = cmd.StderrPipe()
		if err != nil {
			cancel()
			return nil, err
		}
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("starting %s: %w", opts.Engine.Name, err)
	}

	proc := &Process{
		Name:    opts.Engine.Name,
		Cmd:     cmd,
		cancel:  cancel,
		stdout:  stdout,
		stderr:  stderr,
		running: true,
	}

	// Monitor process in background
	go func() {
		err := cmd.Wait()
		proc.mu.Lock()
		proc.running = false
		proc.mu.Unlock()
		if err != nil {
			log.Printf("⚠️  Engine %s exited: %v", opts.Engine.Name, err)
		} else {
			log.Printf("ℹ️  Engine %s exited normally", opts.Engine.Name)
		}
	}()

	return proc, nil
}

// Stop gracefully stops the process.
func (p *Process) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	p.cancel()
	return nil
}

// IsRunning returns whether the process is still running.
func (p *Process) IsRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running
}

// buildFirejailArgs constructs the firejail command arguments.
func buildFirejailArgs(opts RunOptions) []string {
	args := []string{"--noprofile"}

	fj := opts.Firejail
	if fj.NetIface != "" {
		args = append(args, "--net="+fj.NetIface)
	}
	if fj.IP != "" {
		args = append(args, "--ip="+fj.IP)
	}
	if fj.Gateway != "" {
		args = append(args, "--defaultgw="+fj.Gateway)
	}
	if fj.Namespace != "" {
		args = append(args, "--name="+fj.Namespace)
	}
	for _, dns := range fj.DNS {
		args = append(args, "--dns="+dns)
	}

	// Add the actual engine command
	args = append(args, opts.Engine.Path)
	args = append(args, buildEngineArgs(opts)...)

	return args
}

// buildEngineArgs constructs engine-specific arguments.
func buildEngineArgs(opts RunOptions) []string {
	switch opts.Engine.Name {
	case "sing-box":
		return []string{"run", "-c", opts.ConfigFile}
	case "xray":
		return []string{"run", "-c", opts.ConfigFile}
	case "wireguard-go":
		return []string{opts.ConfigFile} // wireguard-go takes interface name
	case "openvpn":
		return []string{"--config", opts.ConfigFile}
	default:
		return opts.Args
	}
}
