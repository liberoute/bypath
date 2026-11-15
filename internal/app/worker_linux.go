//go:build linux

package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// errWorkerCancelled reports that the worker was signalled and produced no
// result. The caller turns it into a cancelled row without claiming bytes.
var errWorkerCancelled = errors.New("the host worker was cancelled before it reported")

// workerResultGrace bounds how long the daemon waits for the result message
// after the worker process is gone.
const workerResultGrace = 5 * time.Second

// netNSOf reads the network namespace identity of a process.
func netNSOf(pid int) string {
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return ""
	}
	return target
}

// NetNSOf exposes the namespace identity to the worker entrypoint.
func NetNSOf(pid int) string { return netNSOf(pid) }

// isolatedWorkerRequired reports whether this process lives in a network
// namespace other than the host's. In that case an isolated engine started
// here would inherit the gateway namespace, so the measurement must run in the
// host-side worker instead.
func isolatedWorkerRequired() (bool, string) {
	self := netNSOf(os.Getpid())
	init := netNSOf(1)
	if self == "" || init == "" {
		return false, ""
	}
	return self != init, self
}

// runWorkerProcess starts one bounded worker in the host network namespace and
// reads its single JSON answer from the private result pipe.
func (s *Local) runWorkerProcess(ctx context.Context, job WorkerJob) (WorkerResult, error) {
	nsenter, err := exec.LookPath("nsenter")
	if err != nil {
		for _, candidate := range []string{"/usr/bin/nsenter", "/bin/nsenter", "/usr/sbin/nsenter"} {
			if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
				nsenter = candidate
				break
			}
		}
	}
	if nsenter == "" {
		return WorkerResult{}, errors.New("isolated tests need the host test worker, but nsenter is not available")
	}
	exe, err := os.Executable()
	if err != nil {
		return WorkerResult{}, fmt.Errorf("locating the worker binary: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	payload, err := json.Marshal(job)
	if err != nil {
		return WorkerResult{}, fmt.Errorf("encoding the worker job: %w", err)
	}
	args := []string{"-t", "1", "-n", "--", exe, "test-worker",
		"--config", s.ConfigFilePath(),
		"--profiles", s.testProfileDir(),
		"--tmp", s.paths.TmpDir,
		"--engines", s.testEngineDir(),
		"--geo", s.paths.GeoDir,
	}

	// The answer travels on its own descriptor. Standard output and standard
	// error carry diagnostics only, so no engine message can be parsed as the
	// result and no result can be lost in engine noise.
	resultR, resultW, err := os.Pipe()
	if err != nil {
		return WorkerResult{}, fmt.Errorf("creating the worker result channel: %w", err)
	}
	defer resultR.Close()

	cmd := exec.Command(nsenter, args...)
	cmd.Stdin = bytes.NewReader(payload)
	stdout := &cappedBuffer{limit: 64 << 10}
	stderr := &cappedBuffer{limit: 64 << 10}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.ExtraFiles = []*os.File{resultW}
	cmd.Env = append(os.Environ(), WorkerResultFDEnv+"="+strconv.Itoa(WorkerResultFD))
	// A process group lets cancellation take the worker's engine children with
	// it instead of leaving them behind on the host.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// Do not hang on I/O if a grandchild keeps the inherited pipes open.
	cmd.WaitDelay = 5 * time.Second

	if err := cmd.Start(); err != nil {
		resultW.Close()
		return WorkerResult{}, fmt.Errorf("starting the host worker: %w", err)
	}
	resultW.Close()

	type readResult struct {
		data []byte
		err  error
	}
	readDone := make(chan readResult, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(resultR, workerResultLimit+1))
		readDone <- readResult{data: data, err: err}
	}()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-done:
	case <-ctx.Done():
		waitErr = stopWorkerGroup(cmd, done, workerGrace)
	}

	var result readResult
	select {
	case result = <-readDone:
	case <-time.After(workerResultGrace):
		// The answer never arrived and the writer is gone: stop waiting.
		resultR.Close()
		result = <-readDone
	}

	if len(result.data) > workerResultLimit {
		return WorkerResult{}, fmt.Errorf("the host worker returned more than %d bytes", workerResultLimit)
	}
	raw := strings.TrimSpace(string(result.data))
	if raw == "" {
		if ctx.Err() == context.Canceled {
			return WorkerResult{}, errWorkerCancelled
		}
		if ctx.Err() == context.DeadlineExceeded {
			return WorkerResult{}, context.DeadlineExceeded
		}
		detail := strings.TrimSpace(stderr.String())
		if noise := strings.TrimSpace(stdout.String()); noise != "" {
			detail = strings.TrimSpace(detail + " " + noise)
		}
		if detail == "" {
			detail = "no result on the worker result channel"
		}
		if waitErr != nil {
			return WorkerResult{}, fmt.Errorf("the host worker exited without a result (%v): %s", waitErr, Redact(detail))
		}
		return WorkerResult{}, fmt.Errorf("the host worker exited without a result: %s", Redact(detail))
	}
	return decodeWorkerResult([]byte(raw))
}

// stopWorkerGroup asks the whole worker process group to stop, then kills it
// once the grace period expires. The group is signalled rather than the single
// process so engine children cannot outlive a cancelled job.
func stopWorkerGroup(cmd *exec.Cmd, done <-chan error, grace time.Duration) error {
	pid := cmd.Process.Pid
	_ = unix.Kill(-pid, unix.SIGINT)
	select {
	case err := <-done:
		return err
	case <-time.After(grace):
	}
	_ = unix.Kill(-pid, unix.SIGKILL)
	return <-done
}

// decodeWorkerResult accepts exactly one JSON message and nothing else. Trailing
// engine output, a second message or a truncated document are all refused, so a
// noisy run can never be mistaken for a certified result.
func decodeWorkerResult(raw []byte) (WorkerResult, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return WorkerResult{}, errors.New("the host worker produced no result message")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	var out WorkerResult
	if err := dec.Decode(&out); err != nil {
		return WorkerResult{}, fmt.Errorf("the host worker returned malformed output: %w", err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return WorkerResult{}, errors.New("the host worker returned more than one message")
	}
	return out, nil
}

// cappedBuffer keeps a bounded amount of process output so a noisy child cannot
// exhaust memory.
type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	room := b.limit - b.buf.Len()
	if room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *cappedBuffer) String() string { return b.buf.String() }
