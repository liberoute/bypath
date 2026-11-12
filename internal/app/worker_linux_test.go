//go:build linux

package app

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const validWorkerMessage = `{"result":{"connection_id":"default/x","kind":"latency","status":"ok"},"spent_bytes":12,"final":true,"proof":{"self_netns":"net:[1]","init_netns":"net:[1]","daemon_netns":"net:[2]","isolation":true}}`

func TestDecodeWorkerResultAcceptsExactlyOneMessage(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{"single message", validWorkerMessage, false},
		{"trailing newline", validWorkerMessage + "\n", false},
		{"leading engine log", "2026/11/11 10:00:00 [Info] transport/internet: started\n" + validWorkerMessage, true},
		{"trailing engine log", validWorkerMessage + "\n2026/11/11 10:00:01 [Warn] transport/internet: closing", true},
		{"engine log before and after", "2026/11/11 [Debug] dialing\n" + validWorkerMessage + "\n2026/11/11 [Info] done", true},
		{"two messages", validWorkerMessage + "\n" + validWorkerMessage, true},
		{"empty channel", "", true},
		{"plain log text", "2026/11/11 10:00:00 [Info] xray: started", true},
		{"truncated message", strings.TrimSuffix(validWorkerMessage, "}"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := decodeWorkerResult([]byte(tc.raw))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("accepted a response it must refuse: %+v", out)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused a valid response: %v", err)
			}
			if out.Result.ConnectionID != "default/x" || !out.Proof.Isolation {
				t.Fatalf("decoded the wrong message: %+v", out)
			}
		})
	}
}

// TestWorkerStdioKeepsEngineNoiseOutOfTheResult re-executes this test binary as
// a worker that writes engine logs to stdout exactly like embedded xray does.
// The result channel must carry the answer alone.
func TestWorkerStdioKeepsEngineNoiseOutOfTheResult(t *testing.T) {
	if os.Getenv("BYPATH_WORKER_STDIO_HELPER") == "1" {
		helperNoisyWorker()
		return
	}

	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("creating the result pipe: %v", err)
	}
	defer pr.Close()

	cmd := exec.Command(os.Args[0], "-test.run=TestWorkerStdioKeepsEngineNoiseOutOfTheResult")
	cmd.Env = append(os.Environ(), "BYPATH_WORKER_STDIO_HELPER=1", WorkerResultFDEnv+"="+strconv.Itoa(WorkerResultFD))
	cmd.ExtraFiles = []*os.File{pw}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		pw.Close()
		t.Fatalf("starting the noisy worker: %v", err)
	}
	pw.Close()
	waitErr := cmd.Wait()

	result, err := io.ReadAll(pr)
	if err != nil {
		t.Fatalf("reading the result channel: %v", err)
	}
	if waitErr != nil {
		t.Fatalf("the noisy worker failed: %v (stderr: %s)", waitErr, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "" {
		t.Fatalf("engine noise reached the worker stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "[Info] xray") || !strings.Contains(stderr.String(), "[Debug] xray") {
		t.Fatalf("engine logs did not reach the log stream: %q", stderr.String())
	}
	out, err := decodeWorkerResult(result)
	if err != nil {
		t.Fatalf("the result channel did not decode: %v (raw: %q)", err, string(result))
	}
	if out.Result.ConnectionID != "default/x" || out.SpentBytes != 7 {
		t.Fatalf("decoded the wrong message: %+v", out)
	}
}

// helperNoisyWorker runs inside the re-executed binary. The stdout writes mimic
// an embedded engine: one through the Go-level stream and one straight to the
// descriptor.
func helperNoisyWorker() {
	out, err := ClaimWorkerStdio(WorkerResultFD, int(os.Stderr.Fd()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "claiming the result channel:", err)
		os.Exit(4)
	}
	fmt.Println("2026/11/11 10:00:00 [Info] xray: transport/internet started")
	raw := os.NewFile(1, "raw-stdout")
	fmt.Fprintln(raw, "2026/11/11 10:00:01 [Debug] xray: dialing tcp")
	if _, err := out.Write([]byte(`{"result":{"connection_id":"default/x","kind":"latency","status":"ok"},"spent_bytes":7,"final":true,"proof":{}}` + "\n")); err != nil {
		fmt.Fprintln(os.Stderr, "writing the result:", err)
		os.Exit(5)
	}
	if err := out.Close(); err != nil {
		os.Exit(6)
	}
	os.Exit(0)
}

// TestStopWorkerGroupKillsEngineChildren proves that cancelling a job removes
// the worker's children too, not just the worker process.
func TestStopWorkerGroupKillsEngineChildren(t *testing.T) {
	if os.Getenv("BYPATH_WORKER_GROUP_CHILD") == "1" {
		groupChild()
		return
	}
	if os.Getenv("BYPATH_WORKER_GROUP_HELPER") == "1" {
		groupHelper()
		return
	}

	pidfile := t.TempDir() + "/worker.pids"
	cmd := exec.Command(os.Args[0], "-test.run=TestStopWorkerGroupKillsEngineChildren")
	cmd.Env = append(os.Environ(), "BYPATH_WORKER_GROUP_HELPER=1", "BYPATH_WORKER_GROUP_PIDFILE="+pidfile)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the worker group: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	pids := waitForPids(t, pidfile)
	if len(pids) != 2 {
		t.Fatalf("expected the worker and its child, got %v", pids)
	}

	start := time.Now()
	err := stopWorkerGroup(cmd, done, 500*time.Millisecond)
	if elapsed := time.Since(start); elapsed < 400*time.Millisecond {
		t.Fatalf("the group was not given its grace period first (%v)", elapsed)
	}
	if err == nil {
		t.Fatal("expected the killed worker to report an error")
	}
	for _, pid := range pids {
		if processAlive(pid) {
			t.Fatalf("process %d survived the group kill", pid)
		}
	}
}

func waitForPids(t *testing.T, pidfile string) []int {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(pidfile)
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) == 2 {
				first, err1 := strconv.Atoi(fields[0])
				second, err2 := strconv.Atoi(fields[1])
				if err1 == nil && err2 == nil {
					return []int{first, second}
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the worker group never reported its pids")
	return nil
}

func processAlive(pid int) bool {
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
	return true
}

func groupHelper() {
	signal.Ignore(syscall.SIGINT)
	child := exec.Command(os.Args[0], "-test.run=TestStopWorkerGroupKillsEngineChildren")
	child.Env = append(os.Environ(), "BYPATH_WORKER_GROUP_CHILD=1")
	if err := child.Start(); err != nil {
		os.Exit(4)
	}
	pidfile := os.Getenv("BYPATH_WORKER_GROUP_PIDFILE")
	_ = os.WriteFile(pidfile, []byte(fmt.Sprintf("%d %d\n", os.Getpid(), child.Process.Pid)), 0o644)
	for {
		time.Sleep(time.Hour)
	}
}

func groupChild() {
	signal.Ignore(syscall.SIGINT)
	for {
		time.Sleep(time.Hour)
	}
}
