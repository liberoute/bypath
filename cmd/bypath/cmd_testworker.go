package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/liberoute/bypath/internal/app"
	"github.com/liberoute/bypath/internal/config"
	"github.com/liberoute/bypath/internal/paths"
	"github.com/liberoute/bypath/internal/profile"
)

// cmdTestWorker is the host-side half of the isolated test runner. It is
// started only by a daemon that lives inside the gateway network namespace, is
// given one bounded job on stdin and reports one JSON answer on the result
// channel. It never opens a network listener, never edits the profile store and
// never charges the budget: the daemon owns both.
func cmdTestWorker(args []string) {
	// Claim the result channel and point standard output at the log stream
	// before any embedded engine can write: engines log to stdout, and that
	// output must never be mixed with the one machine-readable answer.
	out, err := app.ClaimWorkerStdio(app.WorkerResultFDForEnv(), int(os.Stderr.Fd()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "bypath test-worker: the result channel could not be claimed")
		os.Exit(2)
	}
	res, code := runWorkerEntry(args)
	data, mErr := json.Marshal(res)
	if mErr != nil {
		data = []byte(`{"error":"the worker could not encode its result"}`)
	}
	if _, wErr := out.Write(append(data, '\n')); wErr != nil {
		fmt.Fprintln(os.Stderr, "bypath test-worker: the result channel rejected the answer")
	}
	if err := out.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "bypath test-worker: the result channel could not be closed")
	}
	if code != 0 {
		os.Exit(code)
	}
}

// runWorkerEntry turns an unexpected failure into a structured answer instead
// of a bare crash, so the daemon always has something it can classify.
func runWorkerEntry(args []string) (res app.WorkerResult, code int) {
	defer func() {
		if recover() != nil {
			res = app.WorkerResult{Error: "the worker failed unexpectedly"}
			code = 3
		}
	}()
	return runWorkerJob(args), 0
}

func runWorkerJob(args []string) app.WorkerResult {
	var configPath, profileDir, tmpDir, engineDir, geoDir string
	for i, arg := range args {
		if i+1 >= len(args) {
			break
		}
		switch arg {
		case "-c", "--config":
			configPath = args[i+1]
		case "--profiles":
			profileDir = args[i+1]
		case "--tmp":
			tmpDir = args[i+1]
		case "--engines":
			engineDir = args[i+1]
		case "--geo":
			geoDir = args[i+1]
		}
	}

	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return app.WorkerResult{Error: "the worker job could not be read"}
	}
	var job app.WorkerJob
	if err := json.Unmarshal(raw, &job); err != nil {
		return app.WorkerResult{Error: "the worker job is malformed"}
	}
	if job.Group == "" || job.Remark == "" || job.DaemonNetNS == "" ||
		(job.Kind != app.TestKindLatency && job.Kind != app.TestKindSpeed) {
		return app.WorkerResult{Error: "the worker job is incomplete"}
	}

	p := paths.Detect()
	if configPath != "" {
		p.ConfigFile = configPath
	}
	if profileDir != "" {
		p.ProfileDir = profileDir
	}
	if tmpDir != "" {
		p.TmpDir = tmpDir
	}
	if engineDir != "" {
		p.EngineDir = engineDir
	}
	if geoDir != "" {
		p.GeoDir = geoDir
	}

	cfg, err := config.Load(p.ConfigFile)
	if err != nil {
		return app.WorkerResult{Error: "the worker cannot read the configuration"}
	}
	mgr, err := profile.NewManager(p.ProfileDir, cfg.Profiles.ActiveGroup)
	if err != nil {
		return app.WorkerResult{Error: "the worker cannot open the profile store"}
	}
	svc, err := app.NewLocal(app.Options{Paths: p, Config: cfg, ConfigPath: p.ConfigFile, Profiles: mgr})
	if err != nil {
		return app.WorkerResult{Error: "the worker cannot open its service: " + err.Error()}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return svc.RunWorkerJob(ctx, job, app.NetNSOf(os.Getpid()), app.NetNSOf(1))
}
