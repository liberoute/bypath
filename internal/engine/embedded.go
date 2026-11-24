//go:build full

package engine

// This file is only compiled in the "full" build.
// It registers embedded engines (sing-box, xray) that run in-process
// instead of spawning external binaries.

import (
	"context"
	"os"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singJSON "github.com/sagernet/sing/common/json"

	"github.com/liberoute/bypath/internal/geo"
	"github.com/liberoute/bypath/internal/paths"

	xray "github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
)

func init() {
	// Register embedded engine factories
	RegisterEmbedded("sing-box", newEmbeddedSingBox)
	RegisterEmbedded("xray", newEmbeddedXray)
}

// embeddedEngines holds factory functions for in-process engines.
var embeddedEngines = make(map[string]EmbeddedFactory)

// EmbeddedFactory creates an in-process engine runner.
type EmbeddedFactory func(configFile string) (EmbeddedRunner, error)

// EmbeddedRunner is an engine that runs in-process (no external binary).
type EmbeddedRunner interface {
	Start() error
	Stop() error
	IsRunning() bool
}

// RegisterEmbedded registers an embedded engine factory.
func RegisterEmbedded(name string, factory EmbeddedFactory) {
	embeddedEngines[name] = factory
}

// GetEmbedded returns an embedded engine factory if available.
func GetEmbedded(name string) (EmbeddedFactory, bool) {
	f, ok := embeddedEngines[name]
	return f, ok
}

// --- Embedded sing-box ---

// singBoxContext builds a cancellable context carrying the sing-box registries.
// include.Context writes package-level hooks (for example the naive HTTP/3
// listener) on every call, so two concurrent Starts race; benchmark rows start
// embedded engines in parallel. The registries are immutable once built, so
// initialize them exactly once and derive each instance from that base.
var (
	singBoxBaseOnce sync.Once
	singBoxBaseCtx  context.Context
)

func singBoxContext() (context.Context, context.CancelFunc) {
	singBoxBaseOnce.Do(func() {
		singBoxBaseCtx = include.Context(context.Background())
	})
	return context.WithCancel(singBoxBaseCtx)
}

type embeddedSingBox struct {
	configFile string
	instance   *box.Box
	cancel     context.CancelFunc
	mu         sync.Mutex
	running    bool
}

func newEmbeddedSingBox(configFile string) (EmbeddedRunner, error) {
	return &embeddedSingBox{configFile: configFile}, nil
}

func (e *embeddedSingBox) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	data, err := os.ReadFile(e.configFile)
	if err != nil {
		return err
	}

	// Must set up the include context BEFORE unmarshaling so that
	// DNSServerOptions.UnmarshalJSONContext can access the DNS transport
	// registry and populate the Options field. Using encoding/json.Unmarshal
	// without context leaves Options=nil (it has json:"-"), causing
	// "initialize DNS server[0]: invalid server address: :53".
	ctx, cancel := singBoxContext()

	var opts option.Options
	if err := singJSON.UnmarshalContext(ctx, data, &opts); err != nil {
		cancel()
		return err
	}

	instance, err := box.New(box.Options{
		Context: ctx,
		Options: opts,
	})
	if err != nil {
		cancel()
		return err
	}
	if err := instance.Start(); err != nil {
		cancel()
		return err
	}
	e.instance = instance
	e.cancel = cancel
	e.running = true
	return nil
}

func (e *embeddedSingBox) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.instance == nil {
		return nil
	}
	err := e.instance.Close()
	e.cancel()
	e.instance = nil
	e.running = false
	return err
}

func (e *embeddedSingBox) IsRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

// --- Embedded xray ---

type embeddedXray struct {
	configFile string
	instance   *xray.Instance
	mu         sync.Mutex
	running    bool
}

func newEmbeddedXray(configFile string) (EmbeddedRunner, error) {
	return &embeddedXray{configFile: configFile}, nil
}

func (e *embeddedXray) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	data, err := os.ReadFile(e.configFile)
	if err != nil {
		return err
	}
	// Embedded xray would otherwise look for geoip.dat/geosite.dat next to the
	// bypath executable. Point it at the provisioned directory so geoip: rules
	// resolve instead of failing instance startup. An operator-set value wins.
	if os.Getenv("xray.location.asset") == "" {
		if dir := geo.FindXrayAssetDir(paths.Get().EngineDir, paths.Get().GeoDir); dir != "" {
			_ = os.Setenv("xray.location.asset", dir)
		}
	}
	instance, err := xray.StartInstance("json", data)
	if err != nil {
		return err
	}
	e.instance = instance
	e.running = true
	return nil
}

func (e *embeddedXray) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.instance == nil {
		return nil
	}
	err := e.instance.Close()
	e.instance = nil
	e.running = false
	return err
}

func (e *embeddedXray) IsRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}
