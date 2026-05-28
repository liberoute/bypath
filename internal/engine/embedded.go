//go:build full

package engine

// This file is only compiled in the "full" build.
// It registers embedded engines (sing-box, xray) that run in-process
// instead of spawning external binaries.

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

// --- Embedded sing-box (placeholder — will import sing-box library) ---

type embeddedSingBox struct {
	configFile string
	running    bool
}

func newEmbeddedSingBox(configFile string) (EmbeddedRunner, error) {
	return &embeddedSingBox{configFile: configFile}, nil
}

func (e *embeddedSingBox) Start() error {
	// TODO: Import github.com/sagernet/sing-box and run in-process
	// box, err := box.New(box.Options{...})
	// box.Start()
	e.running = true
	return nil
}

func (e *embeddedSingBox) Stop() error {
	e.running = false
	return nil
}

func (e *embeddedSingBox) IsRunning() bool {
	return e.running
}

// --- Embedded xray (placeholder — will import xray-core library) ---

type embeddedXray struct {
	configFile string
	running    bool
}

func newEmbeddedXray(configFile string) (EmbeddedRunner, error) {
	return &embeddedXray{configFile: configFile}, nil
}

func (e *embeddedXray) Start() error {
	// TODO: Import github.com/xtls/xray-core and run in-process
	// core.New(config)
	// server.Start()
	e.running = true
	return nil
}

func (e *embeddedXray) Stop() error {
	e.running = false
	return nil
}

func (e *embeddedXray) IsRunning() bool {
	return e.running
}
