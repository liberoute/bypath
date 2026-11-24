package gateway

import (
	"testing"
	"time"
)

// The seams are atomic because supervisory goroutines may still be unwinding
// when a test moves on. These helpers save the current value and restore it
// after the test, so individual tests only state what they inject.

func setDataPathProbeHook(t *testing.T, fn func(*Gateway) (bool, string)) {
	t.Helper()
	old := dataPathProbeHook.Load()
	t.Cleanup(func() { dataPathProbeHook.Store(old) })
	f := dataPathProbeFunc(fn)
	dataPathProbeHook.Store(&f)
}

func setRepairDataPathHook(t *testing.T, fn func(*Gateway) (bool, error)) {
	t.Helper()
	old := repairDataPathHook.Load()
	t.Cleanup(func() { repairDataPathHook.Store(old) })
	f := dataPathRepairFunc(fn)
	repairDataPathHook.Store(&f)
}

func setEngineRecoveryHook(t *testing.T, fn func(*Gateway, string) bool) {
	t.Helper()
	old := engineRecoveryHook.Load()
	t.Cleanup(func() { engineRecoveryHook.Store(old) })
	f := engineRecoveryFunc(fn)
	engineRecoveryHook.Store(&f)
}

func setHealthProbeHook(t *testing.T, fn func(*Gateway) (bool, string)) {
	t.Helper()
	old := healthProbeHook.Load()
	t.Cleanup(func() { healthProbeHook.Store(old) })
	f := healthProbeFunc(fn)
	healthProbeHook.Store(&f)
}

func setRestartTunPathHook(t *testing.T, fn func(*Gateway) error) {
	t.Helper()
	old := restartTunPathHook.Load()
	t.Cleanup(func() { restartTunPathHook.Store(old) })
	f := tunRestartFunc(fn)
	restartTunPathHook.Store(&f)
}

func setDuration(t *testing.T, d *atomicDuration, v time.Duration) {
	t.Helper()
	old := d.Load()
	t.Cleanup(func() { d.Store(old) })
	d.Store(v)
}
