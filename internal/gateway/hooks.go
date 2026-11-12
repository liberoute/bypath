package gateway

import (
	"sync/atomic"
	"time"
)

// Injectable seams. Production uses the values seeded by init; tests replace
// the implementations and the timing knobs to exercise fault paths without
// touching the host.
//
// Watchdog and recovery work runs on goroutines that may still be winding down
// when a test (or a stopped gateway) moves on, so every read and write goes
// through an atomic value instead of a plain package variable.

// atomicDuration is a time.Duration knob read by supervisory goroutines.
type atomicDuration struct{ v atomic.Int64 }

func (d *atomicDuration) Load() time.Duration   { return time.Duration(d.v.Load()) }
func (d *atomicDuration) Store(v time.Duration) { d.v.Store(int64(v)) }

type (
	dataPathProbeFunc  func(*Gateway) (bool, string)
	dataPathRepairFunc func(*Gateway) (bool, error)
	engineRecoveryFunc func(*Gateway, string) bool
	healthProbeFunc    func(*Gateway) (bool, string)
	tunRestartFunc     func(*Gateway) error
)

var (
	watchdogInterval    atomicDuration
	recoveryBackoffBase atomicDuration
	recoveryBackoffMax  atomicDuration
	// healthIntervalFloor rejects sub-5s health checks in production; tests lower
	// it so supervision runs without waiting seconds per assertion.
	healthIntervalFloor atomicDuration

	dataPathProbeHook  atomic.Pointer[dataPathProbeFunc]
	repairDataPathHook atomic.Pointer[dataPathRepairFunc]
	engineRecoveryHook atomic.Pointer[engineRecoveryFunc]
	healthProbeHook    atomic.Pointer[healthProbeFunc]
	restartTunPathHook atomic.Pointer[tunRestartFunc]
)

func init() {
	watchdogInterval.Store(time.Second)
	recoveryBackoffBase.Store(2 * time.Second)
	recoveryBackoffMax.Store(30 * time.Second)
	healthIntervalFloor.Store(5 * time.Second)

	probe := dataPathProbeFunc((*Gateway).probeDataPath)
	repair := dataPathRepairFunc((*Gateway).repairDataPath)
	dataPathProbeHook.Store(&probe)
	repairDataPathHook.Store(&repair)
	recover := engineRecoveryFunc((*Gateway).recoverRuntime)
	health := healthProbeFunc((*Gateway).healthCheck)
	restart := tunRestartFunc((*Gateway).restartTunPath)
	engineRecoveryHook.Store(&recover)
	healthProbeHook.Store(&health)
	restartTunPathHook.Store(&restart)
}

func callDataPathProbe(gw *Gateway) (bool, string) { return (*dataPathProbeHook.Load())(gw) }

func callRepairDataPath(gw *Gateway) (bool, error) { return (*repairDataPathHook.Load())(gw) }

func callEngineRecovery(gw *Gateway, reason string) bool {
	return (*engineRecoveryHook.Load())(gw, reason)
}

func callHealthProbe(gw *Gateway) (bool, string) { return (*healthProbeHook.Load())(gw) }

func callRestartTunPath(gw *Gateway) error { return (*restartTunPathHook.Load())(gw) }
