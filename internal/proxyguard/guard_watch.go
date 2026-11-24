package proxyguard

import (
	"sync"
	"time"
)

// Watch calls lost when the installed ownership record stops naming want. It is
// the only detection left for a binary that predates every lock (d175a19,
// bb11c37): such a process cannot be excluded, but the daemon it disarms must
// not keep serving on an unguarded LAN port. The caller is expected to shut
// down; a supervisor then reinstalls the guard on the next start.
//
// stop returns only once the watcher has exited, so no read of the record or
// callback can still be in flight after the daemon has begun tearing down.
func Watch(want string, interval time.Duration, lost func()) (stop func()) {
	var once sync.Once
	done := make(chan struct{})
	stopped := make(chan struct{})
	stop = func() {
		once.Do(func() { close(done) })
		<-stopped
	}
	if want == "" {
		close(stopped)
		return stop
	}
	go func() {
		defer close(stopped)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if RecordToken() != want {
					lost()
					return
				}
			}
		}
	}()
	return stop
}
