//go:build windows

package engine

import (
	"log"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	childJobOnce sync.Once
	childJob     windows.Handle // kept open for the daemon's lifetime by design
)

// trackChildProcess binds an engine process to a shared job object configured
// to kill its members when the daemon's last job handle closes. If bypath
// crashes or is forcibly terminated, the OS closes the handle and the engine
// cannot survive as an orphan holding the SOCKS port.
//
// One job is used for every engine a run starts, including recovery restarts,
// so repeated restarts cannot leak a handle per attempt.
func trackChildProcess(pid int) {
	childJobOnce.Do(func() {
		job, err := windows.CreateJobObject(nil, nil)
		if err != nil {
			log.Printf("  ⚠️  cannot create engine job object: %v", err)
			return
		}
		info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
		info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		if _, err := windows.SetInformationJobObject(
			job,
			windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&info)),
			uint32(unsafe.Sizeof(info)),
		); err != nil {
			windows.CloseHandle(job)
			log.Printf("  ⚠️  cannot configure engine job object: %v", err)
			return
		}
		childJob = job
	})
	if childJob == 0 {
		return
	}

	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(pid))
	if err != nil {
		log.Printf("  ⚠️  cannot open engine process for job assignment: %v", err)
		return
	}
	defer windows.CloseHandle(h)
	if err := windows.AssignProcessToJobObject(childJob, h); err != nil {
		log.Printf("  ⚠️  cannot assign engine to job object: %v", err)
	}
}
