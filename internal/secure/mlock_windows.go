//go:build windows

package secure

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32        = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualLock = kernel32.NewProc("VirtualLock")
	procVirtualUnlock = kernel32.NewProc("VirtualUnlock")
)

// mlock locks the region's memory to prevent swapping
func (r *Region) mlock() error {
	if len(r.data) == 0 {
		return nil
	}

	ret, _, err := procVirtualLock.Call(
		uintptr(unsafe.Pointer(&r.data[0])),
		uintptr(len(r.data)),
	)
	if ret == 0 {
		return err
	}
	r.locked = true
	return nil
}

// munlock unlocks the region's memory
func (r *Region) munlock() {
	if !r.locked || len(r.data) == 0 {
		return
	}

	procVirtualUnlock.Call(
		uintptr(unsafe.Pointer(&r.data[0])),
		uintptr(len(r.data)),
	)
	r.locked = false
}

// getMemlockLimit returns the system's working set limit
// Windows doesn't have a direct equivalent to RLIMIT_MEMLOCK
func getMemlockLimit() int {
	// Return a conservative default
	return 64 * 1024 * 1024 // 64MB
}
