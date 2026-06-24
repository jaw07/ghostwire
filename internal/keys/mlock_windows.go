//go:build windows

package keys

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// mlock pins the buffer's pages in physical memory with VirtualLock so the
// secret is never written to the pagefile.
//
// Limitation: Windows enforces a per-process minimum working-set size, and
// VirtualLock fails once the locked total would exceed it. Key buffers are
// small, so the default quota is sufficient in practice; a process that locks
// many large buffers would need SetProcessWorkingSetSize first.
func (sb *SecureBuffer) mlock() error {
	if len(sb.data) == 0 {
		return nil
	}
	err := windows.VirtualLock(
		uintptr(unsafe.Pointer(&sb.data[0])),
		uintptr(len(sb.data)),
	)
	if err == nil {
		sb.locked = true
	}
	return err
}

// munlock releases the VirtualLock pin, allowing the pages to be paged again.
func (sb *SecureBuffer) munlock() {
	if sb.locked && len(sb.data) > 0 {
		windows.VirtualUnlock(
			uintptr(unsafe.Pointer(&sb.data[0])),
			uintptr(len(sb.data)),
		)
		sb.locked = false
	}
}
