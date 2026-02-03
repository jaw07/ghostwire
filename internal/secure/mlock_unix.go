//go:build !windows

package secure

import (
	"golang.org/x/sys/unix"
)

// mlock locks the region's memory to prevent swapping
func (r *Region) mlock() error {
	if len(r.data) == 0 {
		return nil
	}

	err := unix.Mlock(r.data)
	if err == nil {
		r.locked = true
	}
	return err
}

// munlock unlocks the region's memory
func (r *Region) munlock() {
	if r.locked {
		unix.Munlock(r.data)
		r.locked = false
	}
}

// getMemlockLimit returns the system's mlock limit
func getMemlockLimit() int {
	var rlimit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rlimit); err != nil {
		return 0
	}
	// Use soft limit, capped at reasonable size
	limit := int(rlimit.Cur)
	if limit > 1024*1024*1024 { // Cap at 1GB
		limit = 1024 * 1024 * 1024
	}
	return limit
}
