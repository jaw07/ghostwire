//go:build !windows

package keys

import "golang.org/x/sys/unix"

// mlock prevents the memory from being swapped to disk.
func (sb *SecureBuffer) mlock() error {
	err := unix.Mlock(sb.data)
	if err == nil {
		sb.locked = true
	}
	return err
}

// munlock unlocks the memory, allowing it to be swapped.
func (sb *SecureBuffer) munlock() {
	if sb.locked {
		unix.Munlock(sb.data)
		sb.locked = false
	}
}
