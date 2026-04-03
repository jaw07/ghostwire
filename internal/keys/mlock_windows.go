//go:build windows

package keys

// mlock is a no-op on Windows.
// TODO: implement using VirtualLock for swap protection.
func (sb *SecureBuffer) mlock() error {
	return nil
}

// munlock is a no-op on Windows.
func (sb *SecureBuffer) munlock() {
}
