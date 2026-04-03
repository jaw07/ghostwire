package keys

import (
	"runtime"
	"sync"
)

// SecureBuffer holds sensitive data with memory protections.
// On supported platforms, the memory is locked to prevent swapping to disk.
type SecureBuffer struct {
	data   []byte
	locked bool
	mu     sync.Mutex
}

// NewSecureBuffer allocates a secure buffer for sensitive data.
// The buffer memory is locked if the platform supports it.
func NewSecureBuffer(size int) *SecureBuffer {
	sb := &SecureBuffer{
		data: make([]byte, size),
	}

	// Try to lock memory to prevent swapping
	if err := sb.mlock(); err != nil {
		// Non-fatal: mlock may fail without CAP_IPC_LOCK
		// The buffer is still usable, just not swap-protected
	}

	return sb
}

// Write copies data into the secure buffer.
func (sb *SecureBuffer) Write(data []byte) error {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if len(data) > len(sb.data) {
		return ErrInvalidKeyLength
	}

	// Zero existing data first
	WipeBytes(sb.data)

	copy(sb.data, data)
	return nil
}

// Read returns a copy of the buffer data.
// The caller is responsible for wiping the returned copy when done.
func (sb *SecureBuffer) Read() []byte {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	result := make([]byte, len(sb.data))
	copy(result, sb.data)
	return result
}

// Bytes returns direct access to the buffer.
// Use with caution - modifications affect the buffer directly.
func (sb *SecureBuffer) Bytes() []byte {
	return sb.data
}

// Len returns the size of the buffer.
func (sb *SecureBuffer) Len() int {
	return len(sb.data)
}

// Wipe securely zeros the buffer contents.
func (sb *SecureBuffer) Wipe() {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	WipeBytes(sb.data)
}

// Close wipes the buffer and unlocks memory.
func (sb *SecureBuffer) Close() {
	sb.Wipe()
	sb.munlock()
}

// WipeBytes securely zeros a byte slice.
// Uses an explicit loop to prevent compiler optimization from removing the writes.
func WipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// Memory barrier to ensure writes complete before returning
	runtime.KeepAlive(b)
}

// SecureString holds a sensitive string with secure wiping capability.
type SecureString struct {
	buf *SecureBuffer
}

// NewSecureString creates a secure string from the given value.
func NewSecureString(s string) *SecureString {
	ss := &SecureString{
		buf: NewSecureBuffer(len(s)),
	}
	copy(ss.buf.data, s)
	return ss
}

// String returns the string value.
func (ss *SecureString) String() string {
	return string(ss.buf.data)
}

// Wipe securely zeros the string.
func (ss *SecureString) Wipe() {
	ss.buf.Wipe()
}

// Close wipes and releases the secure string.
func (ss *SecureString) Close() {
	ss.buf.Close()
}
