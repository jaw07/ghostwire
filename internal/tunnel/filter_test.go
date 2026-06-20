package tunnel

import (
	"os"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

// fakeTUN is a minimal tun.Device for exercising filteredTUN. Read replays a
// queued batch of packets; Write records what it was handed.
type fakeTUN struct {
	mu       sync.Mutex
	toRead   [][]byte // packets to hand out on the next Read
	written  [][]byte // packets passed through to Write
	events   chan tun.Event
}

func newFakeTUN() *fakeTUN { return &fakeTUN{events: make(chan tun.Event)} }

func (f *fakeTUN) File() *os.File { return nil }

func (f *fakeTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for i, pkt := range f.toRead {
		if i >= len(bufs) {
			break
		}
		copy(bufs[i][offset:], pkt)
		sizes[i] = len(pkt)
		n++
	}
	f.toRead = nil
	return n, nil
}

func (f *fakeTUN) Write(bufs [][]byte, offset int) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range bufs {
		cp := append([]byte(nil), b[offset:]...)
		f.written = append(f.written, cp)
	}
	return len(bufs), nil
}

func (f *fakeTUN) MTU() (int, error)        { return 1420, nil }
func (f *fakeTUN) Name() (string, error)    { return "fake0", nil }
func (f *fakeTUN) Events() <-chan tun.Event { return f.events }
func (f *fakeTUN) Close() error             { return nil }
func (f *fakeTUN) BatchSize() int           { return 4 }

// allowFilter allows/denies based on the first payload byte (1 = allow).
type firstByteFilter struct{}

func (firstByteFilter) Allow(packet []byte, direction string) bool {
	return len(packet) > 0 && packet[0] == 1
}

func mkbuf(first byte) []byte {
	b := make([]byte, 4)
	b[0] = first
	return b
}

func TestFilteredTUNNoFilterPassesThrough(t *testing.T) {
	f := newFakeTUN()
	f.toRead = [][]byte{mkbuf(1), mkbuf(0)}
	ft := newFilteredTUN(f)

	bufs := [][]byte{make([]byte, 8), make([]byte, 8)}
	sizes := make([]int, 2)
	n, err := ft.Read(bufs, sizes, 0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 2 {
		t.Errorf("with no filter, Read returned %d packets, want 2", n)
	}
}

func TestFilteredTUNReadDropsDenied(t *testing.T) {
	f := newFakeTUN()
	// Two allowed (1), one denied (0), interleaved.
	f.toRead = [][]byte{mkbuf(1), mkbuf(0), mkbuf(1)}
	ft := newFilteredTUN(f)
	ft.SetFilter(firstByteFilter{})

	bufs := [][]byte{make([]byte, 8), make([]byte, 8), make([]byte, 8)}
	sizes := make([]int, 3)
	n, err := ft.Read(bufs, sizes, 0)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != 2 {
		t.Fatalf("Read returned %d allowed packets, want 2", n)
	}
	// Survivors compacted to the front, both allowed.
	for i := 0; i < n; i++ {
		if bufs[i][0] != 1 {
			t.Errorf("compacted packet %d has first byte %d, want 1 (allowed)", i, bufs[i][0])
		}
	}
}

func TestFilteredTUNWriteDropsDenied(t *testing.T) {
	f := newFakeTUN()
	ft := newFilteredTUN(f)
	ft.SetFilter(firstByteFilter{})

	bufs := [][]byte{mkbuf(1), mkbuf(0), mkbuf(1)}
	if _, err := ft.Write(bufs, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(f.written) != 2 {
		t.Fatalf("underlying TUN received %d packets, want 2 (1 denied)", len(f.written))
	}
	for i, p := range f.written {
		if p[0] != 1 {
			t.Errorf("written packet %d first byte %d, want 1", i, p[0])
		}
	}
}

func TestFilteredTUNClearFilter(t *testing.T) {
	f := newFakeTUN()
	ft := newFilteredTUN(f)
	ft.SetFilter(firstByteFilter{})
	ft.SetFilter(nil)
	if ft.current() != nil {
		t.Error("SetFilter(nil) should clear the filter")
	}
}
