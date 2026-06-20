package tunnel

import (
	"sync"
	"testing"
)

// TestHTTPSBindCloseNoPanicDuringReceive reproduces the send-on-closed-channel
// race: receive loops sending packets while Close() runs. Under the old code
// (Close closed recvChan while a loop sent to it) this panicked. The fix
// signals shutdown via the done channel and never closes recvChan.
func TestHTTPSBindCloseNoPanicDuringReceive(t *testing.T) {
	b := &HTTPSBind{
		remoteConns: make(map[string]*httpsEndpoint),
		recvChan:    make(chan recvPacket, 4),
		done:        make(chan struct{}),
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Mirror receiveLoop: snapshot channels, then send under select.
			b.closeMu.Lock()
			recvChan := b.recvChan
			done := b.done
			b.closeMu.Unlock()
			for j := 0; j < 2000; j++ {
				select {
				case <-done:
					return
				case recvChan <- recvPacket{}:
				default:
				}
			}
		}()
	}

	// Concurrent close must not panic.
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wg.Wait()

	// Close is idempotent.
	if err := b.Close(); err != nil {
		t.Errorf("second Close returned error: %v", err)
	}
}

// TestHTTPSBindReopen verifies the Close -> Open lifecycle resets the done
// channel so a reopened bind is usable (WireGuard calls Close then Open on Up).
func TestHTTPSBindReopen(t *testing.T) {
	b := &HTTPSBind{
		remoteConns: make(map[string]*httpsEndpoint),
		recvChan:    make(chan recvPacket, 4),
		done:        make(chan struct{}),
	}

	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !b.closed {
		t.Fatal("expected bind to be closed")
	}

	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	if b.closed {
		t.Error("Open should clear the closed flag")
	}

	// done must be a fresh, open channel after reopen.
	select {
	case <-b.done:
		t.Error("done channel should be reopened (not closed) after Open")
	default:
	}
}
