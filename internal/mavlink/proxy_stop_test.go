package mavlink

import "testing"

func TestProxyStopIdempotent(t *testing.T) {
	p := NewProxy(&ProxyConfig{ListenAddr: "127.0.0.1:0"})
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	p.Stop()
	p.Stop() // second Stop must not panic (close-of-closed) or block
}
