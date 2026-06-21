package obfuscation

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Padder tests
// ---------------------------------------------------------------------------

func TestDefaultPaddingConfig(t *testing.T) {
	cfg := DefaultPaddingConfig()
	if cfg == nil {
		t.Fatal("DefaultPaddingConfig returned nil")
	}
	if !cfg.Enabled {
		t.Error("expected Enabled=true")
	}
	if cfg.Mode != "mimic" {
		t.Errorf("expected Mode=mimic, got %s", cfg.Mode)
	}
	if len(cfg.TargetSizes) == 0 {
		t.Error("expected non-empty TargetSizes")
	}
	if cfg.BlockSize <= 0 {
		t.Error("expected positive BlockSize")
	}
}

func TestNewPadderNilConfig(t *testing.T) {
	p := NewPadder(nil)
	if p == nil {
		t.Fatal("NewPadder(nil) returned nil")
	}
	if p.cfg == nil {
		t.Fatal("padder cfg is nil")
	}
	if p.cfg.Mode != "mimic" {
		t.Errorf("expected default mode mimic, got %s", p.cfg.Mode)
	}
}

func TestPadUnpadRoundTrip(t *testing.T) {
	p := NewPadder(nil)
	original := []byte("hello, ghostwire!")

	padded := p.Pad(original)
	if len(padded) <= len(original) {
		t.Fatalf("padded length (%d) should be greater than original (%d)", len(padded), len(original))
	}

	restored, err := p.Unpad(padded)
	if err != nil {
		t.Fatalf("Unpad error: %v", err)
	}
	if !bytes.Equal(restored, original) {
		t.Fatalf("round-trip failed: got %q, want %q", restored, original)
	}
}

func TestPadDisabled(t *testing.T) {
	cfg := DefaultPaddingConfig()
	cfg.Enabled = false
	p := NewPadder(cfg)

	data := []byte("no padding please")
	padded := p.Pad(data)
	if !bytes.Equal(padded, data) {
		t.Error("expected data unchanged when padding disabled")
	}
}

func TestPadMimicMode(t *testing.T) {
	cfg := DefaultPaddingConfig()
	cfg.Mode = "mimic"
	p := NewPadder(cfg)

	data := []byte("short")
	padded := p.Pad(data)

	matched := false
	for _, size := range CommonHTTPSizes {
		if len(padded) == size {
			matched = true
			break
		}
	}
	// For small data, should match one of the common sizes.
	// For very large data it may be a multiple of the largest size.
	if !matched {
		largest := CommonHTTPSizes[len(CommonHTTPSizes)-1]
		if len(padded)%largest != 0 {
			t.Errorf("padded size %d does not match any CommonHTTPSizes or a multiple of largest", len(padded))
		}
	}
}

func TestPadFixedMode(t *testing.T) {
	cfg := DefaultPaddingConfig()
	cfg.Mode = "fixed"
	cfg.BlockSize = 32
	p := NewPadder(cfg)

	data := []byte("align me")
	padded := p.Pad(data)
	if len(padded)%cfg.BlockSize != 0 {
		t.Errorf("padded length %d not aligned to block size %d", len(padded), cfg.BlockSize)
	}
}

func TestPadRandomMode(t *testing.T) {
	cfg := DefaultPaddingConfig()
	cfg.Mode = "random"
	cfg.MinPadding = 10
	cfg.MaxPadding = 50
	p := NewPadder(cfg)

	data := []byte("random pad")
	padded := p.Pad(data)

	minExpected := len(data) + 2 + cfg.MinPadding
	maxExpected := len(data) + 2 + cfg.MaxPadding
	if len(padded) < minExpected || len(padded) > maxExpected {
		t.Errorf("padded length %d not in expected range [%d, %d]", len(padded), minExpected, maxExpected)
	}
}

func TestUnpadInvalidInput(t *testing.T) {
	p := NewPadder(nil)

	// Empty input
	out, err := p.Unpad(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty output for nil input, got len %d", len(out))
	}

	// Single byte (too short for length header)
	out, err = p.Unpad([]byte{0x42})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Errorf("expected 1-byte passthrough, got len %d", len(out))
	}

	// Length header claims more data than available
	bad := make([]byte, 4)
	binary.BigEndian.PutUint16(bad[:2], 100) // claims 100 bytes but only 2 remain
	out, err = p.Unpad(bad)
	if err != nil {
		t.Fatal(err)
	}
	// Should return as-is
	if !bytes.Equal(out, bad) {
		t.Error("expected as-is return for invalid length")
	}
}

func TestPadLargeData(t *testing.T) {
	p := NewPadder(nil)

	// Data larger than all target sizes
	data := make([]byte, 20000)
	for i := range data {
		data[i] = byte(i % 256)
	}

	padded := p.Pad(data)
	if len(padded) < len(data)+2 {
		t.Error("padded must be at least data+2 bytes")
	}

	restored, err := p.Unpad(padded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, data) {
		t.Error("round-trip failed for large data")
	}
}

// ---------------------------------------------------------------------------
// Jitterer tests
// ---------------------------------------------------------------------------

func TestDefaultJitterConfig(t *testing.T) {
	cfg := DefaultJitterConfig()
	if cfg == nil {
		t.Fatal("DefaultJitterConfig returned nil")
	}
	if !cfg.Enabled {
		t.Error("expected Enabled=true")
	}
	if cfg.Distribution != "exponential" {
		t.Errorf("expected exponential distribution, got %s", cfg.Distribution)
	}
	if cfg.MaxDelay <= 0 {
		t.Error("expected positive MaxDelay")
	}
}

func TestNewJittererNilConfig(t *testing.T) {
	j := NewJitterer(nil)
	if j == nil {
		t.Fatal("NewJitterer(nil) returned nil")
	}
	if j.cfg == nil {
		t.Fatal("jitterer cfg is nil")
	}
}

func TestDelayDisabled(t *testing.T) {
	cfg := DefaultJitterConfig()
	cfg.Enabled = false
	j := NewJitterer(cfg)

	d := j.Delay()
	if d != 0 {
		t.Errorf("expected 0 delay when disabled, got %v", d)
	}
}

func TestDelayUniform(t *testing.T) {
	cfg := &JitterConfig{
		Enabled:      true,
		MinDelay:     1 * time.Millisecond,
		MaxDelay:     10 * time.Millisecond,
		Distribution: "uniform",
	}
	j := NewJitterer(cfg)

	for i := 0; i < 100; i++ {
		d := j.Delay()
		if d < cfg.MinDelay || d >= cfg.MaxDelay {
			t.Errorf("uniform delay %v out of range [%v, %v)", d, cfg.MinDelay, cfg.MaxDelay)
		}
	}
}

func TestDelayExponential(t *testing.T) {
	cfg := &JitterConfig{
		Enabled:      true,
		MinDelay:     0,
		MaxDelay:     50 * time.Millisecond,
		Distribution: "exponential",
	}
	j := NewJitterer(cfg)

	for i := 0; i < 100; i++ {
		d := j.Delay()
		if d > cfg.MaxDelay {
			t.Errorf("exponential delay %v exceeds max %v", d, cfg.MaxDelay)
		}
	}
}

func TestDelayNormal(t *testing.T) {
	cfg := &JitterConfig{
		Enabled:      true,
		MinDelay:     1 * time.Millisecond,
		MaxDelay:     20 * time.Millisecond,
		Distribution: "normal",
	}
	j := NewJitterer(cfg)

	for i := 0; i < 100; i++ {
		d := j.Delay()
		if d < cfg.MinDelay || d > cfg.MaxDelay {
			t.Errorf("normal delay %v out of range [%v, %v]", d, cfg.MinDelay, cfg.MaxDelay)
		}
	}
}

func TestBurstMode(t *testing.T) {
	cfg := &JitterConfig{
		Enabled:       true,
		MinDelay:      1 * time.Millisecond,
		MaxDelay:      10 * time.Millisecond,
		Distribution:  "uniform",
		BurstMode:     true,
		BurstSize:     3,
		BurstInterval: 100 * time.Millisecond,
	}
	j := NewJitterer(cfg)

	// First BurstSize calls should return 0 delay
	for i := 0; i < cfg.BurstSize; i++ {
		d := j.Delay()
		if d != 0 {
			t.Errorf("burst packet %d: expected 0 delay, got %v", i, d)
		}
	}
}

// ---------------------------------------------------------------------------
// DecoyGenerator tests
// ---------------------------------------------------------------------------

func TestDefaultDecoyConfig(t *testing.T) {
	cfg := DefaultDecoyConfig()
	if cfg == nil {
		t.Fatal("DefaultDecoyConfig returned nil")
	}
	// Off by default
	if cfg.Enabled {
		t.Error("expected Enabled=false by default")
	}
	if cfg.MinSize <= 0 || cfg.MaxSize <= 0 {
		t.Error("expected positive size values")
	}
}

func TestNewDecoyGenerator(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	dg := NewDecoyGenerator(nil, c1)
	if dg == nil {
		t.Fatal("NewDecoyGenerator returned nil")
	}
	if dg.conn != c1 {
		t.Error("conn not set correctly")
	}
}

func TestDecoyStartStop(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	cfg := &DecoyConfig{
		Enabled:     true,
		MinInterval: 10 * time.Millisecond,
		MaxInterval: 20 * time.Millisecond,
		MinSize:     64,
		MaxSize:     128,
		Pattern:     "random",
	}
	dg := NewDecoyGenerator(cfg, c1)
	dg.Start()

	// Read one decoy packet to confirm it's running
	buf := make([]byte, 256)
	c2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := c2.Read(buf)
	if err != nil {
		t.Fatalf("expected to read decoy packet: %v", err)
	}
	if n == 0 {
		t.Fatal("expected non-zero decoy packet")
	}
	if buf[0] != 0x00 {
		t.Errorf("decoy first byte should be 0x00, got 0x%02x", buf[0])
	}

	dg.Stop()
	c1.Close()
}

func TestDecoyPacketStartsWithZero(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	cfg := &DecoyConfig{
		Enabled:     true,
		MinInterval: 5 * time.Millisecond,
		MaxInterval: 10 * time.Millisecond,
		MinSize:     64,
		MaxSize:     128,
		Pattern:     "constant",
	}
	dg := NewDecoyGenerator(cfg, c1)
	dg.Start()

	buf := make([]byte, 256)
	c2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := c2.Read(buf)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	if n > 0 && buf[0] != 0x00 {
		t.Errorf("decoy packet first byte = 0x%02x, want 0x00", buf[0])
	}

	dg.Stop()
	c1.Close()
}

// ---------------------------------------------------------------------------
// ObfuscatedConn tests
// ---------------------------------------------------------------------------

func TestNewObfuscatedConn(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	oc := NewObfuscatedConn(c1, nil, nil, nil)
	if oc == nil {
		t.Fatal("NewObfuscatedConn returned nil")
	}
	if oc.padder == nil {
		t.Error("padder is nil")
	}
	if oc.jitterer == nil {
		t.Error("jitterer is nil")
	}
}

func TestObfuscatedConnWriteReadRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	// Disable jitter and padding so that the round-trip test exercises the
	// connection wrapping without running into the protocol limitation where
	// the 2-byte padding length header's high byte is 0x00 for small data,
	// which the reader would misidentify as a decoy packet.
	jitCfg := &JitterConfig{Enabled: false}
	padCfg := &PaddingConfig{Enabled: false}
	writer := NewObfuscatedConn(c1, padCfg, jitCfg, nil)
	reader := NewObfuscatedConn(c2, padCfg, jitCfg, nil)

	original := []byte("round trip test data")

	done := make(chan error, 1)
	go func() {
		_, err := writer.Write(original)
		done <- err
	}()

	buf := make([]byte, 1024)
	n, err := reader.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}

	if werr := <-done; werr != nil {
		t.Fatalf("Write error: %v", werr)
	}

	got := buf[:n]
	if !bytes.Equal(got, original) {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, original)
	}
}

// tcpPair returns two ends of a connected TCP loopback connection, so tests
// exercise real stream coalescing/splitting (net.Pipe is synchronous and would
// hide framing bugs).
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()

	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	return r.c, cli
}

func TestObfuscatedConnRoundTrip(t *testing.T) {
	srv, cli := tcpPair(t)
	defer srv.Close()
	defer cli.Close()

	padCfg := &PaddingConfig{Enabled: true, Mode: "mimic", TargetSizes: CommonHTTPSizes}
	jitCfg := &JitterConfig{Enabled: false}
	writer := NewObfuscatedConn(cli, padCfg, jitCfg, nil)
	reader := NewObfuscatedConn(srv, padCfg, jitCfg, nil)
	defer writer.Close()
	defer reader.Close()

	big := make([]byte, 1400)
	for i := range big {
		big[i] = byte(i)
	}
	packets := [][]byte{
		[]byte("hello"),
		{0x00}, // a packet starting with 0x00 (the old escape edge case)
		big,
		[]byte("final packet"),
	}

	go func() {
		for _, p := range packets {
			if _, err := writer.Write(p); err != nil {
				return
			}
		}
	}()

	for i, want := range packets {
		// Small-ish buffer to also exercise the readBuf leftover path.
		buf := make([]byte, 4096)
		n, err := reader.Read(buf)
		if err != nil {
			t.Fatalf("read packet %d: %v", i, err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Errorf("packet %d: got %d bytes (%x...), want %d bytes", i, n, buf[:min(n, 8)], len(want))
		}
	}
}

func TestObfuscatedConnDiscardsDecoy(t *testing.T) {
	srv, cli := tcpPair(t)
	defer srv.Close()
	defer cli.Close()

	decoyCfg := &DecoyConfig{
		Enabled:     true,
		MinInterval: time.Millisecond,
		MaxInterval: 2 * time.Millisecond,
		MinSize:     32,
		MaxSize:     64,
	}
	writer := NewObfuscatedConn(cli, &PaddingConfig{Enabled: false}, &JitterConfig{Enabled: false}, decoyCfg)
	reader := NewObfuscatedConn(srv, &PaddingConfig{Enabled: false}, &JitterConfig{Enabled: false}, nil)
	defer writer.Close()
	defer reader.Close()

	// Let decoy frames flow, then send a real packet interleaved with them.
	time.Sleep(20 * time.Millisecond)
	go func() { writer.Write([]byte("REAL DATA")) }()

	buf := make([]byte, 1024)
	n, err := reader.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "REAL DATA" {
		t.Errorf("got %q, want REAL DATA (decoys must be discarded)", buf[:n])
	}
}

func TestObfuscatedConnCloseIdempotent(t *testing.T) {
	srv, cli := tcpPair(t)
	defer srv.Close()

	oc := NewObfuscatedConn(cli, nil, &JitterConfig{Enabled: false}, &DecoyConfig{
		Enabled: true, MinInterval: time.Millisecond, MaxInterval: 2 * time.Millisecond, MinSize: 16, MaxSize: 32,
	})
	if err := oc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Second close must not panic (closeOnce guards the done channel).
	_ = oc.Close()
}

// ---------------------------------------------------------------------------
// ShapeTraffic tests
// ---------------------------------------------------------------------------

func TestShapeTraffic(t *testing.T) {
	data := []byte("traffic shaping test data that should be copied")
	r := bytes.NewReader(data)
	var w bytes.Buffer

	// Use a high rate so the test completes quickly
	errCh := make(chan error, 1)
	go func() {
		errCh <- ShapeTraffic(r, &w, 1024*1024)
	}()

	select {
	case err := <-errCh:
		// ShapeTraffic returns io.EOF when reader is exhausted
		if err != nil && err != io.EOF {
			t.Fatalf("ShapeTraffic error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ShapeTraffic timed out")
	}

	if !bytes.Equal(w.Bytes(), data) {
		t.Fatalf("ShapeTraffic output mismatch: got %q, want %q", w.Bytes(), data)
	}
}
