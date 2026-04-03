// Package obfuscation implements traffic analysis resistance techniques.
// These include packet padding, timing jitter, and decoy traffic generation.
package obfuscation

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	mrand "math/rand"
	"net"
	"sync"
	"time"
)

// CommonHTTPSizes are packet sizes that mimic common HTTPS response sizes
var CommonHTTPSizes = []int{
	64,    // ACK/small
	128,   // Small response
	256,   // Small JSON
	512,   // Medium response
	1024,  // 1KB
	1460,  // MTU-sized
	2048,  // 2KB
	4096,  // 4KB
	8192,  // 8KB (video chunk)
	16384, // 16KB (larger content)
}

// PaddingConfig configures packet padding behavior
type PaddingConfig struct {
	// Enabled turns padding on/off
	Enabled bool

	// Mode: "fixed", "random", "mimic"
	Mode string

	// TargetSizes for "mimic" mode
	TargetSizes []int

	// MinPadding is minimum padding bytes
	MinPadding int

	// MaxPadding is maximum padding bytes
	MaxPadding int

	// BlockSize for "fixed" mode alignment
	BlockSize int
}

// DefaultPaddingConfig returns default padding configuration
func DefaultPaddingConfig() *PaddingConfig {
	return &PaddingConfig{
		Enabled:     true,
		Mode:        "mimic",
		TargetSizes: CommonHTTPSizes,
		MinPadding:  0,
		MaxPadding:  256,
		BlockSize:   16,
	}
}

// Padder adds padding to packets
type Padder struct {
	cfg  *PaddingConfig
	rng  *mrand.Rand
	mu   sync.Mutex
}

// NewPadder creates a new padder
func NewPadder(cfg *PaddingConfig) *Padder {
	if cfg == nil {
		cfg = DefaultPaddingConfig()
	}

	seed := make([]byte, 8)
	rand.Read(seed)

	return &Padder{
		cfg: cfg,
		rng: mrand.New(mrand.NewSource(int64(binary.BigEndian.Uint64(seed)))),
	}
}

// Pad adds padding to data and returns padded data
// Format: [2-byte length][data][padding]
func (p *Padder) Pad(data []byte) []byte {
	if !p.cfg.Enabled {
		return data
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	dataLen := len(data)
	targetSize := p.selectTargetSize(dataLen)

	// Ensure we have at least enough for header + data
	if targetSize < dataLen+2 {
		targetSize = dataLen + 2
	}

	// Build padded packet: [length:2][data][padding]
	padded := make([]byte, targetSize)
	binary.BigEndian.PutUint16(padded[:2], uint16(dataLen))
	copy(padded[2:], data)

	// Fill padding with random bytes (not zeros - more realistic)
	paddingStart := 2 + dataLen
	if paddingStart < len(padded) {
		rand.Read(padded[paddingStart:])
	}

	return padded
}

// Unpad removes padding and returns original data
func (p *Padder) Unpad(padded []byte) ([]byte, error) {
	if len(padded) < 2 {
		return padded, nil
	}

	dataLen := int(binary.BigEndian.Uint16(padded[:2]))
	if dataLen > len(padded)-2 {
		return padded, nil // Invalid, return as-is
	}

	return padded[2 : 2+dataLen], nil
}

// selectTargetSize chooses a target size based on mode
func (p *Padder) selectTargetSize(dataLen int) int {
	switch p.cfg.Mode {
	case "fixed":
		// Align to block size
		blocks := (dataLen + 2 + p.cfg.BlockSize - 1) / p.cfg.BlockSize
		return blocks * p.cfg.BlockSize

	case "random":
		// Random padding within range
		padding := p.cfg.MinPadding + p.rng.Intn(p.cfg.MaxPadding-p.cfg.MinPadding+1)
		return dataLen + 2 + padding

	case "mimic":
		// Find smallest size that fits
		needed := dataLen + 2
		for _, size := range p.cfg.TargetSizes {
			if size >= needed {
				return size
			}
		}
		// Larger than all targets, use largest + random
		largest := p.cfg.TargetSizes[len(p.cfg.TargetSizes)-1]
		multiple := (needed + largest - 1) / largest
		return multiple * largest

	default:
		return dataLen + 2
	}
}

// JitterConfig configures timing jitter
type JitterConfig struct {
	// Enabled turns jitter on/off
	Enabled bool

	// MinDelay is minimum delay to add
	MinDelay time.Duration

	// MaxDelay is maximum delay to add
	MaxDelay time.Duration

	// Distribution: "uniform", "exponential", "normal"
	Distribution string

	// BurstMode: batch packets to mimic streaming
	BurstMode bool

	// BurstSize is packets per burst
	BurstSize int

	// BurstInterval is time between bursts
	BurstInterval time.Duration
}

// DefaultJitterConfig returns default jitter configuration
func DefaultJitterConfig() *JitterConfig {
	return &JitterConfig{
		Enabled:       true,
		MinDelay:      0,
		MaxDelay:      50 * time.Millisecond,
		Distribution:  "exponential",
		BurstMode:     false,
		BurstSize:     5,
		BurstInterval: 100 * time.Millisecond,
	}
}

// Jitterer adds timing jitter to packet transmission
type Jitterer struct {
	cfg         *JitterConfig
	rng         *mrand.Rand
	mu          sync.Mutex
	burstCount  int
	lastBurst   time.Time
}

// NewJitterer creates a new jitterer
func NewJitterer(cfg *JitterConfig) *Jitterer {
	if cfg == nil {
		cfg = DefaultJitterConfig()
	}

	seed := make([]byte, 8)
	rand.Read(seed)

	return &Jitterer{
		cfg: cfg,
		rng: mrand.New(mrand.NewSource(int64(binary.BigEndian.Uint64(seed)))),
	}
}

// Delay returns how long to wait before sending
func (j *Jitterer) Delay() time.Duration {
	if !j.cfg.Enabled {
		return 0
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	if j.cfg.BurstMode {
		return j.burstDelay()
	}

	return j.randomDelay()
}

// burstDelay implements burst mode timing
func (j *Jitterer) burstDelay() time.Duration {
	now := time.Now()

	// Check if we're in a burst
	if j.burstCount < j.cfg.BurstSize {
		j.burstCount++
		return 0 // No delay within burst
	}

	// Check if burst interval has passed
	if now.Sub(j.lastBurst) >= j.cfg.BurstInterval {
		j.burstCount = 1
		j.lastBurst = now
		return 0
	}

	// Wait for next burst
	wait := j.cfg.BurstInterval - now.Sub(j.lastBurst)
	j.burstCount = 1
	j.lastBurst = now.Add(wait)
	return wait
}

// randomDelay generates a random delay based on distribution
func (j *Jitterer) randomDelay() time.Duration {
	minNs := j.cfg.MinDelay.Nanoseconds()
	maxNs := j.cfg.MaxDelay.Nanoseconds()
	rangeNs := maxNs - minNs

	if rangeNs <= 0 {
		return j.cfg.MinDelay
	}

	var delayNs int64

	switch j.cfg.Distribution {
	case "uniform":
		delayNs = minNs + j.rng.Int63n(rangeNs)

	case "exponential":
		// Exponential distribution - more small delays, fewer large
		lambda := 1.0 / float64(rangeNs/2)
		expVal := -1.0 / lambda * float64(j.rng.Int63n(1000000)) / 1000000.0
		delayNs = minNs + int64(expVal)
		if delayNs > maxNs {
			delayNs = maxNs
		}

	case "normal":
		// Normal distribution centered between min and max
		mean := float64(minNs+maxNs) / 2
		stddev := float64(rangeNs) / 4
		val := j.rng.NormFloat64()*stddev + mean
		delayNs = int64(val)
		if delayNs < minNs {
			delayNs = minNs
		}
		if delayNs > maxNs {
			delayNs = maxNs
		}

	default:
		delayNs = minNs
	}

	return time.Duration(delayNs)
}

// DecoyConfig configures decoy traffic generation
type DecoyConfig struct {
	// Enabled turns decoy traffic on/off
	Enabled bool

	// MinInterval between decoy packets
	MinInterval time.Duration

	// MaxInterval between decoy packets
	MaxInterval time.Duration

	// MinSize of decoy packets
	MinSize int

	// MaxSize of decoy packets
	MaxSize int

	// Pattern: "constant", "random", "mimic_browsing"
	Pattern string
}

// DefaultDecoyConfig returns default decoy configuration
func DefaultDecoyConfig() *DecoyConfig {
	return &DecoyConfig{
		Enabled:     false, // Off by default due to bandwidth
		MinInterval: 1 * time.Second,
		MaxInterval: 5 * time.Second,
		MinSize:     64,
		MaxSize:     1460,
		Pattern:     "mimic_browsing",
	}
}

// DecoyGenerator generates decoy traffic
type DecoyGenerator struct {
	cfg     *DecoyConfig
	rng     *mrand.Rand
	conn    net.Conn
	stopCh  chan struct{}
	mu      sync.Mutex
	running bool
}

// NewDecoyGenerator creates a decoy traffic generator
func NewDecoyGenerator(cfg *DecoyConfig, conn net.Conn) *DecoyGenerator {
	if cfg == nil {
		cfg = DefaultDecoyConfig()
	}

	seed := make([]byte, 8)
	rand.Read(seed)

	return &DecoyGenerator{
		cfg:    cfg,
		rng:    mrand.New(mrand.NewSource(int64(binary.BigEndian.Uint64(seed)))),
		conn:   conn,
		stopCh: make(chan struct{}),
	}
}

// Start begins generating decoy traffic
func (d *DecoyGenerator) Start() {
	d.mu.Lock()
	if d.running || !d.cfg.Enabled {
		d.mu.Unlock()
		return
	}
	d.running = true
	d.mu.Unlock()

	go d.generateLoop()
}

// Stop halts decoy traffic generation
func (d *DecoyGenerator) Stop() {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return
	}
	d.running = false
	d.mu.Unlock()

	close(d.stopCh)
}

func (d *DecoyGenerator) generateLoop() {
	for {
		select {
		case <-d.stopCh:
			return
		case <-time.After(d.nextInterval()):
			d.sendDecoy()
		}
	}
}

func (d *DecoyGenerator) nextInterval() time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()

	minNs := d.cfg.MinInterval.Nanoseconds()
	maxNs := d.cfg.MaxInterval.Nanoseconds()

	if d.cfg.Pattern == "mimic_browsing" {
		// Simulate web browsing: bursts followed by pauses
		if d.rng.Float32() < 0.3 {
			// Short burst interval
			return time.Duration(minNs + d.rng.Int63n(maxNs-minNs)/10)
		}
		// Longer pause
		return time.Duration(minNs + d.rng.Int63n(maxNs-minNs))
	}

	return time.Duration(minNs + d.rng.Int63n(maxNs-minNs))
}

func (d *DecoyGenerator) sendDecoy() {
	d.mu.Lock()
	size := d.cfg.MinSize + d.rng.Intn(d.cfg.MaxSize-d.cfg.MinSize)
	d.mu.Unlock()

	// Generate random decoy data
	decoy := make([]byte, size)
	rand.Read(decoy)

	// Mark as decoy (first byte = 0x00)
	decoy[0] = 0x00

	// Send (ignore errors for decoy)
	d.conn.Write(decoy)
}

// ObfuscatedConn wraps a connection with obfuscation features
type ObfuscatedConn struct {
	net.Conn
	padder    *Padder
	jitterer  *Jitterer
	decoy     *DecoyGenerator
	readBuf   []byte
}

// NewObfuscatedConn creates an obfuscated connection wrapper
func NewObfuscatedConn(conn net.Conn, padCfg *PaddingConfig, jitCfg *JitterConfig, decoyCfg *DecoyConfig) *ObfuscatedConn {
	oc := &ObfuscatedConn{
		Conn:     conn,
		padder:   NewPadder(padCfg),
		jitterer: NewJitterer(jitCfg),
	}

	if decoyCfg != nil && decoyCfg.Enabled {
		oc.decoy = NewDecoyGenerator(decoyCfg, conn)
		oc.decoy.Start()
	}

	return oc
}

func (oc *ObfuscatedConn) Read(b []byte) (int, error) {
	// Return buffered data first
	if len(oc.readBuf) > 0 {
		n := copy(b, oc.readBuf)
		oc.readBuf = oc.readBuf[n:]
		return n, nil
	}

	buf := make([]byte, 65536)
	for {
		// Read from underlying connection
		n, err := oc.Conn.Read(buf)
		if err != nil {
			return 0, err
		}

		// Check for decoy (first byte = 0x00) — discard and loop
		if n > 0 && buf[0] == 0x00 {
			continue
		}

		// Unpad
		data, err := oc.padder.Unpad(buf[:n])
		if err != nil {
			return 0, err
		}

		// Copy to output
		copied := copy(b, data)
		if copied < len(data) {
			oc.readBuf = data[copied:]
		}

		return copied, nil
	}
}

func (oc *ObfuscatedConn) Write(b []byte) (int, error) {
	// Apply jitter
	delay := oc.jitterer.Delay()
	if delay > 0 {
		time.Sleep(delay)
	}

	// Mark as real data (first byte != 0x00)
	if len(b) > 0 && b[0] == 0x00 {
		// Escape the 0x00 by prepending 0x01
		b = append([]byte{0x01}, b...)
	}

	// Pad
	padded := oc.padder.Pad(b)

	// Write
	_, err := oc.Conn.Write(padded)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

func (oc *ObfuscatedConn) Close() error {
	if oc.decoy != nil {
		oc.decoy.Stop()
	}
	return oc.Conn.Close()
}

// ShapeTraffic applies traffic shaping to match a target pattern
func ShapeTraffic(r io.Reader, w io.Writer, targetBytesPerSec int) error {
	// Simple token bucket implementation
	bucket := targetBytesPerSec
	lastRefill := time.Now()

	buf := make([]byte, 4096)
	for {
		// Refill bucket based on elapsed time
		now := time.Now()
		elapsed := now.Sub(lastRefill)
		refill := int(elapsed.Seconds() * float64(targetBytesPerSec))
		bucket += refill
		if bucket > targetBytesPerSec {
			bucket = targetBytesPerSec
		}
		lastRefill = now

		// Read data
		toRead := len(buf)
		if toRead > bucket {
			toRead = bucket
		}
		if toRead == 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		n, err := r.Read(buf[:toRead])
		if err != nil {
			return err
		}

		// Write data
		_, err = w.Write(buf[:n])
		if err != nil {
			return err
		}

		bucket -= n
	}
}
