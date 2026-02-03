// Package fronting implements domain fronting for censorship circumvention.
// Domain fronting hides the true destination by using a CDN as an intermediary.
// The TLS SNI shows a high-reputation domain while the HTTP Host header routes to the relay.
package fronting

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ghostwire/ghostwire/internal/transport"
)

const (
	// Name is the transport identifier
	Name = "domain-fronting"
)

// Config holds domain fronting configuration
type Config struct {
	// FrontDomain is the domain shown in TLS SNI (e.g., "www.google.com")
	FrontDomain string

	// TargetHost is the actual Host header destination (your relay)
	TargetHost string

	// CDNAddr is the CDN edge server address
	CDNAddr string

	// MeshSecret for authentication
	MeshSecret []byte

	// LocalPublicKey for identification
	LocalPublicKey []byte

	// Path is the URL path for the tunnel
	Path string

	// UserAgent to use in requests
	UserAgent string
}

// DefaultConfig returns default domain fronting configuration
func DefaultConfig() *Config {
	return &Config{
		FrontDomain: "www.google.com",
		CDNAddr:     "www.google.com:443",
		Path:        "/generate_204",
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
}

// Transport implements domain fronting
type Transport struct {
	cfg    *Config
	mu     sync.Mutex
	closed bool
}

// New creates a new domain fronting transport
func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if cfg.FrontDomain == "" {
		return nil, fmt.Errorf("front domain required")
	}

	if cfg.TargetHost == "" {
		return nil, fmt.Errorf("target host required")
	}

	return &Transport{
		cfg: cfg,
	}, nil
}

// Name returns the transport identifier
func (t *Transport) Name() string {
	return Name
}

// Dial establishes a domain-fronted connection
func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, fmt.Errorf("transport closed")
	}
	t.mu.Unlock()

	// Connect to CDN with front domain in SNI
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	tcpConn, err := dialer.DialContext(ctx, "tcp", t.cfg.CDNAddr)
	if err != nil {
		return nil, fmt.Errorf("dial CDN: %w", err)
	}

	// TLS with front domain
	tlsConfig := &tls.Config{
		ServerName: t.cfg.FrontDomain,
		MinVersion: tls.VersionTLS12,
	}

	tlsConn := tls.Client(tcpConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	// Send HTTP CONNECT with real target in Host header
	fc := &frontedConn{
		conn:       tlsConn,
		cfg:        t.cfg,
		readBuf:    bufio.NewReader(tlsConn),
		localAddr:  tlsConn.LocalAddr(),
		remoteAddr: tlsConn.RemoteAddr(),
	}

	// Upgrade to tunnel mode
	if err := fc.upgrade(ctx); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("upgrade: %w", err)
	}

	return transport.NewConnWrapper(fc, Name, t.cfg.LocalPublicKey), nil
}

// Listen is not typically used for domain fronting (client-only)
func (t *Transport) Listen(ctx context.Context, addr string) (transport.Listener, error) {
	return nil, fmt.Errorf("domain fronting is client-only; use HTTPS transport for server")
}

// Close shuts down the transport
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return nil
}

// frontedConn wraps a domain-fronted connection
type frontedConn struct {
	conn       net.Conn
	cfg        *Config
	readBuf    *bufio.Reader
	localAddr  net.Addr
	remoteAddr net.Addr
	upgraded   bool
	mu         sync.Mutex
}

// upgrade performs the HTTP upgrade to tunnel mode
func (fc *frontedConn) upgrade(ctx context.Context) error {
	// Build HTTP request with Host header pointing to real target
	req := fmt.Sprintf("POST %s HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"User-Agent: %s\r\n"+
		"Content-Type: application/octet-stream\r\n"+
		"Connection: Upgrade\r\n"+
		"Upgrade: websocket\r\n"+
		"X-GW-Auth: %x\r\n"+
		"\r\n",
		fc.cfg.Path,
		fc.cfg.TargetHost,
		fc.cfg.UserAgent,
		fc.computeAuth(),
	)

	if _, err := fc.conn.Write([]byte(req)); err != nil {
		return fmt.Errorf("send request: %w", err)
	}

	// Read response
	resp, err := http.ReadResponse(fc.readBuf, nil)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	defer resp.Body.Close()

	// Check for upgrade success (101 Switching Protocols or 200 OK)
	if resp.StatusCode != 101 && resp.StatusCode != 200 {
		return fmt.Errorf("upgrade failed: %d %s", resp.StatusCode, resp.Status)
	}

	fc.upgraded = true
	return nil
}

func (fc *frontedConn) computeAuth() []byte {
	// Simple timestamp-based auth
	ts := time.Now().Unix()
	auth := make([]byte, 16)
	for i := 0; i < 16 && i < len(fc.cfg.MeshSecret); i++ {
		auth[i] = fc.cfg.MeshSecret[i] ^ byte(ts>>(i%8))
	}
	return auth
}

func (fc *frontedConn) Read(b []byte) (int, error) {
	if fc.readBuf != nil && fc.readBuf.Buffered() > 0 {
		return fc.readBuf.Read(b)
	}
	return fc.conn.Read(b)
}

func (fc *frontedConn) Write(b []byte) (int, error) {
	return fc.conn.Write(b)
}

func (fc *frontedConn) Close() error {
	return fc.conn.Close()
}

func (fc *frontedConn) LocalAddr() net.Addr {
	return fc.localAddr
}

func (fc *frontedConn) RemoteAddr() net.Addr {
	return fc.remoteAddr
}

func (fc *frontedConn) SetDeadline(t time.Time) error {
	return fc.conn.SetDeadline(t)
}

func (fc *frontedConn) SetReadDeadline(t time.Time) error {
	return fc.conn.SetReadDeadline(t)
}

func (fc *frontedConn) SetWriteDeadline(t time.Time) error {
	return fc.conn.SetWriteDeadline(t)
}

// FrontedDialer provides a high-level interface for domain fronting
type FrontedDialer struct {
	// Fronts maps front domains to their CDN addresses
	Fronts map[string]string

	// Target is the actual destination host
	Target string

	// MeshSecret for authentication
	MeshSecret []byte

	mu sync.Mutex
}

// Dial connects using the best available front
func (fd *FrontedDialer) Dial(ctx context.Context) (net.Conn, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()

	// Try each front in order
	var lastErr error
	for front, cdnAddr := range fd.Fronts {
		cfg := &Config{
			FrontDomain: front,
			TargetHost:  fd.Target,
			CDNAddr:     cdnAddr,
			MeshSecret:  fd.MeshSecret,
		}

		t, _ := New(cfg)
		conn, err := t.Dial(ctx, cdnAddr)
		if err != nil {
			lastErr = err
			continue
		}
		return conn, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no fronts available")
}

// WellKnownFronts returns commonly used front domains
func WellKnownFronts() map[string]string {
	return map[string]string{
		// Note: These are examples - actual availability varies
		"www.google.com":     "www.google.com:443",
		"ajax.googleapis.com": "ajax.googleapis.com:443",
		"fonts.googleapis.com": "fonts.googleapis.com:443",
	}
}

// ProbeConn wraps a connection for probe detection
type ProbeConn struct {
	net.Conn
	initData    []byte
	initDataPos int
}

// NewProbeConn creates a probe-resistant connection
func NewProbeConn(conn net.Conn, initData []byte) *ProbeConn {
	return &ProbeConn{
		Conn:     conn,
		initData: initData,
	}
}

func (pc *ProbeConn) Read(b []byte) (int, error) {
	// First return any buffered initial data
	if pc.initDataPos < len(pc.initData) {
		n := copy(b, pc.initData[pc.initDataPos:])
		pc.initDataPos += n
		return n, nil
	}
	return pc.Conn.Read(b)
}

func (pc *ProbeConn) WriteTo(w io.Writer) (int64, error) {
	// Write buffered data first
	var total int64
	if pc.initDataPos < len(pc.initData) {
		n, err := w.Write(pc.initData[pc.initDataPos:])
		total += int64(n)
		pc.initDataPos = len(pc.initData)
		if err != nil {
			return total, err
		}
	}

	// Then copy from connection
	n, err := io.Copy(w, pc.Conn)
	return total + n, err
}
