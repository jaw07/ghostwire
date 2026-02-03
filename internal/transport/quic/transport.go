// Package quic implements a QUIC-based obfuscation transport.
// QUIC traffic is common on modern networks (Google, YouTube, Cloudflare)
// making it excellent for blending in with normal traffic.
package quic

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/ghostwire/ghostwire/internal/transport"
)

const (
	// Name is the transport identifier
	Name = "quic"

	// StreamTypeData identifies data streams
	StreamTypeData uint8 = 0x01

	// StreamTypeControl identifies control streams
	StreamTypeControl uint8 = 0x02
)

// Config holds QUIC transport configuration
type Config struct {
	// ServerName for TLS SNI
	ServerName string

	// ListenAddr for server mode
	ListenAddr string

	// MeshSecret for authentication
	MeshSecret []byte

	// LocalPublicKey for identification
	LocalPublicKey []byte

	// MaxIdleTimeout before connection cleanup
	MaxIdleTimeout time.Duration

	// KeepAlivePeriod for connection maintenance
	KeepAlivePeriod time.Duration

	// EnableDatagrams for unreliable delivery (lower latency)
	EnableDatagrams bool
}

// DefaultConfig returns default QUIC transport configuration
func DefaultConfig() *Config {
	return &Config{
		ServerName:      "www.google.com",
		ListenAddr:      ":443",
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 10 * time.Second,
		EnableDatagrams: true,
	}
}

// Transport implements the QUIC obfuscation transport
type Transport struct {
	cfg       *Config
	tlsConfig *tls.Config
	quicCfg   *quic.Config
	listener  *quic.Listener
	mu        sync.Mutex
	closed    bool

	// Active connections
	conns   map[string]*QUICConn
	connsMu sync.RWMutex
}

// New creates a new QUIC transport
func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Generate self-signed certificate (in production, use real certs)
	tlsCert, err := generateSelfSignedCert(cfg.ServerName)
	if err != nil {
		return nil, fmt.Errorf("generate cert: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h3", "h3-29"}, // HTTP/3 ALPN
		ServerName:   cfg.ServerName,
		MinVersion:   tls.VersionTLS13,
	}

	quicCfg := &quic.Config{
		MaxIdleTimeout:  cfg.MaxIdleTimeout,
		KeepAlivePeriod: cfg.KeepAlivePeriod,
		EnableDatagrams: cfg.EnableDatagrams,
		Allow0RTT:       true,
	}

	return &Transport{
		cfg:       cfg,
		tlsConfig: tlsConfig,
		quicCfg:   quicCfg,
		conns:     make(map[string]*QUICConn),
	}, nil
}

// Name returns the transport identifier
func (t *Transport) Name() string {
	return Name
}

// Dial establishes an outbound QUIC connection
func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, fmt.Errorf("transport closed")
	}
	t.mu.Unlock()

	// Client TLS config
	tlsConfig := &tls.Config{
		ServerName:         t.cfg.ServerName,
		NextProtos:         []string{"h3", "h3-29"},
		InsecureSkipVerify: true, // For self-signed certs in mesh
		MinVersion:         tls.VersionTLS13,
	}

	conn, err := quic.DialAddr(ctx, addr, tlsConfig, t.quicCfg)
	if err != nil {
		return nil, fmt.Errorf("dial QUIC: %w", err)
	}

	// Open data stream
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "stream open failed")
		return nil, fmt.Errorf("open stream: %w", err)
	}

	// Send authentication
	if err := t.authenticate(stream); err != nil {
		conn.CloseWithError(0, "auth failed")
		return nil, fmt.Errorf("authenticate: %w", err)
	}

	qc := &QUICConn{
		conn:       conn,
		stream:     stream,
		localAddr:  conn.LocalAddr(),
		remoteAddr: conn.RemoteAddr(),
	}

	// Store connection
	t.connsMu.Lock()
	t.conns[addr] = qc
	t.connsMu.Unlock()

	return transport.NewConnWrapper(qc, Name, t.cfg.LocalPublicKey), nil
}

// authenticate sends mesh authentication over the stream
func (t *Transport) authenticate(stream *quic.Stream) error {
	// Simple knock: timestamp + HMAC
	timestamp := time.Now().Unix()
	msg := make([]byte, 8+32)
	binary.BigEndian.PutUint64(msg[:8], uint64(timestamp))

	// Simple HMAC-like: XOR mesh secret with timestamp
	for i := 0; i < 32 && i < len(t.cfg.MeshSecret); i++ {
		msg[8+i] = t.cfg.MeshSecret[i] ^ byte(timestamp>>(i%8))
	}

	_, err := (*stream).Write(msg)
	return err
}

// Listen creates a QUIC listener
func (t *Transport) Listen(ctx context.Context, addr string) (transport.Listener, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, fmt.Errorf("transport closed")
	}

	if addr == "" {
		addr = t.cfg.ListenAddr
	}

	listener, err := quic.ListenAddr(addr, t.tlsConfig, t.quicCfg)
	if err != nil {
		return nil, fmt.Errorf("listen QUIC: %w", err)
	}

	t.listener = listener

	return &quicListener{
		transport: t,
		listener:  listener,
		ctx:       ctx,
	}, nil
}

// Close shuts down the transport
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	if t.listener != nil {
		t.listener.Close()
	}

	t.connsMu.Lock()
	for _, conn := range t.conns {
		conn.Close()
	}
	t.connsMu.Unlock()

	return nil
}

// QUICConn wraps a QUIC connection as net.Conn
type QUICConn struct {
	conn       *quic.Conn
	stream     *quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
	mu         sync.Mutex
}

func (c *QUICConn) Read(b []byte) (int, error) {
	return (*c.stream).Read(b)
}

func (c *QUICConn) Write(b []byte) (int, error) {
	return (*c.stream).Write(b)
}

func (c *QUICConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	(*c.stream).Close()
	return c.conn.CloseWithError(0, "closed")
}

func (c *QUICConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *QUICConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *QUICConn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

func (c *QUICConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *QUICConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

// quicListener implements transport.Listener
type quicListener struct {
	transport *Transport
	listener  *quic.Listener
	ctx       context.Context
}

func (l *quicListener) Accept() (net.Conn, error) {
	conn, err := l.listener.Accept(l.ctx)
	if err != nil {
		return nil, err
	}

	// Accept incoming stream
	stream, err := conn.AcceptStream(l.ctx)
	if err != nil {
		conn.CloseWithError(0, "no stream")
		return nil, err
	}

	// Verify authentication
	peerPubKey, err := l.verifyAuth(stream)
	if err != nil {
		conn.CloseWithError(0, "auth failed")
		return nil, err
	}

	qc := &QUICConn{
		conn:       conn,
		stream:     stream,
		localAddr:  conn.LocalAddr(),
		remoteAddr: conn.RemoteAddr(),
	}

	return transport.NewConnWrapper(qc, Name, peerPubKey), nil
}

func (l *quicListener) verifyAuth(stream *quic.Stream) ([]byte, error) {
	msg := make([]byte, 40)
	n, err := (*stream).Read(msg)
	if err != nil || n < 40 {
		return nil, fmt.Errorf("read auth failed")
	}

	timestamp := int64(binary.BigEndian.Uint64(msg[:8]))

	// Check timestamp freshness (within 30 seconds)
	if abs(time.Now().Unix()-timestamp) > 30 {
		return nil, fmt.Errorf("stale timestamp")
	}

	// Verify HMAC
	expected := make([]byte, 32)
	for i := 0; i < 32 && i < len(l.transport.cfg.MeshSecret); i++ {
		expected[i] = l.transport.cfg.MeshSecret[i] ^ byte(timestamp>>(i%8))
	}

	for i := range expected {
		if msg[8+i] != expected[i] {
			return nil, fmt.Errorf("invalid auth")
		}
	}

	return nil, nil // Could extract peer pubkey from extended auth
}

func (l *quicListener) Close() error {
	return l.listener.Close()
}

func (l *quicListener) Addr() net.Addr {
	return l.listener.Addr()
}

func generateSelfSignedCert(serverName string) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: serverName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{serverName},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
