// Package direct implements a simple direct transport with no obfuscation.
// This transport is used for testing, development, and environments where
// obfuscation is not required.
package direct

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ghostwire/ghostwire/internal/transport"
)

const (
	// Name is the transport identifier
	Name = "direct"
)

func init() {
	// Register with the default transport registry
	transport.Register(Name, func(cfg interface{}) (transport.Transport, error) {
		directCfg, ok := cfg.(*Config)
		if !ok {
			return nil, fmt.Errorf("invalid config type for direct transport")
		}
		return New(directCfg), nil
	})
}

// Config holds configuration for the direct transport
type Config struct {
	// ListenAddr is the address to listen on (e.g., ":51820")
	ListenAddr string

	// Network is the network type ("udp", "tcp")
	Network string
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Network: "udp",
	}
}

// Transport implements a direct passthrough transport
type Transport struct {
	cfg      *Config
	listener net.Listener
	mu       sync.Mutex
	closed   bool
}

// New creates a new direct transport
func New(cfg *Config) *Transport {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if cfg.Network == "" {
		cfg.Network = "udp"
	}
	return &Transport{
		cfg: cfg,
	}
}

// Name returns the transport identifier
func (t *Transport) Name() string {
	return Name
}

// Dial establishes an outbound connection
func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, fmt.Errorf("transport closed")
	}
	t.mu.Unlock()

	var d net.Dialer
	conn, err := d.DialContext(ctx, t.cfg.Network, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	return transport.NewConnWrapper(conn, Name, nil), nil
}

// Listen creates a listener for incoming connections
func (t *Transport) Listen(ctx context.Context, addr string) (transport.Listener, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, fmt.Errorf("transport closed")
	}

	if addr == "" {
		addr = t.cfg.ListenAddr
	}

	switch t.cfg.Network {
	case "tcp":
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("listen tcp: %w", err)
		}
		t.listener = listener
		return &tcpListener{listener: listener}, nil

	case "udp":
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("resolve udp addr: %w", err)
		}
		conn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return nil, fmt.Errorf("listen udp: %w", err)
		}
		return newUDPListener(conn), nil

	default:
		return nil, fmt.Errorf("unsupported network: %s", t.cfg.Network)
	}
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
		return t.listener.Close()
	}
	return nil
}

// tcpListener wraps a TCP listener
type tcpListener struct {
	listener net.Listener
}

func (l *tcpListener) Accept() (net.Conn, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	return transport.NewConnWrapper(conn, Name, nil), nil
}

func (l *tcpListener) Close() error {
	return l.listener.Close()
}

func (l *tcpListener) Addr() net.Addr {
	return l.listener.Addr()
}

// udpListener wraps a UDP connection as a pseudo-listener with per-remote-address
// connection demuxing. Each unique remote address gets its own virtual connection
// with a dedicated receive buffer.
type udpListener struct {
	conn    *net.UDPConn
	mu      sync.Mutex
	closed  bool
	clients map[string]*udpVirtualConn // remoteAddr string -> vconn
	acceptQ chan *udpVirtualConn       // new connections for Accept()
	done    chan struct{}
}

func newUDPListener(conn *net.UDPConn) *udpListener {
	l := &udpListener{
		conn:    conn,
		clients: make(map[string]*udpVirtualConn),
		acceptQ: make(chan *udpVirtualConn, 64),
		done:    make(chan struct{}),
	}
	go l.readLoop()
	return l
}

func (l *udpListener) readLoop() {
	buf := make([]byte, 65536)
	for {
		n, remoteAddr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			close(l.acceptQ)
			return
		}

		key := remoteAddr.String()
		data := make([]byte, n)
		copy(data, buf[:n])

		l.mu.Lock()
		vconn, exists := l.clients[key]
		if !exists {
			// New remote — create virtual connection
			vconn = &udpVirtualConn{
				conn:       l.conn,
				localAddr:  l.conn.LocalAddr(),
				remoteAddr: remoteAddr,
				recvCh:     make(chan []byte, 256),
				closeCh:    make(chan struct{}),
				onClose: func() {
					l.mu.Lock()
					delete(l.clients, key)
					l.mu.Unlock()
				},
			}
			l.clients[key] = vconn
			l.mu.Unlock()

			// Queue for Accept
			select {
			case l.acceptQ <- vconn:
			default:
				// Accept queue full — drop connection
			}
		} else {
			l.mu.Unlock()
		}

		// Deliver packet to the virtual connection
		select {
		case vconn.recvCh <- data:
		default:
			// Drop if buffer full
		}
	}
}

func (l *udpListener) Accept() (net.Conn, error) {
	vconn, ok := <-l.acceptQ
	if !ok {
		return nil, net.ErrClosed
	}
	return transport.NewConnWrapper(vconn, Name, nil), nil
}

func (l *udpListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	return l.conn.Close()
}

func (l *udpListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// udpVirtualConn is a per-remote-address virtual connection over a shared
// UDP socket. Each remote gets its own receive channel for proper demuxing.
type udpVirtualConn struct {
	conn       *net.UDPConn
	localAddr  net.Addr
	remoteAddr *net.UDPAddr
	recvCh     chan []byte
	closeCh    chan struct{}
	closeOnce  sync.Once
	onClose    func()
}

func (c *udpVirtualConn) Read(b []byte) (int, error) {
	select {
	case data, ok := <-c.recvCh:
		if !ok {
			return 0, net.ErrClosed
		}
		return copy(b, data), nil
	case <-c.closeCh:
		return 0, net.ErrClosed
	}
}

func (c *udpVirtualConn) Write(b []byte) (int, error) {
	return c.conn.WriteToUDP(b, c.remoteAddr)
}

func (c *udpVirtualConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeCh)
		if c.onClose != nil {
			c.onClose()
		}
	})
	return nil
}

func (c *udpVirtualConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *udpVirtualConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *udpVirtualConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *udpVirtualConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *udpVirtualConn) SetWriteDeadline(t time.Time) error {
	return nil
}
