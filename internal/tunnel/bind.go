package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/ghostwire/ghostwire/internal/transport/https"
)

// HTTPSBind implements conn.Bind for tunneling WireGuard over HTTPS
type HTTPSBind struct {
	transport   *https.Transport
	localAddr   net.Addr
	remoteConns map[string]*httpsEndpoint // endpoint string -> connection
	connsMu     sync.RWMutex
	recvChan    chan recvPacket
	closed      bool
	closeMu     sync.Mutex
}

type recvPacket struct {
	data     []byte
	endpoint conn.Endpoint
}

type httpsEndpoint struct {
	conn       net.Conn
	addr       string
	lastActive time.Time
}

func (e *httpsEndpoint) ClearSrc() {}

func (e *httpsEndpoint) SrcToString() string {
	return ""
}

func (e *httpsEndpoint) DstToString() string {
	return e.addr
}

func (e *httpsEndpoint) DstToBytes() []byte {
	return []byte(e.addr)
}

func (e *httpsEndpoint) DstIP() netip.Addr {
	host, _, _ := net.SplitHostPort(e.addr)
	addr, _ := netip.ParseAddr(host)
	return addr
}

func (e *httpsEndpoint) SrcIP() netip.Addr {
	return netip.Addr{}
}

// BindConfig holds configuration for creating an HTTPS bind
type BindConfig struct {
	// ServerName for TLS SNI
	ServerName string

	// MeshSecret for knock authentication
	MeshSecret []byte

	// ListenAddr for server mode (empty = client only)
	ListenAddr string

	// TLSConfig for custom TLS settings
	TLSConfig *tls.Config
}

// NewHTTPSBind creates a new HTTPS-based WireGuard bind
func NewHTTPSBind(cfg *BindConfig) (*HTTPSBind, error) {
	transportCfg := &https.Config{
		ServerName: cfg.ServerName,
		MeshSecret: cfg.MeshSecret,
	}

	transport, err := https.New(transportCfg)
	if err != nil {
		return nil, fmt.Errorf("create transport: %w", err)
	}

	b := &HTTPSBind{
		transport:   transport,
		remoteConns: make(map[string]*httpsEndpoint),
		recvChan:    make(chan recvPacket, 256),
	}

	return b, nil
}

// Open implements conn.Bind
func (b *HTTPSBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.closeMu.Lock()
	defer b.closeMu.Unlock()

	if b.closed {
		return nil, 0, fmt.Errorf("bind is closed")
	}

	// Create receive function
	recvFunc := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case pkt, ok := <-b.recvChan:
			if !ok {
				return 0, io.EOF
			}
			n := copy(bufs[0], pkt.data)
			sizes[0] = n
			eps[0] = pkt.endpoint
			return 1, nil
		}
	}

	// Return actual port (0 since we're using HTTPS)
	return []conn.ReceiveFunc{recvFunc}, 443, nil
}

// Close implements conn.Bind
func (b *HTTPSBind) Close() error {
	b.closeMu.Lock()
	defer b.closeMu.Unlock()

	if b.closed {
		return nil
	}
	b.closed = true

	close(b.recvChan)

	b.connsMu.Lock()
	for _, ep := range b.remoteConns {
		ep.conn.Close()
	}
	b.remoteConns = make(map[string]*httpsEndpoint)
	b.connsMu.Unlock()

	return b.transport.Close()
}

// SetMark implements conn.Bind (no-op for HTTPS)
func (b *HTTPSBind) SetMark(mark uint32) error {
	return nil
}

// Send implements conn.Bind
func (b *HTTPSBind) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	ep, ok := endpoint.(*httpsEndpoint)
	if !ok {
		return fmt.Errorf("invalid endpoint type")
	}

	b.connsMu.RLock()
	existing, exists := b.remoteConns[ep.addr]
	b.connsMu.RUnlock()

	var c net.Conn
	if exists && existing.conn != nil {
		c = existing.conn
	} else {
		// Establish new connection
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		newConn, err := b.transport.Dial(ctx, ep.addr)
		if err != nil {
			return fmt.Errorf("dial %s: %w", ep.addr, err)
		}
		c = newConn

		b.connsMu.Lock()
		ep.conn = c
		b.remoteConns[ep.addr] = ep
		b.connsMu.Unlock()

		// Start receiver goroutine for this connection
		go b.receiveLoop(ep)
	}

	// Send all buffers
	for _, buf := range bufs {
		if _, err := c.Write(buf); err != nil {
			return fmt.Errorf("write: %w", err)
		}
	}

	return nil
}

// ParseEndpoint implements conn.Bind
func (b *HTTPSBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return &httpsEndpoint{addr: s}, nil
}

// BatchSize implements conn.Bind
func (b *HTTPSBind) BatchSize() int {
	return 1
}

func (b *HTTPSBind) receiveLoop(ep *httpsEndpoint) {
	buf := make([]byte, 65536)
	for {
		n, err := ep.conn.Read(buf)
		if err != nil {
			b.connsMu.Lock()
			delete(b.remoteConns, ep.addr)
			b.connsMu.Unlock()
			return
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		select {
		case b.recvChan <- recvPacket{data: data, endpoint: ep}:
		default:
			// Drop packet if channel full
		}
	}
}

// DirectBind wraps the default UDP bind with fallback support
type DirectBind struct {
	bind conn.Bind
}

// NewDirectBind creates a standard UDP bind
func NewDirectBind() *DirectBind {
	return &DirectBind{
		bind: conn.NewDefaultBind(),
	}
}

func (b *DirectBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return b.bind.Open(port)
}

func (b *DirectBind) Close() error {
	return b.bind.Close()
}

func (b *DirectBind) SetMark(mark uint32) error {
	return b.bind.SetMark(mark)
}

func (b *DirectBind) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	return b.bind.Send(bufs, endpoint)
}

func (b *DirectBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return b.bind.ParseEndpoint(s)
}

func (b *DirectBind) BatchSize() int {
	return b.bind.BatchSize()
}

// HybridBind supports both HTTPS and direct UDP connections
type HybridBind struct {
	httpsBind  *HTTPSBind
	directBind *DirectBind
	preferHTTPS bool
}

// NewHybridBind creates a bind that can use both HTTPS and direct UDP
func NewHybridBind(httpsCfg *BindConfig, preferHTTPS bool) (*HybridBind, error) {
	var httpsBind *HTTPSBind
	var err error

	if httpsCfg != nil {
		httpsBind, err = NewHTTPSBind(httpsCfg)
		if err != nil {
			return nil, err
		}
	}

	return &HybridBind{
		httpsBind:   httpsBind,
		directBind:  NewDirectBind(),
		preferHTTPS: preferHTTPS,
	}, nil
}

func (b *HybridBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	var recvFuncs []conn.ReceiveFunc
	var actualPort uint16

	if b.httpsBind != nil {
		funcs, p, err := b.httpsBind.Open(port)
		if err == nil {
			recvFuncs = append(recvFuncs, funcs...)
			actualPort = p
		}
	}

	if b.directBind != nil {
		funcs, p, err := b.directBind.Open(port)
		if err == nil {
			recvFuncs = append(recvFuncs, funcs...)
			if actualPort == 0 {
				actualPort = p
			}
		}
	}

	if len(recvFuncs) == 0 {
		return nil, 0, fmt.Errorf("no binds available")
	}

	return recvFuncs, actualPort, nil
}

func (b *HybridBind) Close() error {
	var err error
	if b.httpsBind != nil {
		err = b.httpsBind.Close()
	}
	if b.directBind != nil {
		if e := b.directBind.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

func (b *HybridBind) SetMark(mark uint32) error {
	if b.httpsBind != nil {
		b.httpsBind.SetMark(mark)
	}
	if b.directBind != nil {
		b.directBind.SetMark(mark)
	}
	return nil
}

func (b *HybridBind) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	// Try HTTPS first if preferred and endpoint looks like HTTPS
	if b.preferHTTPS && b.httpsBind != nil {
		if _, ok := endpoint.(*httpsEndpoint); ok {
			return b.httpsBind.Send(bufs, endpoint)
		}
	}

	// Fall back to direct
	if b.directBind != nil {
		return b.directBind.Send(bufs, endpoint)
	}

	return fmt.Errorf("no bind available for endpoint")
}

func (b *HybridBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	// Determine endpoint type based on format
	// HTTPS endpoints use "https://host:port" format
	// Direct endpoints use "host:port" format
	if len(s) > 8 && s[:8] == "https://" {
		if b.httpsBind != nil {
			return b.httpsBind.ParseEndpoint(s[8:])
		}
	}

	if b.directBind != nil {
		return b.directBind.ParseEndpoint(s)
	}

	return nil, fmt.Errorf("no bind available for endpoint: %s", s)
}

func (b *HybridBind) BatchSize() int {
	return 1
}

// Listener for server-side HTTPS connections
type HTTPSListener struct {
	transport *https.Transport
	listener  net.Listener
	bind      *HTTPSBind
}

// StartHTTPSListener starts listening for incoming HTTPS connections
func (b *HTTPSBind) StartListener(addr string, tlsConfig *tls.Config) error {
	ln, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}

			// Handle incoming connection
			go b.handleIncoming(conn)
		}
	}()

	return nil
}

func (b *HTTPSBind) handleIncoming(c net.Conn) {
	// Wrap connection with HTTP handling for knock auth
	// This is simplified - full implementation would do HTTP parsing

	remoteAddr := c.RemoteAddr().String()
	ep := &httpsEndpoint{
		conn: c,
		addr: remoteAddr,
	}

	b.connsMu.Lock()
	b.remoteConns[remoteAddr] = ep
	b.connsMu.Unlock()

	// Start receive loop
	b.receiveLoop(ep)
}

// Ensure interfaces are satisfied
var _ conn.Bind = (*HTTPSBind)(nil)
var _ conn.Bind = (*DirectBind)(nil)
var _ conn.Bind = (*HybridBind)(nil)
var _ conn.Endpoint = (*httpsEndpoint)(nil)
