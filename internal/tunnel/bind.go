package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/ghostwire/ghostwire/internal/obfuscation"
	"github.com/ghostwire/ghostwire/internal/transport/https"
)

// transportIdleTimeout bounds how long a post-knock transport connection may go
// without any read before it is reaped. WireGuard persistent keepalive (25s)
// keeps live tunnels well under this; it exists to free goroutines/connections
// held by dead or stalled (slowloris) peers.
const transportIdleTimeout = 5 * time.Minute

// wsConn wraps a net.Conn with WebSocket binary framing.
// This makes post-knock WireGuard traffic look like a WebSocket session
// to DPI systems. Each WireGuard packet is sent as a WebSocket binary frame
// with randomized padding to resist traffic analysis.
// The real payload length is XOR-masked with a per-session key to prevent
// the length field from being used as a DPI fingerprint.
type wsConn struct {
	net.Conn
	readBuf  []byte  // buffered payload from partially-read frame
	lenMask  [2]byte // per-session XOR mask for length field
	isClient bool    // client frames are masked per RFC 6455
}

func newWSConn(c net.Conn) (*wsConn, error) {
	var mask [2]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return nil, fmt.Errorf("generate length mask: %w", err)
	}
	w := &wsConn{Conn: c, lenMask: mask, isClient: true}
	// Send the mask as the first 2 bytes so the peer can decode lengths.
	// A failed write leaves the session desynced, so surface the error.
	if _, err := c.Write(mask[:]); err != nil {
		return nil, fmt.Errorf("send length mask: %w", err)
	}
	return w, nil
}

func newWSConnServer(c net.Conn) (*wsConn, error) {
	// Read the client's length mask
	var mask [2]byte
	if _, err := io.ReadFull(c, mask[:]); err != nil {
		return nil, fmt.Errorf("read length mask: %w", err)
	}
	return &wsConn{Conn: c, lenMask: mask, isClient: false}, nil
}

// Write wraps data in a WebSocket binary frame: 0x82 + length + mask + payload
func (w *wsConn) Write(b []byte) (int, error) {
	// Add random padding (4-64 bytes) to resist packet-size analysis.
	// Uses crypto/rand to prevent padding length from leaking payload content.
	var padByte [1]byte
	rand.Read(padByte[:])
	padLen := 4 + int(padByte[0]%61)
	padded := make([]byte, len(b)+padLen)
	copy(padded, b)
	rand.Read(padded[len(b):]) // random padding bytes

	frame := encodeWSFrame(0x82, padded, len(b), w.lenMask, w.isClient) // 0x82 = binary, final
	_, err := w.Conn.Write(frame)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// Read reads a WebSocket frame and returns the payload (without padding)
func (w *wsConn) Read(b []byte) (int, error) {
	// Return buffered data first
	if len(w.readBuf) > 0 {
		n := copy(b, w.readBuf)
		w.readBuf = w.readBuf[n:]
		return n, nil
	}

	payload, err := decodeWSFrame(w.Conn, w.lenMask)
	if err != nil {
		return 0, err
	}

	n := copy(b, payload)
	if n < len(payload) {
		w.readBuf = payload[n:]
	}
	return n, nil
}

// encodeWSFrame creates a WebSocket binary frame per RFC 6455.
// Client frames include the MASK bit and a 4-byte masking key.
func encodeWSFrame(opcode byte, data []byte, realLen int, lenMask [2]byte, masked bool) []byte {
	totalLen := len(data) + 2 // +2 for masked realLen
	var header []byte
	lenByte := byte(0)
	if masked {
		lenByte = 0x80 // Set MASK bit per RFC 6455
	}

	if totalLen < 126 {
		header = []byte{opcode, lenByte | byte(totalLen)}
	} else if totalLen < 65536 {
		header = []byte{opcode, lenByte | 126, byte(totalLen >> 8), byte(totalLen)}
	} else {
		header = make([]byte, 10)
		header[0] = opcode
		header[1] = lenByte | 127
		binary.BigEndian.PutUint64(header[2:], uint64(totalLen))
	}

	// Generate masking key if client
	var maskKey [4]byte
	if masked {
		rand.Read(maskKey[:])
		header = append(header, maskKey[:]...)
	}

	// Build payload: maskedRealLen(2) + data
	payload := make([]byte, 2+len(data))
	var lenBytes [2]byte
	binary.BigEndian.PutUint16(lenBytes[:], uint16(realLen))
	payload[0] = lenBytes[0] ^ lenMask[0]
	payload[1] = lenBytes[1] ^ lenMask[1]
	copy(payload[2:], data)

	// Apply masking per RFC 6455 if client
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	frame := make([]byte, len(header)+len(payload))
	copy(frame, header)
	copy(frame[len(header):], payload)
	return frame
}

// decodeWSFrame reads one WebSocket frame per RFC 6455 and returns the real payload
func decodeWSFrame(r io.Reader, lenMask [2]byte) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}

	isMasked := hdr[1]&0x80 != 0
	payloadLen := uint64(hdr[1] & 0x7F)
	switch payloadLen {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return nil, err
		}
		payloadLen = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(r, ext[:]); err != nil {
			return nil, err
		}
		payloadLen = binary.BigEndian.Uint64(ext[:])
	}

	// Read masking key if present (RFC 6455: client-to-server frames are masked)
	var maskKey [4]byte
	if isMasked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return nil, err
		}
	}

	if payloadLen < 2 || payloadLen > 65536+2 {
		return nil, fmt.Errorf("invalid ws frame length: %d", payloadLen)
	}

	buf := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	// Unmask if needed
	if isMasked {
		for i := range buf {
			buf[i] ^= maskKey[i%4]
		}
	}

	// First 2 bytes are the XOR-masked real payload length
	buf[0] ^= lenMask[0]
	buf[1] ^= lenMask[1]
	realLen := binary.BigEndian.Uint16(buf[:2])
	if int(realLen) > len(buf)-2 {
		return nil, fmt.Errorf("invalid real length: %d > %d", realLen, len(buf)-2)
	}

	return buf[2 : 2+realLen], nil
}

// HTTPSBind implements conn.Bind for tunneling WireGuard over HTTPS
type HTTPSBind struct {
	transport   *https.Transport
	localAddr   net.Addr
	remoteConns map[string]*httpsEndpoint // endpoint string -> connection
	connsMu     sync.RWMutex
	recvChan    chan recvPacket
	done        chan struct{}  // closed by Close() to signal receive loops to stop
	listeners   []net.Listener // server-side listeners, closed by Close()
	obfuscate   bool           // wrap post-knock conns with the padding-mimicry layer
	closed      bool
	closeMu     sync.Mutex
}

// maybeObfuscate wraps a post-knock connection with the padding-mimicry layer
// when enabled (size-mimicry only — no timing jitter or decoy traffic, which
// would harm a live tunnel). Both peers must have it enabled; the config flag
// is mesh-wide.
func (b *HTTPSBind) maybeObfuscate(c net.Conn) net.Conn {
	if !b.obfuscate {
		return c
	}
	return obfuscation.NewObfuscatedConn(c,
		&obfuscation.PaddingConfig{Enabled: true, Mode: "mimic", TargetSizes: obfuscation.CommonHTTPSizes},
		&obfuscation.JitterConfig{Enabled: false},
		nil,
	)
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

	// LocalPublicKey is this node's WireGuard public key (for knock auth)
	LocalPublicKey []byte

	// ListenAddr for server mode (empty = client only)
	ListenAddr string

	// Obfuscate enables the padding-mimicry layer on post-knock connections.
	// Must match across the mesh.
	Obfuscate bool

	// TLSConfig for custom TLS settings
	TLSConfig *tls.Config
}

// NewHTTPSBind creates a new HTTPS-based WireGuard bind
func NewHTTPSBind(cfg *BindConfig) (*HTTPSBind, error) {
	transportCfg := &https.Config{
		ServerName:     cfg.ServerName,
		MeshSecret:     cfg.MeshSecret,
		LocalPublicKey: cfg.LocalPublicKey,
		KnockWindow:    https.DefaultKnockWindow,
		Timeout:        https.DefaultTimeout,
	}

	transport, err := https.New(transportCfg)
	if err != nil {
		return nil, fmt.Errorf("create transport: %w", err)
	}

	b := &HTTPSBind{
		transport:   transport,
		remoteConns: make(map[string]*httpsEndpoint),
		recvChan:    make(chan recvPacket, 256),
		done:        make(chan struct{}),
		obfuscate:   cfg.Obfuscate,
	}

	return b, nil
}

// Open implements conn.Bind.
// WireGuard calls Close() then Open() during device.Up(), so Open must
// be able to reopen a previously closed bind.
func (b *HTTPSBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.closeMu.Lock()
	defer b.closeMu.Unlock()

	// Reopen if previously closed (WireGuard lifecycle: Close -> Open on Up)
	if b.closed {
		b.recvChan = make(chan recvPacket, 256)
		b.done = make(chan struct{})
		b.closed = false
	}

	// Capture the current channels so the receive function is not racing with
	// a concurrent Close/Open swapping the fields.
	recvChan := b.recvChan
	done := b.done

	// Create receive function. recvChan is never closed (that would race with
	// in-flight sends from receiveLoop); shutdown is signalled via done.
	recvFunc := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case pkt := <-recvChan:
			n := copy(bufs[0], pkt.data)
			sizes[0] = n
			eps[0] = pkt.endpoint
			return 1, nil
		case <-done:
			return 0, io.EOF
		}
	}

	// Return actual port (0 since we're using HTTPS)
	return []conn.ReceiveFunc{recvFunc}, 443, nil
}

// Close implements conn.Bind.
// Closes the receive channel and active connections, but preserves the
// transport so the bind can be reopened by a subsequent Open() call.
func (b *HTTPSBind) Close() error {
	b.closeMu.Lock()
	defer b.closeMu.Unlock()

	if b.closed {
		return nil
	}
	b.closed = true

	// Signal receive loops and receive funcs to stop. We never close recvChan
	// itself: a receiveLoop may still be mid-send, and closing would panic.
	close(b.done)

	// Close any server-side listeners and stop their accept loops.
	for _, ln := range b.listeners {
		ln.Close()
	}
	b.listeners = nil

	b.connsMu.Lock()
	for _, ep := range b.remoteConns {
		ep.conn.Close()
	}
	b.remoteConns = make(map[string]*httpsEndpoint)
	b.connsMu.Unlock()

	// Don't close the transport — it will be reused if Open is called again.
	// The transport is only fully closed when the Device is closed.
	return nil
}

// SetMark implements conn.Bind (no-op for HTTPS)
func (b *HTTPSBind) SetMark(mark uint32) error {
	return nil
}

// Send implements conn.Bind
func (b *HTTPSBind) Send(bufs [][]byte, endpoint conn.Endpoint) error {
	b.closeMu.Lock()
	if b.closed {
		b.closeMu.Unlock()
		return net.ErrClosed
	}
	b.closeMu.Unlock()

	ep, ok := endpoint.(*httpsEndpoint)
	if !ok {
		return fmt.Errorf("invalid endpoint type")
	}

	// Use write lock for full check-then-dial to prevent duplicate connections
	b.connsMu.Lock()
	existing, exists := b.remoteConns[ep.addr]

	var c net.Conn
	if exists && existing.conn != nil {
		c = existing.conn
		b.connsMu.Unlock()
	} else {
		b.connsMu.Unlock()

		// Dial outside the lock (slow I/O operation)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		newConn, err := b.dialRaw(ctx, ep.addr)
		if err != nil {
			return fmt.Errorf("dial %s: %w", ep.addr, err)
		}
		c = newConn

		// Re-check under lock — another goroutine may have connected
		b.connsMu.Lock()
		if existing2, exists2 := b.remoteConns[ep.addr]; exists2 && existing2.conn != nil {
			// Another goroutine won the race — close our connection and use theirs
			b.connsMu.Unlock()
			c.(*wsConn).Conn.Close()
			c = existing2.conn
		} else {
			ep.conn = c
			b.remoteConns[ep.addr] = ep
			b.connsMu.Unlock()

			// Start receiver goroutine for this connection
			go b.receiveLoop(ep)
		}
	}

	// Send all buffers
	for _, buf := range bufs {
		if _, err := c.Write(buf); err != nil {
			return fmt.Errorf("write to %s: %w", ep.addr, err)
		}
	}
	// Packets sent

	return nil
}

// dialRaw establishes a raw TLS connection with knock authentication.
// Returns the raw TLS conn after knock handshake (no TunnelConn framing).
func (b *HTTPSBind) dialRaw(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial tcp: %w", err)
	}

	tlsConfig := &tls.Config{
		ServerName:         b.transport.ServerName(),
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
	}

	tlsConn := tls.Client(tcpConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	// Perform knock
	knock := b.transport.GenerateKnock()
	knockReq := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\n", knock.Path, b.transport.ServerName())
	for key, value := range knock.Headers {
		knockReq += fmt.Sprintf("%s: %s\r\n", key, value)
	}
	knockReq += fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(knock.Body), knock.Body)

	if _, err := tlsConn.Write([]byte(knockReq)); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("send knock: %w", err)
	}

	// Read knock response
	buf := make([]byte, 1024)
	n, err := tlsConn.Read(buf)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("read knock response: %w", err)
	}
	// Accept both 200 OK (legacy) and 101 Switching Protocols (WebSocket upgrade)
	if n < 12 || (string(buf[9:12]) != "200" && string(buf[9:12]) != "101") {
		tlsConn.Close()
		return nil, fmt.Errorf("knock failed: %s", string(buf[:n]))
	}

	// Wrap in WebSocket framing for DPI resistance.
	// Post-knock traffic now looks like WebSocket binary frames.
	ws, err := newWSConn(tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("websocket wrap: %w", err)
	}
	return b.maybeObfuscate(ws), nil
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
	// Capture the current channels under the lock so we are not racing with a
	// concurrent Close/Open swapping the fields.
	b.closeMu.Lock()
	recvChan := b.recvChan
	done := b.done
	b.closeMu.Unlock()

	// Receive loop for connection
	buf := make([]byte, 65536)
	for {
		// Idle read deadline: reap connections that go silent. WireGuard
		// persistent keepalive (25s) keeps healthy tunnels well within this,
		// so only dead/stalled peers (slowloris) trip it.
		ep.conn.SetReadDeadline(time.Now().Add(transportIdleTimeout))
		n, err := ep.conn.Read(buf)
		if err != nil {
			// Connection closed, idle-timed-out, or error
			b.connsMu.Lock()
			delete(b.remoteConns, ep.addr)
			b.connsMu.Unlock()
			return
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		// Deliver the packet, but never block forever and never send on a
		// channel after shutdown. done is closed by Close(); recvChan is never
		// closed, so the send can never panic.
		select {
		case <-done:
			return
		case recvChan <- recvPacket{data: data, endpoint: ep}:
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
	httpsBind   *HTTPSBind
	directBind  *DirectBind
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

// StartHTTPSListener starts listening for incoming HTTPS connections.
// Incoming connections go through knock validation, then authenticated
// connections are fed into the WireGuard receive channel.
func (b *HTTPSBind) StartListener(addr string, tlsConfig *tls.Config) error {
	ln, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	// Track the listener so Close() can shut it down and stop the accept loop.
	b.closeMu.Lock()
	if b.closed {
		b.closeMu.Unlock()
		ln.Close()
		return net.ErrClosed
	}
	b.listeners = append(b.listeners, ln)
	b.closeMu.Unlock()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				// Listener closed (by Close) or fatal accept error: stop.
				return
			}
			go b.handleIncoming(conn)
		}
	}()

	return nil
}

func (b *HTTPSBind) handleIncoming(c net.Conn) {
	// Defense in depth: a malformed knock from an untrusted peer must never
	// take down the daemon. Recover from any panic in knock parsing/validation
	// and just drop the connection.
	defer func() {
		if r := recover(); r != nil {
			c.Close()
		}
	}()

	// Read the full knock HTTP request using buffered reads.
	// A single Read may not return the complete HTTP request on slow/fragmented connections.
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, err := c.Read(tmp)
		if err != nil {
			c.Close()
			return
		}
		buf = append(buf, tmp[:n]...)
		// HTTP request ends with \r\n\r\n
		if bytes.Contains(buf, []byte("\r\n\r\n")) || len(buf) > 8192 {
			break
		}
	}
	c.SetReadDeadline(time.Time{})

	// Validate knock using the transport's knock validator
	peerKey := b.transport.ValidateKnock(buf)
	if peerKey == nil {
		// Not a valid knock — serve cover response and close
		cover := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 44\r\n\r\n<html><body>Nothing to see here.</body></html>"
		c.Write([]byte(cover))
		c.Close()
		return
	}

	// Valid knock — send WebSocket upgrade response (looks like a real WS handshake)
	wsResponse := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	c.Write([]byte(wsResponse))

	// Wrap in WebSocket framing — read the client's length mask first
	wsConn, err := newWSConnServer(c)
	if err != nil {
		c.Close()
		return
	}

	remoteAddr := c.RemoteAddr().String()

	ep := &httpsEndpoint{
		conn: b.maybeObfuscate(wsConn),
		addr: remoteAddr,
	}

	b.connsMu.Lock()
	b.remoteConns[remoteAddr] = ep
	b.connsMu.Unlock()

	b.receiveLoop(ep)
}

// Ensure interfaces are satisfied
var _ conn.Bind = (*HTTPSBind)(nil)
var _ conn.Bind = (*DirectBind)(nil)
var _ conn.Bind = (*HybridBind)(nil)
var _ conn.Endpoint = (*httpsEndpoint)(nil)
