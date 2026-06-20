package https

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/ghostwire/ghostwire/internal/transport"
)

const (
	// transientAcceptBackoff is the pause after a transient Accept error so a
	// persistent failure cannot spin a CPU core.
	transientAcceptBackoff = 10 * time.Millisecond

	// knockReadTimeout bounds how long we wait for a client's initial knock
	// request before giving up (slowloris protection).
	knockReadTimeout = 10 * time.Second
)

// Transport implements the HTTPS-mimic obfuscation transport
type Transport struct {
	cfg            *Config
	knockGenerator *KnockGenerator
	knockValidator *KnockValidator
	tlsConfig      *tls.Config
	server         *http.Server
	listener       net.Listener
	mu             sync.Mutex
	closed         bool
	connections    map[string]*TunnelConn // peerPubKey -> conn
}

// New creates a new HTTPS-mimic transport
func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	t := &Transport{
		cfg:            cfg,
		knockGenerator: NewKnockGenerator(cfg.MeshSecret, cfg.KnockWindow),
		knockValidator: NewKnockValidator(cfg.MeshSecret, cfg.KnockWindow),
		connections:    make(map[string]*TunnelConn),
	}

	// Setup TLS config
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load TLS certificate: %w", err)
		}
		t.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
			MinVersion:   tls.VersionTLS13,
		}
	}

	return t, nil
}

// Name returns the transport identifier
func (t *Transport) Name() string {
	return Name
}

// ServerName returns the configured TLS server name
func (t *Transport) ServerName() string {
	return t.cfg.ServerName
}

// GenerateKnock creates a knock sequence using the local public key
func (t *Transport) GenerateKnock() *KnockSequence {
	return t.knockGenerator.Generate(t.cfg.LocalPublicKey)
}

// ValidateKnock validates a raw HTTP request as a knock sequence.
// Returns the peer's public key if valid, nil otherwise.
func (t *Transport) ValidateKnock(data []byte) []byte {
	req, err := parseHTTPRequest(data)
	if err != nil {
		return nil
	}
	return t.knockValidator.Validate(req)
}

// AddPeer adds a peer's public key for knock validation
func (t *Transport) AddPeer(pubKey []byte) {
	t.knockValidator.AddKnownClient(pubKey)
}

// RemovePeer removes a peer's public key
func (t *Transport) RemovePeer(pubKey []byte) {
	t.knockValidator.RemoveKnownClient(pubKey)
}

// Dial establishes an outbound obfuscated connection
func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, ErrTransportClosed
	}
	t.mu.Unlock()

	// Create TLS connection with browser fingerprint
	// Note: For full browser mimicry, use utls here
	dialer := &net.Dialer{}
	tcpConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial tcp: %w", err)
	}

	tlsConfig := &tls.Config{
		ServerName:         t.cfg.ServerName,
		NextProtos:         []string{"h2", "http/1.1"},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Peer authentication is via WireGuard Noise + knock, not TLS PKI
	}

	tlsConn := tls.Client(tcpConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	// Perform knock authentication
	knock := t.knockGenerator.Generate(t.cfg.LocalPublicKey)
	if err := t.performKnock(tlsConn, knock); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("knock: %w", err)
	}

	// Create tunnel connection
	tunnelConn := NewTunnelConn(tlsConn, t.cfg.LocalPublicKey, nil)

	return transport.NewConnWrapper(tunnelConn, Name, nil), nil
}

// performKnock sends the knock sequence and waits for acknowledgment
func (t *Transport) performKnock(conn net.Conn, knock *KnockSequence) error {
	// Build HTTP request
	req := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\n", knock.Path, t.cfg.ServerName)
	for key, value := range knock.Headers {
		req += fmt.Sprintf("%s: %s\r\n", key, value)
	}
	req += fmt.Sprintf("Content-Length: %d\r\n\r\n", len(knock.Body))

	// Send request
	if _, err := conn.Write([]byte(req)); err != nil {
		return err
	}
	if _, err := conn.Write(knock.Body); err != nil {
		return err
	}

	// Read response (simplified - a full implementation would parse HTTP properly)
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}

	// Check for success response
	response := string(buf[:n])
	if len(response) < 12 || response[9:12] != "200" {
		return ErrKnockFailed
	}

	return nil
}

// Listen creates a listener for incoming obfuscated connections
func (t *Transport) Listen(ctx context.Context, addr string) (transport.Listener, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil, ErrTransportClosed
	}

	if addr == "" {
		addr = t.cfg.ListenAddr
	}

	// Create TCP listener
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen tcp: %w", err)
	}

	// Wrap with TLS if configured
	if t.tlsConfig != nil {
		t.listener = tls.NewListener(tcpListener, t.tlsConfig)
	} else {
		t.listener = tcpListener
	}

	return &httpsListener{
		transport: t,
		listener:  t.listener,
		tunnelCh:  make(chan net.Conn, 10),
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

	if t.server != nil {
		t.server.Close()
	}

	// Close all active connections
	for _, conn := range t.connections {
		conn.Close()
	}

	return nil
}

// httpsListener implements transport.Listener
type httpsListener struct {
	transport *Transport
	listener  net.Listener
	tunnelCh  chan net.Conn
	mu        sync.Mutex
	closed    bool
	accepting bool
}

func (l *httpsListener) Accept() (net.Conn, error) {
	// Start a goroutine to accept raw connections and handle knock auth
	l.mu.Lock()
	if !l.accepting {
		l.accepting = true
		go l.acceptLoop()
	}
	l.mu.Unlock()

	// Block until an authenticated tunnel connection is ready
	tunnelConn, ok := <-l.tunnelCh
	if !ok {
		return nil, net.ErrClosed
	}
	return tunnelConn, nil
}

func (l *httpsListener) acceptLoop() {
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			l.mu.Lock()
			closed := l.closed
			l.mu.Unlock()
			if closed {
				close(l.tunnelCh)
				return
			}
			// Transient accept error — back off so we don't spin a CPU core.
			time.Sleep(transientAcceptBackoff)
			continue
		}
		go l.handleConnection(conn)
	}
}

func (l *httpsListener) handleConnection(conn net.Conn) {
	// Read initial request to check for knock. Bound the read with a deadline
	// so an idle/slowloris client cannot pin a goroutine + connection forever.
	buf := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(knockReadTimeout))
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{}) // clear deadline for the tunnel lifetime

	// Parse as HTTP request (simplified)
	req, err := parseHTTPRequest(buf[:n])
	if err != nil {
		// Not a valid HTTP request - serve cover site or close
		l.serveCover(conn, buf[:n])
		return
	}

	// Check for valid knock
	peerPubKey := l.transport.knockValidator.Validate(req)
	if peerPubKey == nil {
		// Invalid knock - serve cover site
		l.serveCoverResponse(conn)
		conn.Close()
		return
	}

	// Valid knock - send success response and transition to tunnel mode
	response := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 29\r\n\r\n{\"status\":\"ok\",\"tunnel\":true}"
	conn.Write([]byte(response))

	// Create tunnel connection
	tunnelConn := NewTunnelConn(conn, l.transport.cfg.LocalPublicKey, peerPubKey)

	// Send to channel for Accept()
	select {
	case l.tunnelCh <- transport.NewConnWrapper(tunnelConn, Name, peerPubKey):
	default:
		// Channel full - close connection
		tunnelConn.Close()
	}
}

func (l *httpsListener) serveCover(conn net.Conn, initialData []byte) {
	// Serve a simple cover response
	l.serveCoverResponse(conn)
	conn.Close()
}

func (l *httpsListener) serveCoverResponse(conn net.Conn) {
	response := `HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 137

<!DOCTYPE html>
<html><head><title>Welcome</title></head>
<body><h1>Welcome</h1><p>This server is functioning normally.</p></body></html>`
	conn.Write([]byte(response))
}

func (l *httpsListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	return l.listener.Close()
}

func (l *httpsListener) Addr() net.Addr {
	return l.listener.Addr()
}

// parseHTTPRequest is a simplified HTTP request parser
func parseHTTPRequest(data []byte) (*http.Request, error) {
	// This is a simplified parser - a full implementation would use bufio.Reader
	// For now, create a minimal request object
	req := &http.Request{
		Header: make(http.Header),
	}

	// Parse first line
	lines := splitLines(data)
	if len(lines) < 1 {
		return nil, fmt.Errorf("invalid request")
	}

	// Parse request line
	parts := splitSpaces(lines[0])
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line")
	}
	req.Method = string(parts[0])

	// Parse URL
	urlStr := string(parts[1])
	parsedURL, _ := url.Parse(urlStr)
	req.URL = parsedURL

	// Parse headers
	for i := 1; i < len(lines); i++ {
		if len(lines[i]) == 0 {
			break
		}
		colonIdx := -1
		for j, b := range lines[i] {
			if b == ':' {
				colonIdx = j
				break
			}
		}
		if colonIdx > 0 {
			key := string(lines[i][:colonIdx])
			value := string(lines[i][colonIdx+1:])
			// Trim leading space from value
			if len(value) > 0 && value[0] == ' ' {
				value = value[1:]
			}
			req.Header.Set(key, value)
		}
	}

	return req, nil
}

func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' {
			end := i
			if end > start && data[end-1] == '\r' {
				end--
			}
			lines = append(lines, data[start:end])
			start = i + 1
		}
	}
	if start < len(data) {
		lines = append(lines, data[start:])
	}
	return lines
}

func splitSpaces(data []byte) [][]byte {
	var parts [][]byte
	start := 0
	for i := 0; i < len(data); i++ {
		if data[i] == ' ' {
			if i > start {
				parts = append(parts, data[start:i])
			}
			start = i + 1
		}
	}
	if start < len(data) {
		parts = append(parts, data[start:])
	}
	return parts
}
