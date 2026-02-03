// Package doh implements a DNS-over-HTTPS tunnel transport.
// Data is encoded in DNS queries and responses, appearing as legitimate DNS traffic.
// This is useful when only DNS traffic is allowed through a firewall.
package doh

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/ghostwire/ghostwire/internal/transport"
)

const (
	// Name is the transport identifier
	Name = "dns-tunnel"

	// MaxLabelLength is the max DNS label length
	MaxLabelLength = 63

	// MaxNameLength is the max DNS name length
	MaxNameLength = 253

	// ChunkSize is the data size per DNS query (conservative for TXT)
	ChunkSize = 180
)

// Config holds DNS tunnel configuration
type Config struct {
	// Domain is the base domain for tunneling (e.g., "t.example.com")
	Domain string

	// DoHServer is the DNS-over-HTTPS server URL
	DoHServer string

	// MeshSecret for authentication
	MeshSecret []byte

	// LocalPublicKey for identification
	LocalPublicKey []byte

	// PollInterval is how often to poll for data
	PollInterval time.Duration

	// Timeout for DNS queries
	Timeout time.Duration
}

// DefaultConfig returns default DNS tunnel configuration
func DefaultConfig() *Config {
	return &Config{
		DoHServer:    "https://cloudflare-dns.com/dns-query",
		PollInterval: 100 * time.Millisecond,
		Timeout:      5 * time.Second,
	}
}

// Transport implements the DNS tunnel transport
type Transport struct {
	cfg        *Config
	httpClient *http.Client
	encoder    *base32.Encoding
	mu         sync.Mutex
	closed     bool
}

// New creates a new DNS tunnel transport
func New(cfg *Config) (*Transport, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if cfg.Domain == "" {
		return nil, fmt.Errorf("tunnel domain required")
	}

	// Use base32 without padding for DNS-safe encoding
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)

	httpClient := &http.Client{
		Timeout: cfg.Timeout,
	}

	return &Transport{
		cfg:        cfg,
		httpClient: httpClient,
		encoder:    encoder,
	}, nil
}

// Name returns the transport identifier
func (t *Transport) Name() string {
	return Name
}

// Dial establishes a DNS tunnel connection
func (t *Transport) Dial(ctx context.Context, addr string) (net.Conn, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, fmt.Errorf("transport closed")
	}
	t.mu.Unlock()

	// Generate session ID
	sessionID := generateSessionID()

	// Create DNS tunnel connection
	dc := &dnsConn{
		transport: t,
		sessionID: sessionID,
		sendCh:    make(chan []byte, 100),
		recvCh:    make(chan []byte, 100),
		closeCh:   make(chan struct{}),
		localAddr: &dnsAddr{network: "dns", addr: "local"},
		remoteAddr: &dnsAddr{network: "dns", addr: t.cfg.Domain},
	}

	// Start sender and receiver goroutines
	go dc.sendLoop(ctx)
	go dc.recvLoop(ctx)

	// Perform handshake
	if err := dc.handshake(ctx); err != nil {
		dc.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	return transport.NewConnWrapper(dc, Name, t.cfg.LocalPublicKey), nil
}

// Listen creates a DNS tunnel listener (requires authoritative DNS server)
func (t *Transport) Listen(ctx context.Context, addr string) (transport.Listener, error) {
	// DNS tunnel listening requires running an authoritative DNS server
	// This is more complex and typically done out-of-band
	return nil, fmt.Errorf("DNS tunnel listening requires authoritative DNS server setup")
}

// Close shuts down the transport
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return nil
}

// sendQuery sends a DNS query and returns the response
func (t *Transport) sendQuery(ctx context.Context, qname string, qtype uint16) (*dns.Msg, error) {
	// Build DNS query
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(qname), qtype)
	msg.RecursionDesired = true

	// Serialize to wire format
	wireData, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack query: %w", err)
	}

	// Send via DoH
	req, err := http.NewRequestWithContext(ctx, "POST", t.cfg.DoHServer, bytes.NewReader(wireData))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH error: %d", resp.StatusCode)
	}

	// Read response
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// Parse DNS response
	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(respData); err != nil {
		return nil, fmt.Errorf("unpack response: %w", err)
	}

	return respMsg, nil
}

// dnsConn implements net.Conn over DNS
type dnsConn struct {
	transport  *Transport
	sessionID  string
	sendCh     chan []byte
	recvCh     chan []byte
	closeCh    chan struct{}
	localAddr  net.Addr
	remoteAddr net.Addr
	readBuf    []byte
	mu         sync.Mutex
	seqSend    uint32
	seqRecv    uint32
}

func (dc *dnsConn) handshake(ctx context.Context) error {
	// Send handshake query
	qname := fmt.Sprintf("h.%s.%s", dc.sessionID, dc.transport.cfg.Domain)
	resp, err := dc.transport.sendQuery(ctx, qname, dns.TypeTXT)
	if err != nil {
		return err
	}

	// Check for valid response
	if resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("handshake failed: rcode %d", resp.Rcode)
	}

	return nil
}

func (dc *dnsConn) sendLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-dc.closeCh:
			return
		case data := <-dc.sendCh:
			dc.sendData(ctx, data)
		}
	}
}

func (dc *dnsConn) sendData(ctx context.Context, data []byte) error {
	// Encode data in DNS query labels
	encoded := dc.transport.encoder.EncodeToString(data)

	// Add sequence number
	dc.mu.Lock()
	seq := dc.seqSend
	dc.seqSend++
	dc.mu.Unlock()

	// Build query name: <seq>.<encoded_data>.<session>.<domain>
	// Split encoded data into valid DNS labels
	labels := splitIntoLabels(encoded, MaxLabelLength)
	qname := fmt.Sprintf("%d.%s.%s.%s",
		seq,
		strings.Join(labels, "."),
		dc.sessionID,
		dc.transport.cfg.Domain,
	)

	// Truncate if too long
	if len(qname) > MaxNameLength {
		qname = qname[:MaxNameLength]
	}

	_, err := dc.transport.sendQuery(ctx, qname, dns.TypeA)
	return err
}

func (dc *dnsConn) recvLoop(ctx context.Context) {
	ticker := time.NewTicker(dc.transport.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-dc.closeCh:
			return
		case <-ticker.C:
			data, err := dc.pollData(ctx)
			if err != nil {
				continue
			}
			if len(data) > 0 {
				select {
				case dc.recvCh <- data:
				default:
					// Channel full, drop
				}
			}
		}
	}
}

func (dc *dnsConn) pollData(ctx context.Context) ([]byte, error) {
	dc.mu.Lock()
	seq := dc.seqRecv
	dc.mu.Unlock()

	// Query for pending data
	qname := fmt.Sprintf("p.%d.%s.%s", seq, dc.sessionID, dc.transport.cfg.Domain)
	resp, err := dc.transport.sendQuery(ctx, qname, dns.TypeTXT)
	if err != nil {
		return nil, err
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, nil
	}

	// Extract data from TXT records
	var data []byte
	for _, ans := range resp.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			for _, s := range txt.Txt {
				decoded, err := dc.transport.encoder.DecodeString(s)
				if err == nil {
					data = append(data, decoded...)
				}
			}
		}
	}

	if len(data) > 0 {
		dc.mu.Lock()
		dc.seqRecv++
		dc.mu.Unlock()
	}

	return data, nil
}

func (dc *dnsConn) Read(b []byte) (int, error) {
	// Return buffered data first
	if len(dc.readBuf) > 0 {
		n := copy(b, dc.readBuf)
		dc.readBuf = dc.readBuf[n:]
		return n, nil
	}

	// Wait for new data
	select {
	case data := <-dc.recvCh:
		n := copy(b, data)
		if n < len(data) {
			dc.readBuf = data[n:]
		}
		return n, nil
	case <-dc.closeCh:
		return 0, io.EOF
	}
}

func (dc *dnsConn) Write(b []byte) (int, error) {
	select {
	case <-dc.closeCh:
		return 0, io.ErrClosedPipe
	default:
	}

	// Send data in chunks
	total := 0
	for i := 0; i < len(b); i += ChunkSize {
		end := i + ChunkSize
		if end > len(b) {
			end = len(b)
		}

		select {
		case dc.sendCh <- b[i:end]:
			total += end - i
		case <-dc.closeCh:
			return total, io.ErrClosedPipe
		}
	}

	return total, nil
}

func (dc *dnsConn) Close() error {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	select {
	case <-dc.closeCh:
		return nil
	default:
		close(dc.closeCh)
	}
	return nil
}

func (dc *dnsConn) LocalAddr() net.Addr {
	return dc.localAddr
}

func (dc *dnsConn) RemoteAddr() net.Addr {
	return dc.remoteAddr
}

func (dc *dnsConn) SetDeadline(t time.Time) error {
	return nil // DNS tunnel doesn't support deadlines directly
}

func (dc *dnsConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (dc *dnsConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// dnsAddr implements net.Addr for DNS tunnels
type dnsAddr struct {
	network string
	addr    string
}

func (a *dnsAddr) Network() string { return a.network }
func (a *dnsAddr) String() string  { return a.addr }

// splitIntoLabels splits a string into DNS-valid labels
func splitIntoLabels(s string, maxLen int) []string {
	var labels []string
	for len(s) > 0 {
		end := maxLen
		if end > len(s) {
			end = len(s)
		}
		labels = append(labels, strings.ToLower(s[:end]))
		s = s[end:]
	}
	return labels
}

// generateSessionID creates a random session identifier
func generateSessionID() string {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(time.Now().UnixNano()))
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf[:6])
}
