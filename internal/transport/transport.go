// Package transport defines the pluggable transport interface for GHOSTWIRE.
// Transports provide obfuscation layers that make VPN traffic indistinguishable
// from normal network traffic.
package transport

import (
	"context"
	"io"
	"net"
	"time"
)

// Transport defines the interface for obfuscation transports.
// All transports wrap raw network connections to disguise VPN traffic.
type Transport interface {
	// Name returns the transport identifier (e.g., "https-mimic", "quic", "direct")
	Name() string

	// Dial establishes an outbound obfuscated connection to a peer.
	// The returned connection can be used to send/receive WireGuard packets.
	Dial(ctx context.Context, addr string) (net.Conn, error)

	// Listen creates a listener for incoming obfuscated connections.
	// Returns a Listener that accepts connections after transport-specific handshake.
	Listen(ctx context.Context, addr string) (Listener, error)

	// Close shuts down the transport and releases resources.
	Close() error
}

// Listener wraps net.Listener with transport-specific functionality.
type Listener interface {
	// Accept waits for and returns the next obfuscated connection.
	Accept() (net.Conn, error)

	// Close stops listening.
	Close() error

	// Addr returns the listener's network address.
	Addr() net.Addr
}

// Conn extends net.Conn with transport-specific functionality.
type Conn interface {
	net.Conn

	// Transport returns the name of the transport used for this connection.
	Transport() string

	// PeerPublicKey returns the peer's WireGuard public key (if authenticated).
	// Returns nil if the connection is not yet authenticated.
	PeerPublicKey() []byte
}

// PacketConn is used for transports that support packet-oriented communication.
// This is more efficient for WireGuard which is itself packet-based.
type PacketConn interface {
	// ReadPacket reads a single WireGuard packet.
	ReadPacket() ([]byte, error)

	// WritePacket writes a single WireGuard packet.
	WritePacket(data []byte) error

	// Close closes the connection.
	Close() error

	// LocalAddr returns the local network address.
	LocalAddr() net.Addr

	// RemoteAddr returns the remote network address.
	RemoteAddr() net.Addr
}

// Authenticator handles transport-level authentication (e.g., knock sequences).
type Authenticator interface {
	// Authenticate performs transport-specific authentication.
	// Returns the authenticated peer's public key on success.
	Authenticate(conn net.Conn, isServer bool) (peerPubKey []byte, err error)
}

// Config holds common transport configuration.
type Config struct {
	// ListenAddr is the address to listen on (for server mode)
	ListenAddr string

	// MeshSecret is the shared secret for knock authentication
	MeshSecret []byte

	// LocalPublicKey is this node's WireGuard public key
	LocalPublicKey []byte

	// LocalPrivateKey is this node's WireGuard private key (for signing)
	LocalPrivateKey []byte
}

// ConnWrapper wraps a net.Conn with additional transport metadata.
type ConnWrapper struct {
	net.Conn
	transportName string
	peerPubKey    []byte
}

// NewConnWrapper creates a wrapped connection with transport metadata.
func NewConnWrapper(conn net.Conn, transportName string, peerPubKey []byte) *ConnWrapper {
	return &ConnWrapper{
		Conn:          conn,
		transportName: transportName,
		peerPubKey:    peerPubKey,
	}
}

// Transport returns the name of the transport used for this connection.
func (c *ConnWrapper) Transport() string {
	return c.transportName
}

// PeerPublicKey returns the peer's WireGuard public key.
func (c *ConnWrapper) PeerPublicKey() []byte {
	return c.peerPubKey
}

// Stats holds transport connection statistics.
type Stats struct {
	BytesSent     uint64
	BytesReceived uint64
	PacketsSent   uint64
	PacketsRecv   uint64
	Errors        uint64
}

// StatsCollector collects transport statistics.
type StatsCollector interface {
	// Stats returns current statistics.
	Stats() Stats

	// ResetStats resets all statistics to zero.
	ResetStats()
}

// Dialer is a function type for creating outbound connections.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// NetDialer returns a standard net.Dialer as a Dialer function.
func NetDialer(timeout int) Dialer {
	d := &net.Dialer{}
	if timeout > 0 {
		d.Timeout = time.Duration(timeout) * time.Second
	}
	return d.DialContext
}

// BufferedConn wraps a connection with read buffering for packet framing.
type BufferedConn struct {
	net.Conn
	reader io.Reader
}

// NewBufferedConn creates a new buffered connection.
func NewBufferedConn(conn net.Conn, bufSize int) *BufferedConn {
	return &BufferedConn{
		Conn:   conn,
		reader: io.LimitReader(conn, int64(bufSize)),
	}
}

// Read reads from the buffered connection.
func (c *BufferedConn) Read(b []byte) (int, error) {
	return c.Conn.Read(b)
}
