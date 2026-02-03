package tunnel

import (
	"net"
	"net/netip"
	"time"
)

// Peer represents a WireGuard peer in the mesh
type Peer struct {
	// NodeID is the GHOSTWIRE node identifier
	NodeID string

	// PublicKey is the X25519 WireGuard public key
	PublicKey [32]byte

	// MeshIP is the peer's mesh IP address
	MeshIP netip.Addr

	// Endpoint is the peer's current UDP endpoint (may be nil)
	Endpoint *net.UDPAddr

	// AllowedIPs are the IP ranges allowed from this peer
	AllowedIPs []netip.Prefix

	// PersistentKeepalive interval in seconds (0 = disabled)
	PersistentKeepalive int

	// Roles are the peer's assigned roles
	Roles []string

	// LastHandshake is the time of the last successful handshake
	LastHandshake time.Time

	// BytesSent is the total bytes sent to this peer
	BytesSent uint64

	// BytesReceived is the total bytes received from this peer
	BytesReceived uint64
}

// PeerConfig holds configuration for adding a peer
type PeerConfig struct {
	NodeID              string
	PublicKey           [32]byte
	MeshIP              netip.Addr
	Endpoints           []string // host:port addresses
	PersistentKeepalive int
	Roles               []string
}

// NewPeer creates a new Peer from configuration
func NewPeer(cfg *PeerConfig) *Peer {
	p := &Peer{
		NodeID:              cfg.NodeID,
		PublicKey:           cfg.PublicKey,
		MeshIP:              cfg.MeshIP,
		PersistentKeepalive: cfg.PersistentKeepalive,
		Roles:               cfg.Roles,
		AllowedIPs:          []netip.Prefix{netip.PrefixFrom(cfg.MeshIP, 32)},
	}

	// Try to resolve first endpoint
	if len(cfg.Endpoints) > 0 {
		if addr, err := net.ResolveUDPAddr("udp", cfg.Endpoints[0]); err == nil {
			p.Endpoint = addr
		}
	}

	return p
}

// IsConnected returns true if we have a recent handshake
func (p *Peer) IsConnected() bool {
	// Consider connected if handshake within last 3 minutes
	return time.Since(p.LastHandshake) < 3*time.Minute
}

// HasRole checks if the peer has a specific role
func (p *Peer) HasRole(role string) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// IsRelay returns true if the peer has the relay role
func (p *Peer) IsRelay() bool {
	return p.HasRole("relay")
}

// IsAdmin returns true if the peer has the admin role
func (p *Peer) IsAdmin() bool {
	return p.HasRole("admin")
}

// PeerStatus represents the current status of a peer
type PeerStatus struct {
	NodeID        string
	PublicKey     [32]byte
	MeshIP        netip.Addr
	Endpoint      string
	Connected     bool
	LastHandshake time.Time
	BytesSent     uint64
	BytesReceived uint64
}

// Status returns the current status of the peer
func (p *Peer) Status() *PeerStatus {
	status := &PeerStatus{
		NodeID:        p.NodeID,
		PublicKey:     p.PublicKey,
		MeshIP:        p.MeshIP,
		Connected:     p.IsConnected(),
		LastHandshake: p.LastHandshake,
		BytesSent:     p.BytesSent,
		BytesReceived: p.BytesReceived,
	}

	if p.Endpoint != nil {
		status.Endpoint = p.Endpoint.String()
	}

	return status
}
