// Package tunnel provides WireGuard tunnel management for GHOSTWIRE.
package tunnel

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/ghostwire/ghostwire/internal/config"
)

// Device wraps a WireGuard device with GHOSTWIRE-specific functionality
type Device struct {
	wgDevice   *device.Device
	tunDevice  tun.Device
	filterTUN  *filteredTUN // wraps tunDevice; applies the policy packet filter
	wgBind     conn.Bind    // retained for listener management
	privateKey [32]byte
	publicKey  [32]byte
	meshIP     netip.Addr
	meshPrefix netip.Prefix

	peers   map[string]*Peer // nodeID -> peer
	peersMu sync.RWMutex

	logger *device.Logger
	closed bool
	mu     sync.Mutex
}

// Config holds configuration for creating a new tunnel device
type Config struct {
	// Interface name (e.g., "gw0")
	InterfaceName string

	// WireGuard private key (X25519)
	PrivateKey [32]byte

	// Mesh IP address for this node
	MeshIP netip.Addr

	// Mesh subnet
	MeshPrefix netip.Prefix

	// Listen port for direct WireGuard (0 = auto)
	ListenPort int

	// MTU for the tunnel interface
	MTU int

	// Log level (0 = silent, 1 = error, 2 = info, 3 = debug)
	LogLevel int

	// Transport mode: "direct", "https", "hybrid"
	TransportMode string

	// HTTPS transport config (required if TransportMode is "https" or "hybrid")
	HTTPSConfig *BindConfig
}

// SetPacketFilter attaches a PacketFilter (e.g. the policy enforcer) to the
// data path. It may be called after the device is up; pass nil to disable
// filtering. Packets read from the TUN are checked with direction "egress" and
// packets written to the TUN with direction "ingress".
func (d *Device) SetPacketFilter(filter PacketFilter) {
	d.filterTUN.SetFilter(filter)
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		InterfaceName: "gw0",
		ListenPort:    0, // Auto-assign
		MTU:           1420,
		LogLevel:      1,
	}
}

// New creates a new GHOSTWIRE tunnel device
func New(cfg *Config) (*Device, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// Validate config
	if !cfg.MeshIP.IsValid() {
		return nil, fmt.Errorf("invalid mesh IP address")
	}
	if !cfg.MeshPrefix.IsValid() {
		return nil, fmt.Errorf("invalid mesh prefix")
	}

	// Create logger
	logger := device.NewLogger(cfg.LogLevel, fmt.Sprintf("(%s) ", cfg.InterfaceName))

	// macOS requires the TUN device be named "utun" or "utunN"; a Linux-style
	// name like "gw0" is rejected. Pass "utun" so the kernel assigns the next
	// free utun unit (the real name is read back from tunDev.Name() below).
	ifName := cfg.InterfaceName
	if runtime.GOOS == "darwin" && !strings.HasPrefix(ifName, "utun") {
		ifName = "utun"
	}

	// Create TUN device
	tunDev, err := tun.CreateTUN(ifName, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("create TUN device: %w", err)
	}

	// Get actual interface name (may differ on some platforms)
	actualName, err := tunDev.Name()
	if err != nil {
		tunDev.Close()
		return nil, fmt.Errorf("get TUN name: %w", err)
	}
	logger.Verbosef("Created TUN device: %s", actualName)

	// Create bind based on transport mode
	var wgBind conn.Bind
	switch cfg.TransportMode {
	case "https":
		if cfg.HTTPSConfig == nil {
			tunDev.Close()
			return nil, fmt.Errorf("HTTPS config required for https transport mode")
		}
		httpsBind, err := NewHTTPSBind(cfg.HTTPSConfig)
		if err != nil {
			tunDev.Close()
			return nil, fmt.Errorf("create HTTPS bind: %w", err)
		}
		wgBind = httpsBind
	case "hybrid":
		hybridBind, err := NewHybridBind(cfg.HTTPSConfig, true)
		if err != nil {
			tunDev.Close()
			return nil, fmt.Errorf("create hybrid bind: %w", err)
		}
		wgBind = hybridBind
	default: // "direct" or empty
		wgBind = conn.NewDefaultBind()
	}

	// Wrap the TUN so the policy enforcer can filter packets in both
	// directions. With no filter attached this is a transparent pass-through.
	filterTUN := newFilteredTUN(tunDev)

	// Create WireGuard device
	wgDev := device.NewDevice(filterTUN, wgBind, logger)

	// Configure private key
	if err := wgDev.IpcSet(fmt.Sprintf("private_key=%s\n", keyToHex(cfg.PrivateKey[:]))); err != nil {
		tunDev.Close()
		wgDev.Close()
		return nil, fmt.Errorf("set private key: %w", err)
	}

	// Configure listen port if specified
	if cfg.ListenPort > 0 {
		if err := wgDev.IpcSet(fmt.Sprintf("listen_port=%d\n", cfg.ListenPort)); err != nil {
			tunDev.Close()
			wgDev.Close()
			return nil, fmt.Errorf("set listen port: %w", err)
		}
	}

	// Derive public key
	var publicKey [32]byte
	copy(publicKey[:], derivePublicKey(cfg.PrivateKey[:]))

	d := &Device{
		wgDevice:   wgDev,
		tunDevice:  tunDev,
		filterTUN:  filterTUN,
		wgBind:     wgBind,
		privateKey: cfg.PrivateKey,
		publicKey:  publicKey,
		meshIP:     cfg.MeshIP,
		meshPrefix: cfg.MeshPrefix,
		peers:      make(map[string]*Peer),
		logger:     logger,
	}

	return d, nil
}

// NewFromConfig creates a Device from a MeshConfig
func NewFromConfig(meshCfg *config.MeshConfig, privateKey [32]byte, meshSecret []byte) (*Device, error) {
	// Parse mesh IP
	meshIP, err := netip.ParseAddr(meshCfg.AssignedIP)
	if err != nil {
		return nil, fmt.Errorf("parse mesh IP: %w", err)
	}

	// Parse mesh subnet
	meshPrefix, err := netip.ParsePrefix(meshCfg.MeshSubnet)
	if err != nil {
		return nil, fmt.Errorf("parse mesh subnet: %w", err)
	}

	cfg := &Config{
		InterfaceName: "gw0",
		PrivateKey:    privateKey,
		MeshIP:        meshIP,
		MeshPrefix:    meshPrefix,
		MTU:           1420,
		LogLevel:      1,
	}

	// Derive local public key for transport authentication (knock)
	var localPubKey [32]byte
	curve25519.ScalarBaseMult(&localPubKey, &privateKey)

	// Configure transport based on mesh config
	switch meshCfg.Transport.Active {
	case "https-mimic", "https":
		cfg.TransportMode = "https"
		cfg.HTTPSConfig = &BindConfig{
			ServerName:     meshCfg.Transport.HTTPS.ServerName,
			MeshSecret:     meshSecret,
			ListenAddr:     meshCfg.Transport.HTTPS.ListenAddr,
			LocalPublicKey: localPubKey[:],
			Obfuscate:      meshCfg.Transport.HTTPS.Obfuscate,
		}
	case "hybrid":
		cfg.TransportMode = "hybrid"
		cfg.HTTPSConfig = &BindConfig{
			ServerName:     meshCfg.Transport.HTTPS.ServerName,
			MeshSecret:     meshSecret,
			ListenAddr:     meshCfg.Transport.HTTPS.ListenAddr,
			LocalPublicKey: localPubKey[:],
			Obfuscate:      meshCfg.Transport.HTTPS.Obfuscate,
		}
	case "direct", "":
		cfg.TransportMode = "direct"
		if meshCfg.Transport.Direct.ListenPort > 0 {
			cfg.ListenPort = meshCfg.Transport.Direct.ListenPort
		}
	}

	return New(cfg)
}

// Up brings the tunnel interface up and configures routes
func (d *Device) Up() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return fmt.Errorf("device is closed")
	}

	// Bring up the device
	d.wgDevice.Up()

	// Configure IP address and routes (platform-specific)
	if err := d.configureInterface(); err != nil {
		return fmt.Errorf("configure interface: %w", err)
	}

	d.logger.Verbosef("Device is up with IP %s", d.meshIP)
	return nil
}

// Down brings the tunnel interface down
func (d *Device) Down() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}

	d.wgDevice.Down()
	d.logger.Verbosef("Device is down")
	return nil
}

// Close shuts down the tunnel device
func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return nil
	}
	d.closed = true

	// Close WireGuard device (also closes TUN)
	d.wgDevice.Close()

	// Wipe private key
	for i := range d.privateKey {
		d.privateKey[i] = 0
	}

	d.logger.Verbosef("Device closed")
	return nil
}

// PublicKey returns the device's WireGuard public key
func (d *Device) PublicKey() [32]byte {
	return d.publicKey
}

// MeshIP returns the device's mesh IP address
func (d *Device) MeshIP() netip.Addr {
	return d.meshIP
}

// InterfaceName returns the TUN interface name
func (d *Device) InterfaceName() (string, error) {
	return d.tunDevice.Name()
}

// AddPeer adds a peer to the WireGuard device
func (d *Device) AddPeer(peer *Peer) error {
	d.peersMu.Lock()
	defer d.peersMu.Unlock()

	if _, exists := d.peers[peer.NodeID]; exists {
		return fmt.Errorf("peer %s already exists", peer.NodeID)
	}

	// Configure peer in WireGuard
	ipcConfig := fmt.Sprintf(
		"public_key=%s\nallowed_ip=%s/32\n",
		keyToHex(peer.PublicKey[:]),
		peer.MeshIP,
	)

	// Add endpoint if available
	if peer.Endpoint != nil {
		ipcConfig += fmt.Sprintf("endpoint=%s\n", peer.Endpoint.String())
	}

	// Add persistent keepalive
	if peer.PersistentKeepalive > 0 {
		ipcConfig += fmt.Sprintf("persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
	}

	if err := d.wgDevice.IpcSet(ipcConfig); err != nil {
		return fmt.Errorf("configure peer: %w", err)
	}

	d.peers[peer.NodeID] = peer
	d.logger.Verbosef("Added peer %s (%s)", peer.NodeID, peer.MeshIP)
	return nil
}

// RemovePeer removes a peer from the WireGuard device
func (d *Device) RemovePeer(nodeID string) error {
	d.peersMu.Lock()
	defer d.peersMu.Unlock()

	peer, exists := d.peers[nodeID]
	if !exists {
		return fmt.Errorf("peer %s not found", nodeID)
	}

	// Remove peer from WireGuard
	ipcConfig := fmt.Sprintf(
		"public_key=%s\nremove=true\n",
		keyToHex(peer.PublicKey[:]),
	)

	if err := d.wgDevice.IpcSet(ipcConfig); err != nil {
		return fmt.Errorf("remove peer: %w", err)
	}

	delete(d.peers, nodeID)
	d.logger.Verbosef("Removed peer %s", nodeID)
	return nil
}

// UpdatePeerEndpoint updates a peer's endpoint
func (d *Device) UpdatePeerEndpoint(nodeID string, endpoint *net.UDPAddr) error {
	d.peersMu.Lock()
	defer d.peersMu.Unlock()

	peer, exists := d.peers[nodeID]
	if !exists {
		return fmt.Errorf("peer %s not found", nodeID)
	}

	ipcConfig := fmt.Sprintf(
		"public_key=%s\nendpoint=%s\n",
		keyToHex(peer.PublicKey[:]),
		endpoint.String(),
	)

	if err := d.wgDevice.IpcSet(ipcConfig); err != nil {
		return fmt.Errorf("update peer endpoint: %w", err)
	}

	peer.Endpoint = endpoint
	d.logger.Verbosef("Updated peer %s endpoint to %s", nodeID, endpoint)
	return nil
}

// GetPeer returns a peer by node ID
func (d *Device) GetPeer(nodeID string) (*Peer, bool) {
	d.peersMu.RLock()
	defer d.peersMu.RUnlock()
	peer, exists := d.peers[nodeID]
	return peer, exists
}

// ListPeers returns all configured peers
func (d *Device) ListPeers() []*Peer {
	d.peersMu.RLock()
	defer d.peersMu.RUnlock()

	peers := make([]*Peer, 0, len(d.peers))
	for _, p := range d.peers {
		peers = append(peers, p)
	}
	return peers
}

// GetStats returns device statistics
func (d *Device) GetStats() (*Stats, error) {
	// Query WireGuard for stats via IPC
	// This is a simplified version; full implementation would parse IPC output

	stats := &Stats{
		InterfaceName: "",
		PublicKey:     d.publicKey,
		MeshIP:        d.meshIP,
		PeerCount:     len(d.peers),
	}

	if name, err := d.tunDevice.Name(); err == nil {
		stats.InterfaceName = name
	}

	return stats, nil
}

// Stats holds device statistics
type Stats struct {
	InterfaceName string
	PublicKey     [32]byte
	MeshIP        netip.Addr
	PeerCount     int
	BytesSent     uint64
	BytesReceived uint64
}

// RegisterKnockPeer registers a peer's public key with the HTTPS transport's
// knock validator so the peer can authenticate incoming connections.
func (d *Device) RegisterKnockPeer(pubKey []byte) {
	if httpsBind, ok := d.wgBind.(*HTTPSBind); ok && httpsBind.transport != nil {
		httpsBind.transport.AddPeer(pubKey)
	}
	if hybridBind, ok := d.wgBind.(*HybridBind); ok && hybridBind.httpsBind != nil && hybridBind.httpsBind.transport != nil {
		hybridBind.httpsBind.transport.AddPeer(pubKey)
	}
}

// StartTransportListener starts the HTTPS bind's incoming connection listener.
// This must be called after Up() for nodes that need to accept incoming tunnel connections.
func (d *Device) StartTransportListener(addr string, tlsConfig *tls.Config) error {
	if httpsBind, ok := d.wgBind.(*HTTPSBind); ok {
		return httpsBind.StartListener(addr, tlsConfig)
	}
	if hybridBind, ok := d.wgBind.(*HybridBind); ok && hybridBind.httpsBind != nil {
		return hybridBind.httpsBind.StartListener(addr, tlsConfig)
	}
	// Direct bind doesn't need a listener (uses UDP)
	return nil
}

// keyToHex converts a key to hex string for WireGuard IPC
func keyToHex(key []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(key)*2)
	for i, b := range key {
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0x0f]
	}
	return string(result)
}

// derivePublicKey derives the X25519 public key from a private key
func derivePublicKey(privateKey []byte) []byte {
	var private, public [32]byte
	copy(private[:], privateKey)

	// Derive public key using curve25519 scalar base multiplication
	curve25519.ScalarBaseMult(&public, &private)

	return public[:]
}

// configureInterface sets up IP address and routes (implemented per-platform)
func (d *Device) configureInterface() error {
	name, err := d.tunDevice.Name()
	if err != nil {
		return err
	}

	return configureTunnel(name, d.meshIP, d.meshPrefix)
}
