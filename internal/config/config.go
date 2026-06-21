// Package config manages GHOSTWIRE configuration including encrypted storage.
package config

import (
	"time"
)

// MeshConfig is the main configuration structure for a GHOSTWIRE node
type MeshConfig struct {
	// Version of the config format
	Version int `yaml:"version"`

	// Mesh identification
	MeshName string `yaml:"mesh_name"`
	MeshID   string `yaml:"mesh_id"` // Hex-encoded SHA-256 of root CA public key

	// Node identity
	NodeID      string   `yaml:"node_id"`
	Roles       []string `yaml:"roles"`
	Compartment string   `yaml:"compartment,omitempty"`

	// PKI material (PEM-encoded)
	NodePrivateKey  string `yaml:"node_private_key"` // Ed25519 seed in PEM
	NodeCertificate string `yaml:"node_certificate"` // X.509 certificate
	CACertChain     string `yaml:"ca_cert_chain"`    // CA certificate chain

	// Network configuration
	MeshSubnet string `yaml:"mesh_subnet"` // e.g., "10.gw.0.0/16"
	AssignedIP string `yaml:"assigned_ip"` // e.g., "10.gw.0.5"

	// Bootstrap peers
	Peers []PeerConfig `yaml:"peers"`

	// Obfuscation settings
	Transport TransportConfig `yaml:"transport"`

	// Certificate renewal settings
	CertRenewalThreshold time.Duration `yaml:"cert_renewal_threshold"`

	// Operational security
	Canary CanaryConfig `yaml:"canary,omitempty"`

	// Mesh secret for knock authentication (base64-encoded)
	MeshSecret string `yaml:"mesh_secret"`
}

// PeerConfig describes a known peer in the mesh
type PeerConfig struct {
	NodeID    string   `yaml:"node_id"`
	PublicKey string   `yaml:"public_key"` // Base64 X25519 WireGuard key
	MeshIP    string   `yaml:"mesh_ip"`    // Peer's mesh IP address
	Endpoints []string `yaml:"endpoints"`  // host:port addresses
	Roles     []string `yaml:"roles"`
}

// TransportConfig configures the obfuscation transport
type TransportConfig struct {
	// Active transport type: "https-mimic", "quic", "direct"
	Active string `yaml:"active"`

	// HTTPS mimic transport settings
	HTTPS HTTPSTransportConfig `yaml:"https,omitempty"`

	// QUIC transport settings
	QUIC QUICTransportConfig `yaml:"quic,omitempty"`

	// Direct (no obfuscation) settings
	Direct DirectTransportConfig `yaml:"direct,omitempty"`
}

// HTTPSTransportConfig configures the HTTPS mimic transport
type HTTPSTransportConfig struct {
	// Domain to use for TLS SNI
	ServerName string `yaml:"server_name"`

	// Path to cover site files (for serving to probes)
	CoverSitePath string `yaml:"cover_site_path,omitempty"`

	// TLS certificate and key paths (optional, uses embedded if not set)
	CertFile string `yaml:"cert_file,omitempty"`
	KeyFile  string `yaml:"key_file,omitempty"`

	// Browser fingerprint profile: "chrome", "firefox", "safari", "auto"
	Fingerprint string `yaml:"fingerprint"`

	// Listen address for enrollment/API server mode
	ListenAddr string `yaml:"listen_addr,omitempty"`

	// Listen address for WireGuard transport connections (separate from enrollment)
	TransportListenAddr string `yaml:"transport_listen_addr,omitempty"`

	// AdvertiseEndpoint is the host:port that enrolling nodes should dial to
	// reach this node's WireGuard transport. Set this when the transport is
	// reached via a different address than the local listen address — e.g.
	// behind a Cloudflare tunnel ("gwt.example.com:443") or a NAT. When empty,
	// peers fall back to the admin host + transport port.
	AdvertiseEndpoint string `yaml:"advertise_endpoint,omitempty"`

	// Obfuscate enables an additional padding-mimicry layer on the transport
	// (frames are padded to common HTTPS sizes). It is OFF by default and must
	// be set identically on ALL nodes in the mesh — a mismatch breaks the
	// tunnel framing between peers. Only size-mimicry is applied; timing jitter
	// and decoy traffic are intentionally not used here, as they add latency
	// and waste bandwidth on a live tunnel.
	Obfuscate bool `yaml:"obfuscate,omitempty"`
}

// QUICTransportConfig configures the QUIC transport
type QUICTransportConfig struct {
	Enabled bool `yaml:"enabled"`
}

// DirectTransportConfig configures direct UDP transport (no obfuscation)
type DirectTransportConfig struct {
	Enabled    bool   `yaml:"enabled"`
	ListenPort int    `yaml:"listen_port,omitempty"`
	ListenAddr string `yaml:"listen_addr,omitempty"`
}

// CanaryConfig configures the dead man's switch feature
type CanaryConfig struct {
	Enabled         bool          `yaml:"enabled"`
	CheckInInterval time.Duration `yaml:"check_in_interval"`
	MissedThreshold int           `yaml:"missed_threshold"`
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *MeshConfig {
	return &MeshConfig{
		Version:              1,
		CertRenewalThreshold: 6 * time.Hour,
		Transport: TransportConfig{
			Active: "https-mimic",
			HTTPS: HTTPSTransportConfig{
				Fingerprint: "auto",
			},
			Direct: DirectTransportConfig{
				Enabled: true,
			},
		},
		Canary: CanaryConfig{
			Enabled:         false,
			CheckInInterval: 6 * time.Hour,
			MissedThreshold: 3,
		},
	}
}

// AdminConfig holds configuration specific to admin nodes (for mesh initialization)
type AdminConfig struct {
	MeshConfig `yaml:",inline"`

	// CA private key (only on admin nodes)
	CAPrivateKey string `yaml:"ca_private_key,omitempty"`

	// IP allocation state
	IPAllocator IPAllocatorState `yaml:"ip_allocator"`

	// Active enrollment tokens
	EnrollmentTokens []StoredToken `yaml:"enrollment_tokens,omitempty"`
}

// IPAllocatorState tracks IP address allocation within the mesh
type IPAllocatorState struct {
	Subnet    string            `yaml:"subnet"`    // e.g., "10.100.0.0/16"
	Allocated map[string]string `yaml:"allocated"` // node_id -> IP
	NextIP    string            `yaml:"next_ip"`   // Next IP to allocate
}

// StoredToken represents an enrollment token stored in admin config
type StoredToken struct {
	TokenID   string    `yaml:"token_id"`
	CreatedAt time.Time `yaml:"created_at"`
	ExpiresAt time.Time `yaml:"expires_at"`
	Roles     []string  `yaml:"roles"`
	MaxUses   int       `yaml:"max_uses"`
	UsedCount int       `yaml:"used_count"`
}
