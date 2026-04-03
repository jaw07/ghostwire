// Package https implements the HTTPS-mimic obfuscation transport.
// This transport tunnels WireGuard packets inside genuine TLS 1.3 connections
// that are indistinguishable from normal HTTPS browsing traffic.
package https

import (
	"time"

	"github.com/ghostwire/ghostwire/internal/transport"
)

const (
	// Name is the transport identifier
	Name = "https-mimic"

	// DefaultKnockWindow is the time window for knock validation
	DefaultKnockWindow = 30 * time.Second

	// DefaultTimeout is the connection timeout
	DefaultTimeout = 10 * time.Second
)

// Config holds configuration for the HTTPS-mimic transport
type Config struct {
	// Server name for TLS SNI (the cover domain)
	ServerName string

	// TLS certificate and key paths
	CertFile string
	KeyFile  string

	// Path to cover site static files
	CoverSitePath string

	// Browser fingerprint profile: "chrome", "firefox", "safari", "auto"
	Fingerprint string

	// Listen address for server mode
	ListenAddr string

	// Mesh secret for knock authentication (32 bytes)
	MeshSecret []byte

	// Local node's WireGuard public key
	LocalPublicKey []byte

	// CACertPEM is the mesh CA certificate in PEM format.
	// If set, the transport trusts this CA for peer TLS connections.
	CACertPEM []byte

	// Knock authentication window
	KnockWindow time.Duration

	// Connection timeout
	Timeout time.Duration

	// Enable decoy traffic during idle periods
	DecoyTraffic bool

	// Decoy traffic interval
	DecoyInterval time.Duration
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Fingerprint:   "auto",
		KnockWindow:   DefaultKnockWindow,
		Timeout:       DefaultTimeout,
		DecoyTraffic:  false,
		DecoyInterval: 5 * time.Second,
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.ServerName == "" {
		return ErrMissingServerName
	}
	if len(c.MeshSecret) != 32 {
		return ErrInvalidMeshSecret
	}
	return nil
}

func init() {
	// Register with the default transport registry
	transport.Register(Name, func(cfg interface{}) (transport.Transport, error) {
		httpsCfg, ok := cfg.(*Config)
		if !ok {
			return nil, ErrInvalidConfig
		}
		return New(httpsCfg)
	})
}
