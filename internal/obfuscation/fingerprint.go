package obfuscation

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// BrowserProfile represents a browser to mimic
type BrowserProfile string

const (
	ProfileChrome     BrowserProfile = "chrome"
	ProfileFirefox    BrowserProfile = "firefox"
	ProfileSafari     BrowserProfile = "safari"
	ProfileEdge       BrowserProfile = "edge"
	ProfileIOS        BrowserProfile = "ios"
	ProfileAndroid    BrowserProfile = "android"
	ProfileRandomized BrowserProfile = "randomized"
	ProfileAuto       BrowserProfile = "auto"
)

// FingerprintConfig configures TLS fingerprint mimicry
type FingerprintConfig struct {
	// Profile is the browser profile to mimic
	Profile BrowserProfile

	// ServerName is the SNI value
	ServerName string

	// InsecureSkipVerify skips certificate verification
	InsecureSkipVerify bool

	// NextProtos are the ALPN protocols
	NextProtos []string

	// SessionTicket for TLS resumption
	SessionTicket []byte
}

// DefaultFingerprintConfig returns default configuration
func DefaultFingerprintConfig() *FingerprintConfig {
	return &FingerprintConfig{
		Profile:    ProfileChrome,
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// TLSDialer creates connections with browser-mimicking TLS fingerprints
type TLSDialer struct {
	cfg *FingerprintConfig
	mu  sync.Mutex
}

// NewTLSDialer creates a new fingerprint-mimicking TLS dialer
func NewTLSDialer(cfg *FingerprintConfig) *TLSDialer {
	if cfg == nil {
		cfg = DefaultFingerprintConfig()
	}
	return &TLSDialer{cfg: cfg}
}

// Dial creates a TLS connection with browser fingerprint
func (d *TLSDialer) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	// TCP connect first
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	tcpConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dial: %w", err)
	}

	// Get the appropriate ClientHelloID
	helloID := d.getClientHelloID()

	// Create uTLS config
	tlsConfig := &utls.Config{
		ServerName:         d.cfg.ServerName,
		InsecureSkipVerify: d.cfg.InsecureSkipVerify,
		NextProtos:         d.cfg.NextProtos,
	}

	// Create uTLS connection
	tlsConn := utls.UClient(tcpConn, tlsConfig, helloID)

	// Apply handshake
	if err := tlsConn.Handshake(); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	return tlsConn, nil
}

// DialWithProfile creates a connection using a specific browser profile
func (d *TLSDialer) DialWithProfile(ctx context.Context, network, addr string, profile BrowserProfile) (net.Conn, error) {
	d.mu.Lock()
	originalProfile := d.cfg.Profile
	d.cfg.Profile = profile
	d.mu.Unlock()

	defer func() {
		d.mu.Lock()
		d.cfg.Profile = originalProfile
		d.mu.Unlock()
	}()

	return d.Dial(ctx, network, addr)
}

// getClientHelloID maps profile to uTLS ClientHelloID
func (d *TLSDialer) getClientHelloID() utls.ClientHelloID {
	switch d.cfg.Profile {
	case ProfileChrome:
		return utls.HelloChrome_Auto
	case ProfileFirefox:
		return utls.HelloFirefox_Auto
	case ProfileSafari:
		return utls.HelloSafari_Auto
	case ProfileEdge:
		return utls.HelloEdge_Auto
	case ProfileIOS:
		return utls.HelloIOS_Auto
	case ProfileAndroid:
		return utls.HelloAndroid_11_OkHttp
	case ProfileRandomized:
		return utls.HelloRandomized
	case ProfileAuto:
		// Select based on current environment/time
		return utls.HelloChrome_Auto
	default:
		return utls.HelloChrome_Auto
	}
}

// FingerprintConn wraps a connection with fingerprint-aware functionality
type FingerprintConn struct {
	net.Conn
	profile         BrowserProfile
	serverName      string
	negotiatedProto string
}

// NewFingerprintConn wraps a connection with fingerprint metadata
func NewFingerprintConn(conn net.Conn, profile BrowserProfile, serverName string) *FingerprintConn {
	fc := &FingerprintConn{
		Conn:       conn,
		profile:    profile,
		serverName: serverName,
	}

	// Try to get negotiated protocol
	if tlsConn, ok := conn.(*utls.UConn); ok {
		fc.negotiatedProto = tlsConn.ConnectionState().NegotiatedProtocol
	} else if tlsConn, ok := conn.(*tls.Conn); ok {
		fc.negotiatedProto = tlsConn.ConnectionState().NegotiatedProtocol
	}

	return fc
}

// Profile returns the browser profile used
func (fc *FingerprintConn) Profile() BrowserProfile {
	return fc.profile
}

// ServerName returns the SNI value
func (fc *FingerprintConn) ServerName() string {
	return fc.serverName
}

// NegotiatedProtocol returns the ALPN protocol
func (fc *FingerprintConn) NegotiatedProtocol() string {
	return fc.negotiatedProto
}

// HTTP2Settings returns HTTP/2 settings that match the browser profile
func (d *TLSDialer) HTTP2Settings() map[string]uint32 {
	switch d.cfg.Profile {
	case ProfileChrome:
		return map[string]uint32{
			"HEADER_TABLE_SIZE":      65536,
			"ENABLE_PUSH":            0,
			"MAX_CONCURRENT_STREAMS": 1000,
			"INITIAL_WINDOW_SIZE":    6291456,
			"MAX_HEADER_LIST_SIZE":   262144,
		}
	case ProfileFirefox:
		return map[string]uint32{
			"HEADER_TABLE_SIZE":      65536,
			"ENABLE_PUSH":            1,
			"MAX_CONCURRENT_STREAMS": 100,
			"INITIAL_WINDOW_SIZE":    131072,
			"MAX_HEADER_LIST_SIZE":   65536,
		}
	case ProfileSafari:
		return map[string]uint32{
			"HEADER_TABLE_SIZE":      4096,
			"ENABLE_PUSH":            1,
			"MAX_CONCURRENT_STREAMS": 100,
			"INITIAL_WINDOW_SIZE":    2097152,
			"MAX_HEADER_LIST_SIZE":   16384,
		}
	default:
		return map[string]uint32{
			"HEADER_TABLE_SIZE":   65536,
			"INITIAL_WINDOW_SIZE": 6291456,
		}
	}
}

// WindowUpdate returns the initial window update value for the profile
func (d *TLSDialer) WindowUpdate() uint32 {
	switch d.cfg.Profile {
	case ProfileChrome:
		return 15663105
	case ProfileFirefox:
		return 12517377
	case ProfileSafari:
		return 10485760
	default:
		return 15663105
	}
}

// HeaderOrder returns the HTTP/2 header order for the profile
func (d *TLSDialer) HeaderOrder() []string {
	switch d.cfg.Profile {
	case ProfileChrome:
		return []string{":method", ":authority", ":scheme", ":path"}
	case ProfileFirefox:
		return []string{":method", ":path", ":authority", ":scheme"}
	case ProfileSafari:
		return []string{":method", ":scheme", ":path", ":authority"}
	default:
		return []string{":method", ":authority", ":scheme", ":path"}
	}
}

// JA3Fingerprint returns a string that can be used to verify the fingerprint
func (fc *FingerprintConn) JA3Fingerprint() string {
	// JA3 is computed from the ClientHello
	// This is a simplified representation
	if utlsConn, ok := fc.Conn.(*utls.UConn); ok {
		state := utlsConn.ConnectionState()
		return fmt.Sprintf("%d,%d,%s",
			state.Version,
			state.CipherSuite,
			state.NegotiatedProtocol,
		)
	}
	return ""
}

// RandomProfile returns a random browser profile
func RandomProfile() BrowserProfile {
	profiles := []BrowserProfile{
		ProfileChrome,
		ProfileFirefox,
		ProfileSafari,
		ProfileEdge,
	}

	// Simple random selection
	seed := make([]byte, 1)
	if _, err := rand.Read(seed); err != nil {
		return ProfileChrome
	}

	return profiles[int(seed[0])%len(profiles)]
}

// ProfileForPlatform returns an appropriate profile for the platform
func ProfileForPlatform(platform string) BrowserProfile {
	switch platform {
	case "darwin":
		return ProfileSafari
	case "windows":
		return ProfileChrome
	case "linux":
		return ProfileFirefox
	case "android":
		return ProfileAndroid
	case "ios":
		return ProfileIOS
	default:
		return ProfileChrome
	}
}

// ValidateFingerprint checks if a connection's fingerprint looks legitimate
func ValidateFingerprint(conn net.Conn) error {
	utlsConn, ok := conn.(*utls.UConn)
	if !ok {
		return nil // Not a uTLS connection, skip validation
	}

	state := utlsConn.ConnectionState()

	// Check TLS version
	if state.Version < tls.VersionTLS12 {
		return fmt.Errorf("TLS version too old: %d", state.Version)
	}

	// Check for modern cipher suites
	modernCiphers := map[uint16]bool{
		tls.TLS_AES_128_GCM_SHA256:       true,
		tls.TLS_AES_256_GCM_SHA384:       true,
		tls.TLS_CHACHA20_POLY1305_SHA256: true,
	}

	if state.Version == tls.VersionTLS13 && !modernCiphers[state.CipherSuite] {
		return fmt.Errorf("unexpected cipher suite for TLS 1.3: %d", state.CipherSuite)
	}

	return nil
}
