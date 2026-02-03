package pki

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/ghostwire/ghostwire/internal/keys"
)

var (
	// ErrCertExpired indicates the certificate has expired
	ErrCertExpired = errors.New("certificate has expired")
	// ErrCertNotYetValid indicates the certificate is not yet valid
	ErrCertNotYetValid = errors.New("certificate is not yet valid")
	// ErrInvalidChain indicates certificate chain verification failed
	ErrInvalidChain = errors.New("certificate chain verification failed")
	// ErrMeshIDMismatch indicates the certificate is for a different mesh
	ErrMeshIDMismatch = errors.New("certificate mesh ID does not match")
	// ErrWireGuardKeyMismatch indicates the WireGuard key doesn't match the certificate
	ErrWireGuardKeyMismatch = errors.New("WireGuard public key does not match certificate")
	// ErrMissingExtensions indicates required GHOSTWIRE extensions are missing
	ErrMissingExtensions = errors.New("missing required GHOSTWIRE extensions")
)

// Verifier validates peer certificates
type Verifier struct {
	rootPool *x509.CertPool
	meshID   [32]byte
}

// NewVerifier creates a certificate verifier for the given mesh
func NewVerifier(rootCert *x509.Certificate, meshID [32]byte) *Verifier {
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	return &Verifier{
		rootPool: pool,
		meshID:   meshID,
	}
}

// VerifiedPeer contains information about a verified peer
type VerifiedPeer struct {
	NodeID          string
	Roles           []string
	AllowedNetworks []AllowedNetwork
	Compartment     string
	Certificate     *x509.Certificate
	WireGuardPubKey [32]byte
}

// VerifyCertificate validates a peer certificate and extracts its information
func (v *Verifier) VerifyCertificate(cert *x509.Certificate) (*VerifiedPeer, error) {
	// Check time validity
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return nil, ErrCertNotYetValid
	}
	if now.After(cert.NotAfter) {
		return nil, ErrCertExpired
	}

	// Parse GHOSTWIRE extensions first to handle critical extensions
	gwExt, err := ParseExtensions(cert.Extensions)
	if err != nil {
		return nil, fmt.Errorf("parse extensions: %w", err)
	}

	// Filter out GHOSTWIRE critical extensions from UnhandledCriticalExtensions
	// Go's x509 library rejects unknown critical extensions, but we handle ours
	filteredCritical := filterGhostwireCriticalExtensions(cert.UnhandledCriticalExtensions)

	// Temporarily clear unhandled critical extensions for verification
	origCritical := cert.UnhandledCriticalExtensions
	cert.UnhandledCriticalExtensions = filteredCritical

	// Verify certificate chain
	opts := x509.VerifyOptions{
		Roots:       v.rootPool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	_, err = cert.Verify(opts)
	cert.UnhandledCriticalExtensions = origCritical // Restore original

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidChain, err)
	}

	// Verify required fields
	if gwExt.NodeID == "" {
		return nil, fmt.Errorf("%w: node ID", ErrMissingExtensions)
	}
	if len(gwExt.Roles) == 0 {
		return nil, fmt.Errorf("%w: roles", ErrMissingExtensions)
	}

	// Verify mesh ID
	if gwExt.MeshID != v.meshID {
		return nil, ErrMeshIDMismatch
	}

	return &VerifiedPeer{
		NodeID:          gwExt.NodeID,
		Roles:           gwExt.Roles,
		AllowedNetworks: gwExt.AllowedNetworks,
		Compartment:     gwExt.Compartment,
		Certificate:     cert,
		WireGuardPubKey: gwExt.WireGuardPubKey,
	}, nil
}

// filterGhostwireCriticalExtensions removes GHOSTWIRE OIDs from the list
// of unhandled critical extensions, since we handle them ourselves
func filterGhostwireCriticalExtensions(oids []asn1.ObjectIdentifier) []asn1.ObjectIdentifier {
	var filtered []asn1.ObjectIdentifier
	for _, oid := range oids {
		if !isGhostwireOID(oid) {
			filtered = append(filtered, oid)
		}
	}
	return filtered
}

// isGhostwireOID checks if an OID is in the GHOSTWIRE namespace
func isGhostwireOID(oid asn1.ObjectIdentifier) bool {
	// Check if OID starts with GHOSTWIRE root: 1.3.6.1.4.1.99999.1
	if len(oid) < len(OIDGhostwireRoot) {
		return false
	}
	for i, v := range OIDGhostwireRoot {
		if oid[i] != v {
			return false
		}
	}
	return true
}

// VerifyCertificateWithWireGuard validates a certificate and verifies the WireGuard key matches
func (v *Verifier) VerifyCertificateWithWireGuard(cert *x509.Certificate, wgPubKey [32]byte) (*VerifiedPeer, error) {
	peer, err := v.VerifyCertificate(cert)
	if err != nil {
		return nil, err
	}

	// Derive X25519 key from certificate's Ed25519 public key
	edPub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("certificate must use Ed25519 key")
	}

	derivedWG, err := keys.Ed25519PublicKeyToX25519(edPub)
	if err != nil {
		return nil, fmt.Errorf("derive WireGuard key: %w", err)
	}

	// Verify the presented WireGuard key matches
	if derivedWG != wgPubKey {
		return nil, ErrWireGuardKeyMismatch
	}

	// Also verify against embedded key if present
	var zeroKey [32]byte
	if peer.WireGuardPubKey != zeroKey && peer.WireGuardPubKey != wgPubKey {
		return nil, ErrWireGuardKeyMismatch
	}

	peer.WireGuardPubKey = wgPubKey
	return peer, nil
}

// HasRole checks if a verified peer has a specific role
func (vp *VerifiedPeer) HasRole(role string) bool {
	for _, r := range vp.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// IsAdmin checks if the peer has admin role
func (vp *VerifiedPeer) IsAdmin() bool {
	return vp.HasRole(RoleAdmin)
}

// IsRelay checks if the peer can act as a relay
func (vp *VerifiedPeer) IsRelay() bool {
	return vp.HasRole(RoleRelay) || vp.HasRole(RoleAdmin)
}

// TimeUntilExpiry returns the duration until the certificate expires
func (vp *VerifiedPeer) TimeUntilExpiry() time.Duration {
	return time.Until(vp.Certificate.NotAfter)
}

// NeedsRenewal returns true if the certificate should be renewed
// (within the given threshold of expiry)
func (vp *VerifiedPeer) NeedsRenewal(threshold time.Duration) bool {
	return vp.TimeUntilExpiry() < threshold
}

// ParseCertificatePEM parses a PEM-encoded certificate
func ParseCertificatePEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
